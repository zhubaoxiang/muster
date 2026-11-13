package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"dianbing/internal/ai"
	"dianbing/internal/guard"
	"dianbing/internal/model"
)

// WebProber 并发 HTTP 探测器（首期阶段）。
// 二期接入 naabu 后，这里只消费「开放端口」结果；当前用常见 Web 端口直探。
type WebProber struct {
	guard    *guard.Guard
	sem      chan struct{}
	client   *http.Client
	analyzer ai.Analyzer
}

func NewWebProber(g *guard.Guard, concurrency int) *WebProber {
	return &WebProber{
		guard:    g,
		sem:      make(chan struct{}, concurrency),
		analyzer: ai.NewTieredAnalyzer(false),
		client: &http.Client{
			Timeout: 6 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
				MaxIdleConnsPerHost:   4,
				DisableKeepAlives:     true,
				DialContext:           (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
				TLSHandshakeTimeout:   4 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				// 重定向跨主机也要过护栏
				if !g.CheckHost(req.URL.Hostname()) {
					return fmt.Errorf("重定向目标 %s 不在白名单内", req.URL.Hostname())
				}
				return nil
			},
		},
	}
}

func (w *WebProber) Name() string { return "web-probe" }

// RunOpen 对端口扫描产出的开放端口做 Web 探测。
// 返回产生了 HTTP 资产 (host:port) 的集合，供引擎对剩余开放端口记 tcp 资产。
func (w *WebProber) RunOpen(ctx context.Context, open []OpenPort,
	out chan<- model.Asset, progress func(done, total int, current string)) map[string]bool {

	var urls []string
	for _, op := range open {
		if !w.guard.CheckHost(op.Host) {
			continue
		}
		scheme := "http"
		if op.Port == 443 || op.Port == 8443 {
			scheme = "https"
		}
		urls = append(urls, fmt.Sprintf("%s://%s:%d", scheme, op.Host, op.Port))
	}
	total := len(urls)
	httpPorts := map[string]bool{}
	if total == 0 {
		return httpPorts
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0

	for _, u := range urls {
		select {
		case <-ctx.Done():
			wg.Wait()
			return httpPorts
		default:
		}
		w.sem <- struct{}{}
		wg.Add(1)
		go func(url string) {
			defer func() {
				<-w.sem
				wg.Done()
				mu.Lock()
				done++
				d, t := done, total
				mu.Unlock()
				if d%20 == 0 || d == t {
					progress(d, t, url)
				}
			}()
			if a, ok := w.probeOne(ctx, url); ok {
				mu.Lock()
				httpPorts[a.Host+":"+fmt.Sprint(a.Port)] = true
				mu.Unlock()
				out <- a
			}
		}(u)
	}
	wg.Wait()
	return httpPorts
}

func (w *WebProber) Run(ctx context.Context, hosts []string, ports []int,
	out chan<- model.Asset, progress func(done, total int, current string)) error {

	var urls []string
	for _, h := range hosts {
		if !w.guard.CheckHost(h) {
			continue
		}
		for _, p := range ports {
			scheme := "http"
			if p == 443 || p == 8443 {
				scheme = "https"
			}
			urls = append(urls, fmt.Sprintf("%s://%s:%d", scheme, h, p))
		}
	}
	total := len(urls)
	if total == 0 {
		return nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0

	for _, u := range urls {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		default:
		}
		w.sem <- struct{}{}
		wg.Add(1)
		go func(url string) {
			defer func() {
				<-w.sem
				wg.Done()
				mu.Lock()
				done++
				d, t := done, total
				mu.Unlock()
				if d%20 == 0 || d == t {
					progress(d, t, url)
				}
			}()
			if a, ok := w.probeOne(ctx, url); ok {
				out <- a
			}
		}(u)
	}
	wg.Wait()
	return nil
}

func (w *WebProber) probeOne(ctx context.Context, url string) (model.Asset, bool) {
	a := model.Asset{Scheme: schemeOf(url)}
	u, _ := splitURL(url)
	a.Host, a.Port = u.host, u.port

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return a, false
	}
	req.Header.Set("User-Agent", "dianbing-scanner/0.1")

	resp, err := w.client.Do(req)
	if err != nil {
		// https 失败时对非常见 TLS 端口回退试一次 http
		if a.Scheme == "https" && a.Port != 443 && a.Port != 8443 {
			return w.retryHTTP(ctx, url)
		}
		return a, false
	}
	defer resp.Body.Close()

	in := ai.ProbeInput{
		URL:     url,
		Status:  resp.StatusCode,
		Headers: map[string]string{},
	}
	for k, v := range resp.Header {
		key := strings.ToLower(k)
		switch key {
		case "server":
			in.Server = v[0]
			a.Server = v[0]
		case "x-powered-by", "x-application-context", "x-jenkins":
			in.Headers[key] = strings.Join(v, ",")
		default:
			in.Headers[key] = strings.Join(v, ",")
		}
	}
	if body, err := io.ReadAll(io.LimitReader(resp.Body, 8192)); err == nil {
		in.BodySniff = string(body)
		a.Title = ai.ExtractTitle(in.BodySniff)
	}
	a.Status = resp.StatusCode
	a.Fingerprint = w.analyzer.Analyze(in)
	return a, true
}

// retryHTTP 对 https 失败的端口尝试 http
func (w *WebProber) retryHTTP(ctx context.Context, httpsURL string) (model.Asset, bool) {
	httpURL := strings.Replace(httpsURL, "https://", "http://", 1)
	a := model.Asset{Scheme: "http"}
	u, _ := splitURL(httpURL)
	a.Host, a.Port = u.host, u.port
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if err != nil {
		return a, false
	}
	req.Header.Set("User-Agent", "dianbing-scanner/0.1")
	resp, err := w.client.Do(req)
	if err != nil {
		return a, false
	}
	defer resp.Body.Close()
	in := ai.ProbeInput{URL: httpURL, Status: resp.StatusCode, Headers: map[string]string{}}
	if v, ok := resp.Header["Server"]; ok {
		in.Server, a.Server = v[0], v[0]
	}
	for k, v := range resp.Header {
		in.Headers[strings.ToLower(k)] = strings.Join(v, ",")
	}
	if body, err := io.ReadAll(io.LimitReader(resp.Body, 8192)); err == nil {
		in.BodySniff = string(body)
		a.Title = ai.ExtractTitle(in.BodySniff)
	}
	a.Status = resp.StatusCode
	a.Fingerprint = w.analyzer.Analyze(in)
	return a, true
}

type urlParts struct {
	host string
	port int
}

func splitURL(raw string) (urlParts, bool) {
	s := strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return urlParts{host: s, port: 80}, true
	}
	p := 0
	for _, c := range s[idx+1:] {
		if c < '0' || c > '9' {
			return urlParts{host: strings.TrimSuffix(s, "/"), port: 80}, true
		}
		p = p*10 + int(c-'0')
	}
	return urlParts{host: s[:idx], port: p}, true
}

func schemeOf(url string) string {
	if strings.HasPrefix(url, "https://") {
		return "https"
	}
	return "http"
}
