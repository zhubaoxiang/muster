// Package engine 探测流水线：解析目标 → Web 探测 → 归一化打标 → 批量入库。
// 首期只挂 webprobe 一个阶段；端口扫描(naabu)与深度探测(nuclei)按同一
// Stage 接口在二期接入，流水线结构不变。
package engine

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"muster/internal/ai"
	"muster/internal/guard"
	"muster/internal/model"
	"muster/internal/store"
)

// Stage 流水线阶段接口，二期 naabu/nuclei 按此接入
type Stage interface {
	Name() string
	Run(ctx context.Context, hosts []string, ports []int, out chan<- model.Asset, progress func(done, total int, current string)) error
}

type Engine struct {
	guard    *guard.Guard
	store    *store.Store
	maxRate  int
	analyzer ai.Analyzer
	probe    *WebProber
}

func New(g *guard.Guard, st *store.Store, maxRate int) *Engine {
	if maxRate <= 0 {
		maxRate = 200
	}
	if maxRate > 200 {
		maxRate = 200 // 硬顶，UI 调不过这里
	}
	return &Engine{
		guard:    g,
		store:    st,
		maxRate:  maxRate,
		analyzer: ai.NewTieredAnalyzer(false), // 二期开 LLM 档
		probe:    NewWebProber(g, maxRate),
	}
}

// scanConcurrency 端口扫描并发数：纯 TCP connect 比 HTTP 请求轻得多，可用更高并发
func scanConcurrency(maxRate int) int {
	c := maxRate * 2
	if c < 100 {
		c = 100
	}
	if c > 500 {
		c = 500
	}
	return c
}

// Run 执行完整任务。emit 回调推进度，内部 panic 由调用方 recover。
func (e *Engine) Run(ctx context.Context, taskID string, req model.ScanRequest, emit func(model.Progress)) {
	defer func() {
		emit(model.Progress{TaskID: taskID, Stage: "finished"})
	}()

	hosts, err := e.guard.TargetIPs()
	if err != nil || len(hosts) == 0 {
		emit(model.Progress{TaskID: taskID, Stage: "failed", Error: "无可探测目标"})
		return
	}

	// 域名收敛为 IP，保证逐 IP 过护栏；解析失败的域名跳过并上报
	var resolved []string
	skipped := 0
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			if e.guard.CheckIP(ip) {
				resolved = append(resolved, h)
			}
			continue
		}
		ips, err := net.LookupIP(h)
		if err != nil {
			skipped++
			continue
		}
		for _, ip := range ips {
			if e.guard.CheckIP(ip) {
				resolved = append(resolved, ip.String())
			}
		}
	}
	if skipped > 0 {
		emit(model.Progress{TaskID: taskID, Stage: "resolve", Current: fmt.Sprintf("%d 个域名解析失败已跳过", skipped)})
	}
	if len(resolved) == 0 {
		emit(model.Progress{TaskID: taskID, Stage: "failed", Error: "目标解析后无可用 IP"})
		return
	}

	ports := req.Ports
	if req.Mode == "deep" && req.FullRange {
		// 全端口 1-65535：TCP Connect 方式可行，量级 = 主机数 × 65535，
		// 局域网内 RST 响应快（毫秒级），主要耗时在防火墙 DROP 的 1s 超时
		ports = make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
	} else if len(ports) == 0 {
		if req.Mode == "deep" {
			ports = TopPorts
		} else {
			ports = model.DefaultPorts
		}
	}
	sort.Ints(ports)

	// 任务审计：记录实际扫描范围与结果统计，事后可查库核查
	meta := model.TaskMeta{
		TaskID: taskID, Mode: req.Mode, FullRange: req.FullRange,
		PortCount: len(ports), PortsOpen: -1, StartedAt: time.Now(),
	}
	var aliveCount, openCount, found int
	defer func() {
		meta.HostsAlive = aliveCount
		meta.PortsOpen = openCount
		meta.AssetsFound = found
		meta.FinishedAt = time.Now()
		_ = e.store.SaveTask(meta)
	}()

	// produce 按模式选择流水线：fast = Web 端口直探；deep = 主机发现 → 端口扫描 → Web 探测 → tcp 资产
	produce := func(out chan<- model.Asset) error {
		if req.Mode != "deep" {
			aliveCount = len(resolved)
			return e.probe.Run(ctx, resolved, ports, out, func(done, total int, current string) {
				emit(model.Progress{TaskID: taskID, Stage: "web-probe", Done: done, Total: total, Current: current})
			})
		}
		// 阶段 1：主机发现（TCP 探活）
		alive := HostDiscover(ctx, resolved, e.maxRate, func(done, total int, current string) {
			emit(model.Progress{TaskID: taskID, Stage: "host-discovery", Done: done, Total: total, Current: current})
		})
		aliveCount = len(alive)
		emit(model.Progress{TaskID: taskID, Stage: "host-discovery", Current: fmt.Sprintf("存活主机 %d/%d", len(alive), len(resolved))})
		if len(alive) == 0 {
			return nil
		}
		// 阶段 2：TCP Connect 端口扫描
		open := ScanPorts(ctx, alive, ports, scanConcurrency(e.maxRate), func(done, total int, current string) {
			emit(model.Progress{TaskID: taskID, Stage: "port-scan", Done: done, Total: total, Current: current})
		})
		openCount = len(open)
		emit(model.Progress{TaskID: taskID, Stage: "port-scan", Current: fmt.Sprintf("开放端口 %d 个", len(open))})
		if len(open) == 0 {
			return nil
		}
		// 阶段 3：Web 探测（只探开放端口）
		httpPorts := e.probe.RunOpen(ctx, open, out, func(done, total int, current string) {
			emit(model.Progress{TaskID: taskID, Stage: "web-probe", Done: done, Total: total, Current: current})
		})
		// 阶段 4：未响应 HTTP 的开放端口记为 tcp 资产（SSH/SMB/RDP 等）
		for _, op := range open {
			if httpPorts[op.Host+":"+fmt.Sprint(op.Port)] {
				continue
			}
			name := serviceTitle(op.Port)
			out <- model.Asset{
				Host:        op.Host,
				Port:        op.Port,
				Scheme:      "tcp",
				Title:       name,
				Fingerprint: []string{"tcp-open", name},
			}
		}
		return nil
	}

	results := make(chan model.Asset, 512)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer close(results) // 探测结束（含被取消）关闭通道，消费端自然退出
		defer wg.Done()
		if err := produce(results); err != nil && ctx.Err() == nil {
			emit(model.Progress{TaskID: taskID, Stage: "failed", Error: err.Error()})
		}
	}()

	// 消费端：AI 打标 + 批量入库（每 50 条一批）
	batch := make([]model.Asset, 0, 50)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := e.store.UpsertAssets(batch); err != nil {
			emit(model.Progress{TaskID: taskID, Stage: "store-error", Error: err.Error()})
		}
		batch = batch[:0]
	}
	for a := range results {
		found++
		a.TaskID = taskID
		a.FirstSeen = time.Now()
		a.LastSeen = a.FirstSeen
		batch = append(batch, a)
		if len(batch) >= 50 {
			flush()
		}
	}
	wg.Wait()
	flush()
	emit(model.Progress{TaskID: taskID, Stage: "summary", Found: found})
}
