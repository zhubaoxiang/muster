// Package ai 三档分析器：规则指纹（档1）→ 本地 Ollama（档2）→ 云 API（档3）。
// 档 1 是内置兜底，毫秒级、零成本；档 2/3 首期留接口。
package ai

import (
	"regexp"
	"strings"
)

// ProbeInput 交给分析器的一次探测结果（归一化后的最小集合）
type ProbeInput struct {
	URL       string            `json:"url"`
	Status    int               `json:"status"`
	Title     string            `json:"title"`
	Server    string            `json:"server"`
	Headers   map[string]string `json:"headers"`
	BodySniff string            `json:"bodySniff"` // body 前 8KB
}

// Analyzer 归一化打标接口。返回技术栈/组件标签列表。
type Analyzer interface {
	Analyze(in ProbeInput) []string
}

// ---------- 档 1：规则指纹 ----------

type rule struct {
	name    string
	check   func(in ProbeInput) bool
}

// RuleAnalyzer 规则指纹库。目标覆盖常见 Web 服务器/中间件/框架/组件。
type RuleAnalyzer struct {
	rules []rule
}

func NewRuleAnalyzer() *RuleAnalyzer {
	r := &RuleAnalyzer{}
	// header 键一律用小写——探测层（webprobe）存表时已把键统一 ToLower
	header := func(k, v string) func(ProbeInput) bool {
		return func(in ProbeInput) bool {
			return strings.Contains(strings.ToLower(in.Headers[k]), v)
		}
	}
	// hasHeader 只判断头存在且非空（不要传 v="" 给 header，Contains 对空串恒真）
	hasHeader := func(k string) func(ProbeInput) bool {
		return func(in ProbeInput) bool { return in.Headers[k] != "" }
	}
	body := func(kw string) func(ProbeInput) bool {
		kwLower := strings.ToLower(kw)
		return func(in ProbeInput) bool { return strings.Contains(strings.ToLower(in.BodySniff), kwLower) }
	}

	r.rules = []rule{
		{"Nginx", header("server", "nginx")},
		{"Apache", header("server", "apache")},
		{"IIS", header("server", "iis")},
		{"Tomcat", func(in ProbeInput) bool {
			return strings.Contains(strings.ToLower(in.Server), "tomcat") ||
				strings.Contains(strings.ToLower(in.Server), "coyote")
		}},
		{"Jetty", header("server", "jetty")},
		{"WebLogic", body("weblogic")},
		{"PHP", header("x-powered-by", "php")},
		{"ASP.NET", header("x-powered-by", "asp.net")},
		{"Jenkins", hasHeader("x-jenkins")},
		{"GitLab", func(in ProbeInput) bool {
			return strings.Contains(strings.ToLower(in.Title), "gitlab")
		}},
		{"Swagger", body("swagger-ui")},
		{"Spring Boot", func(in ProbeInput) bool {
			// 新版 Spring Boot 已移除 X-Application-Context，whitelabel 错误页是更稳的特征
			return hasHeader("x-application-context")(in) || body("whitelabel error page")(in)
		}},
		{"ThinkPHP", body("thinkphp")},
		{"WordPress", body("wp-content")},
		{"Vue", func(in ProbeInput) bool {
			return strings.Contains(in.BodySniff, `id="app"`) && strings.Contains(in.BodySniff, "/assets/")
		}},
		{"React", func(in ProbeInput) bool {
			return body("__next")(in) || body("reactroot")(in)
		}},
		{"Kibana", body("kibana")},
		{"Grafana", body("grafana")},
		{"MinIO", func(in ProbeInput) bool { return in.Headers["x-minio-deploy"] != "" || body("minio")(in) }},
		{"Harbor", body("harbor")},
		{"Druid", body("druid")},
		{"Nacos", body("nacos")},
		{"phpMyAdmin", body("phpmyadmin")},
		{"Login-Form", body("type=\"password\"")},
	}
	return r
}

func (r *RuleAnalyzer) Analyze(in ProbeInput) []string {
	var out []string
	for _, rl := range r.rules {
		if rl.check(in) {
			out = append(out, rl.name)
		}
	}
	return out
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// ExtractTitle 从 HTML body 提取标题
func ExtractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// ---------- 档 2/3：LLM 兜底（首期留接口） ----------

// TieredAnalyzer 组合分析器：规则先跑，规则无命中且开启了 LLM 档，
// 把灰色 banner 批量丢给 LLM 打标（二期实现 Ollama/云 API 客户端）。
type TieredAnalyzer struct {
	Rules     *RuleAnalyzer
	EnableLLM bool
}

func NewTieredAnalyzer(enableLLM bool) *TieredAnalyzer {
	return &TieredAnalyzer{Rules: NewRuleAnalyzer(), EnableLLM: enableLLM}
}

func (t *TieredAnalyzer) Analyze(in ProbeInput) []string {
	tags := t.Rules.Analyze(in)
	// TODO 二期：规则零命中时入 LLM 批量队列（batch=32），
	// 本地 Ollama 优先，未配置则走云 API，结果回写规则库做沉淀。
	return tags
}
