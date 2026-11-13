package model

import "time"

// ScanRequest 前端下发的扫描任务
type ScanRequest struct {
	Targets     []string `json:"targets"`     // IP / CIDR / 域名
	Ports       []int    `json:"ports"`       // 端口列表，空则按模式用默认集
	Concurrency int      `json:"concurrency"` // 并发数，上限 200
	AllowPublic bool     `json:"allowPublic"` // 是否允许公网目标（默认 false，仅私网）
	Mode        string   `json:"mode"`        // "fast"=Web 端口直探（默认）；"deep"=主机发现+端口扫描+Web 探测
	FullRange   bool     `json:"fullRange"`   // deep 模式下扫描全部 1-65535 端口
}

// Asset 单条资产记录
type Asset struct {
	ID          int64     `json:"id"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Scheme      string    `json:"scheme"`
	Status      int       `json:"status"`
	Title       string    `json:"title"`
	Server      string    `json:"server"`
	Fingerprint []string  `json:"fingerprint"`
	TaskID      string    `json:"taskId"`
	FirstSeen   time.Time `json:"firstSeen"`
	LastSeen    time.Time `json:"lastSeen"`
}

// Progress 实时进度事件
type Progress struct {
	TaskID  string `json:"taskId"`
	Stage   string `json:"stage"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	Found   int    `json:"found"`
	Current string `json:"current"`
	Error   string `json:"error,omitempty"`
}

// TaskMeta 任务审计记录：每次任务的实际扫描范围与结果统计，用于事后核查
type TaskMeta struct {
	TaskID      string    `json:"taskId"`
	Mode        string    `json:"mode"`        // fast / deep
	FullRange   bool      `json:"fullRange"`   // 是否全端口
	PortCount   int       `json:"portCount"`   // 实际扫描的端口数
	HostsAlive  int       `json:"hostsAlive"`  // 存活主机数（fast 模式 = 解析后目标数）
	PortsOpen   int       `json:"portsOpen"`   // 发现的开放端口数（fast 模式 = -1 不适用）
	AssetsFound int       `json:"assetsFound"` // 入库资产数
	StartedAt   time.Time `json:"startedAt"`
	FinishedAt  time.Time `json:"finishedAt"`
}

// Settings 持久化配置（白名单等）
type Settings struct {
	Whitelist   string `json:"whitelist"`   // 换行分隔的目标列表
	AllowPublic bool   `json:"allowPublic"` // 公网解锁开关
	MaxRate     int    `json:"maxRate"`     // 全局并发硬顶
}

// DefaultPorts 首期 Web 探测默认端口集
var DefaultPorts = []int{80, 443, 8080, 8443, 8000, 8888, 9090, 7001, 9080}
