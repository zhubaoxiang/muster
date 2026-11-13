# 点兵 · AI 资产测绘（桌面版）

> 点兵——沙场点兵，盘点自己有多少兵、多少门。仓库目录 `muster/`，英文标识 **Muster**；
> 二进制、Go module 与运行时数据目录仍沿用 `dianbing`（见下方「命名约定」）。

Wails v2 + Vue 3 + Go 单机桌面应用。探测引擎内嵌同进程，SQLite 单文件存储，
内置目标护栏（白名单 + 私网锁定 + 并发硬顶），AI 三档分析（规则指纹 → Ollama → 云 API）。

> ⚠️ 仅用于自有资产或已获书面授权的目标探测。

## 目录结构

```
muster/
├── main.go                  # Wails 入口（嵌入 frontend/dist）
├── app.go                   # 绑定层：StartScan/StopScan/GetAssets/设置读写（含旧库自动迁移）
├── wails.json
├── internal/
│   ├── guard/               # 目标护栏：白名单 + 私网锁定 + 逐 IP 校验（含单测）
│   ├── engine/              # 流水线：主机发现 → 端口扫描 → Web 探测 → AI 打标 → 批量入库
│   │   ├── engine.go        #   编排 + channel 消费端（50 条/批落库）+ 任务审计
│   │   ├── portscan.go      #   TCP 探活 + Connect 端口扫描（全端口 1-65535，超时重试）
│   │   └── webprobe.go      #   Web 探测器（并发池 + 重定向护栏 + 开放端口直探）
│   ├── ai/                  # 规则指纹库 + LLM 档接口（二期）（含回归单测）
│   ├── store/               # SQLite（modernc 纯 Go 驱动，WAL，批量 upsert，任务审计表）
│   └── model/               # 共享类型
├── tools/dbdump/            # 诊断工具：任务审计 + 资产分布 + 设置
└── frontend/                # Vue 3 + Vite + TS
    └── src/
        ├── App.vue          # 模式选择 / 扫描范围预览 / 实时进度 / 资产表
        └── services/api.ts  # Wails 绑定检测 + 浏览器 mock（可独立开发 UI）
```

## 命名约定

项目有两个标识并存，改动时注意区分：

| 标识 | 值 | 出现位置 | 说明 |
|------|-----|----------|------|
| 仓库目录 | `muster` | 文件夹名、git 仓库 | 对外英文名 |
| 二进制产物 | `dianbing` | `wails.json` → `build/bin/dianbing.exe` | 中文「点兵」拼音 |
| Go module | `dianbing` | `go.mod`、全部 import 路径 | `dianbing/internal/...` |
| 前端包名 | `dianbing-frontend` | `frontend/package.json` | |
| 数据目录 | `dianbing/dianbing.db` | `%AppData%`（`app.go` 拼装） | 改名会导致旧库不被读取 |
| User-Agent | `dianbing-scanner/0.1` | `internal/engine/webprobe.go` | 探测流量标识 |

> Go module 名与仓库目录名解耦，目录叫 `muster`、module 叫 `dianbing` 不影响编译。
> 若将来要把 module 也改成 `muster`，需同步替换全部 import、`wails.json`、`package.json`，
> 并处理 `%AppData%/dianbing/` 下已有数据库的迁移，否则用户会"丢"掉历史资产。

## 环境要求

- Go 1.22+
- Node 18+
- Windows 10/11（依赖 WebView2 Runtime，系统自带；老 Win7 不支持）
- Wails CLI：`go install github.com/wailsapp/wails/v2/cmd/wails@latest`

## 常用命令

```bash
# 首次：拉取 Go 依赖（含 Wails v2、modernc/sqlite）
cd muster && go mod tidy

# 开发模式（前端热更新 + 引擎直连）
wails dev

# 出包：单个 exe（frontend/dist 已内嵌）
wails build
# 产物：build/bin/dianbing.exe（文件名由 wails.json 的 outputfilename 决定）

# 只跑护栏单测
go test ./internal/guard/
```

前端可脱离 Go 独立开发（mock 模式，界面右上有「浏览器演示模式」标识）：

```bash
cd frontend && npm install && npm run dev   # http://localhost:5173
```

## 护栏设计（重要）

1. 白名单持久化在设置里；本次请求目标必须能被白名单吸收
2. 公网探测 = 设置解锁 **且** 请求勾选解锁，两者缺一不可
3. 私网模式下域名必须解析成功且全部落在私网才放行
4. HTTP 重定向跨主机同样过护栏（`CheckRedirect` 内校验）
5. 并发硬顶 200（engine 层强制，UI 调不过）
6. 引擎所有 goroutine 有 recover，panic 不带崩 UI，错误走 `scan:progress` 事件上报

## 路线图

- [x] M1：全链路打通——Web 探测（常见端口直探）+ 规则指纹 + SQLite + UI
- [x] M2：主机发现 + TCP Connect 端口扫描（纯 Go 零依赖免 Npcap，支持全端口 1-65535，tcp 资产入库，任务审计表）
- [ ] M3：AI 档 2/3——Ollama 批量打标（batch=32）+ 云 API，灰色 banner 回写规则库；异常端口数检测（疑似安全设备代答）
- [ ] M4：nuclei 深度探测 + Agent 决策回注 + 攻击面报告
- [ ] M5：资产历史快照对比 / 变更监控

## 协议注意

自研代码无第三方传染问题：Wails (MIT)、modernc/sqlite (BSD)、ProjectDiscovery 全家桶 (MIT)。
参考 ARL-Next 架构时只学思路，不抄代码（GPL-3.0 有传染性）。
