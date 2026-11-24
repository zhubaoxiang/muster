# 点兵 · AI 资产测绘（桌面版）

> 点兵——沙场点兵，盘点自己有多少兵。英文标识 **Muster**，仓库目录 `muster/`；
> Go module、二进制产物与运行时数据目录统一使用 `muster`（见下方「命名与升级」）。

Wails v2 + Vue 3 + Go 单机桌面应用。探测引擎内嵌同进程，SQLite 单文件存储，
内置目标护栏（白名单 + 私网锁定 + 并发硬顶），AI 三档分析（规则指纹 → Ollama → 云 API）。

> ⚠️ 仅用于自有资产或已获书面授权的目标探测。使用前请务必阅读文末[免责声明](#免责声明)。

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

## 命名与升级

中文名「点兵」，英文标识统一为 `muster`：

| 项 | 值 |
|----|-----|
| 仓库目录 | `muster/` |
| Go module | `muster`（import 路径 `muster/internal/...`） |
| 二进制产物 | `build/bin/muster.exe`（由 `wails.json` 的 `outputfilename` 决定） |
| 前端包名 | `muster-frontend` |
| 数据目录 | `%AppData%/muster/muster.db` |
| User-Agent | `muster-scanner/0.1` |

> **升级注意**：库名经历过两次变更，最早为 `aiasset`，上一版为点兵拼音标识。
> 首次以新名字启动时，`app.go` 的 `migrateOldDB` 会按「新 → 旧」顺序找到最近的旧库
> 整体复制过来（含 `-wal`，保留未 checkpoint 的数据），资产与设置不会丢。
> 旧数据目录原样保留，确认迁移无误后可自行删除。

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
# 产物：build/bin/muster.exe（文件名由 wails.json 的 outputfilename 决定）

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

## 免责声明

> 本节为使用本软件的法律前提。下载、安装、运行本软件，即视为已完整阅读并同意以下全部条款。

1. **授权范围**：本软件仅限用于探测**自有资产**，或已取得目标所有者**书面授权**的资产。未获授权，不得使用。
2. **使用者责任**：使用者须自行确认探测行为符合所在地法律法规。在中国大陆，未经授权扫描、探测、侵入他人网络或计算机信息系统，可能违反《中华人民共和国网络安全法》《中华人民共和国刑法》第二百八十五条、第二百八十六条等规定，情节严重的须承担刑事责任。
3. **风险自担**：本软件会主动发起网络连接与探测请求，可能造成目标服务响应变慢、连接数升高、触发日志与告警；极端情况下（目标设备自身存在缺陷、链路带宽受限、防护设备误判等）**可能导致网络拥塞、服务中断甚至瘫痪**。使用者应在使用前自行评估影响，控制并发与频率，避开业务高峰。
4. **责任免除**：**因下载、使用或无法使用本软件而直接或间接导致的任何后果——包括但不限于违法行为的法律责任与行政处罚、网络中断或瘫痪、数据丢失或损坏、业务停滞、第三方索赔、商誉损失——均由使用者自行承担。作者及贡献者不承担任何法律、经济或连带责任，亦不提供任何形式的担保或技术支持承诺。**
5. **软件现状**：本软件按「现状」（AS IS）提供，不附带任何明示或暗示的担保，包括但不限于适销性、特定用途适用性与无侵权担保。
6. **条款变更**：作者保留随时修改本声明的权利，恕不另行通知，以仓库最新版本为准。

---

**许可说明**：自研代码无第三方传染问题——Wails (MIT)、modernc/sqlite (BSD)、ProjectDiscovery 全家桶 (MIT)。参考 ARL-Next 架构时只学思路，不抄代码（GPL-3.0 有传染性）。
