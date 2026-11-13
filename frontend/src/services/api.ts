import type { Asset, Progress, ScanRequest, Settings } from '../types'

// Go 侧 Wails 绑定接口（wails build/dev 时由 wailsjs 自动生成）
type GoApp = {
  StartScan(req: ScanRequest): Promise<string>
  StopScan(): Promise<void>
  GetAssets(limit: number): Promise<Asset[]>
  GetSettings(): Promise<Settings>
  SaveSettings(s: Settings): Promise<void>
}

declare global {
  interface Window {
    go?: { app?: GoApp }
    runtime?: { EventsOn(name: string, cb: (data: any) => void): void }
  }
}

const w = window as unknown as Window

// 每次调用时动态检测绑定。
// 桌面 WebView 里 window.go 在脚本执行前就已注入（同步）；
// 浏览器走 localhost:34115 桥时是 websocket 异步注入，页面加载瞬间
// 可能还不存在，所以不能在模块加载时一次性判定，否则会永久误判为 mock。
// Go 侧绑定注册在 package main 的 *App 上，Wails 命名空间为 go.main.App；
// 兼容兜底 go.app。桌面 WebView 同步注入，34115 浏览器桥异步注入。
function nativeApp(): GoApp | null {
  return (w.go as any)?.main?.App ?? (w.go as any)?.app ?? null
}

export function isNativeNow(): boolean {
  return !!nativeApp()
}

// ---------- 浏览器开发模式的 mock 实现 ----------
// 直接 npm run dev 时没有 Wails 运行时，用 mock 走通 UI 全流程
const mockApp: GoApp = {
  async StartScan(req: ScanRequest): Promise<string> {
    const taskId = `t${Date.now()}`
    setTimeout(async () => {
      // mock 也尊重用户输入的目标：取第一个目标的网段生成模拟资产
      const first = (req.targets[0] || '192.168.1.0').trim()
      const baseIP = /^\d+\.\d+\.\d+\.\d+$/.test(first)
        ? first.replace(/\.\d+$/, '')
        : first.replace(/^https?:\/\//, '').split('/')[0]
      const now = new Date().toISOString()
      const mk = (suffix: number, port: number, scheme: string, status: number, title: string, server: string, fp: string[]): Asset => ({
        id: suffix, host: `${baseIP}.${suffix}`, port, scheme, status, title, server, fingerprint: fp,
        taskId, firstSeen: now, lastSeen: now
      })
      const fake: Asset[] = [
        mk(1, 80, 'http', 200, '路由器管理登录', 'nginx', ['Nginx', 'Login-Form']),
        mk(10, 8080, 'http', 200, 'Jenkins', 'Jetty', ['Jetty', 'Jenkins']),
        mk(20, 443, 'https', 200, '内部 OA 系统', 'Apache', ['Apache', 'Vue', 'Login-Form']),
        mk(30, 9090, 'http', 302, '登录页', 'Tomcat', ['Tomcat', 'Login-Form']),
        mk(40, 8443, 'https', 200, 'MinIO Console', '', ['MinIO'])
      ]
      mockEmitter.emit({ taskId, stage: 'web-probe', done: 0, total: 40, found: 0, current: req.targets.join(', ') })
      for (let i = 1; i <= 40; i++) {
        await new Promise(r => setTimeout(r, 80))
        mockEmitter.emit({ taskId, stage: 'web-probe', done: i, total: 40, found: Math.min(fake.length, Math.ceil(i / 8)), current: `${baseIP}.${Math.min(254, 100 + i)}` })
      }
      mockEmitter.emit({ taskId, stage: 'finished', done: 40, total: 40, found: fake.length, current: '' })
      mockAssets = fake
    }, 300)
    return taskId
  },
  async StopScan(): Promise<void> {},
  async GetAssets(limit: number): Promise<Asset[]> {
    return mockAssets.slice(0, limit)
  },
  async GetSettings(): Promise<Settings> {
    return { whitelist: '', allowPublic: false, maxRate: 200 }
  },
  async SaveSettings(s: Settings): Promise<void> {}
}

let mockAssets: Asset[] = []
const mockEmitter = {
  subs: new Set<(p: Progress) => void>(),
  emit(p: Progress) { this.subs.forEach(f => f(p)) },
  subscribe(f: (p: Progress) => void) {
    this.subs.add(f)
    return () => this.subs.delete(f)
  }
}

// 每个方法调用时优先走真绑定，绑定未就位才降级 mock
export const api: GoApp = {
  StartScan(req) {
    const a = nativeApp()
    return a ? a.StartScan(req) : mockApp.StartScan(req)
  },
  StopScan() {
    const a = nativeApp()
    return a ? a.StopScan() : mockApp.StopScan()
  },
  GetAssets(limit) {
    const a = nativeApp()
    return a ? a.GetAssets(limit) : mockApp.GetAssets(limit)
  },
  GetSettings() {
    const a = nativeApp()
    return a ? a.GetSettings() : mockApp.GetSettings()
  },
  SaveSettings(s) {
    const a = nativeApp()
    return a ? a.SaveSettings(s) : mockApp.SaveSettings(s)
  }
}

export function onProgress(cb: (p: Progress) => void): () => void {
  // mock 发射器始终订阅（真引擎模式它不会发射，无副作用）
  const unsubMock = mockEmitter.subscribe(cb)
  // runtime 注入是异步的（34115 浏览器桥），轮询等它就位后再挂真事件
  let tries = 0
  const timer = setInterval(() => {
    if (w.runtime?.EventsOn) {
      w.runtime.EventsOn('scan:progress', cb)
      clearInterval(timer)
      return
    }
    if (++tries > 40) clearInterval(timer) // 20s 仍无 runtime = 纯 mock 场景
  }, 500)
  return () => {
    clearInterval(timer)
    unsubMock?.()
  }
}
