<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { api, isNativeNow, onProgress } from './services/api'
import type { Asset, Progress, Settings } from './types'

const settings = ref<Settings>({ whitelist: '', allowPublic: false, maxRate: 200 })
const showSettings = ref(true)

const form = reactive({
  targets: '',
  ports: '',
  concurrency: 50,
  allowPublic: false,
  mode: 'fast' as 'fast' | 'deep',
  fullRange: false
})

// 端口解析：支持单个端口、范围（8000-8100）、全端口关键字（all / 1-65535）
function parsePorts(text: string): { ports: number[]; fullRange: boolean } {
  const tokens = text.split(/[,\s]+/).map(t => t.trim()).filter(Boolean)
  let fullRange = false
  const ports = new Set<number>()
  for (const t of tokens) {
    if (/^(all|full|\*)$/i.test(t) || t === '1-65535') {
      fullRange = true
      continue
    }
    const m = t.match(/^(\d{1,5})-(\d{1,5})$/)
    if (m) {
      let a = Number(m[1]); let b = Number(m[2])
      if (a > b) { const tmp = a; a = b; b = tmp }
      for (let p = Math.max(1, a); p <= Math.min(65535, b); p++) ports.add(p)
      continue
    }
    const n = Number(t)
    if (n > 0 && n < 65536) ports.add(n)
  }
  return { ports: [...ports], fullRange }
}

// 流水线阶段的中文展示名
const stageNames: Record<string, string> = {
  starting: '启动中',
  resolve: '域名解析',
  'host-discovery': '主机发现',
  'port-scan': '端口扫描',
  'web-probe': 'Web 探测',
  summary: '汇总',
  'store-error': '入库异常'
}

const scanning = ref(false)
const progress = ref<Progress>({ taskId: '', stage: '', done: 0, total: 0, found: 0, current: '' })
const assets = ref<Asset[]>([])
const onlyThisTask = ref(true)
const errorMsg = ref('')
const refreshing = ref(false)
const refreshNote = ref('')

const shownAssets = computed(() => {
  if (!onlyThisTask.value || !progress.value.taskId) return assets.value
  return assets.value.filter(a => a.taskId === progress.value.taskId)
})

// 扫描范围预览：让「实际会扫多少」在点开始前就可见
const scopePreview = computed(() => {
  const lines = form.targets.split('\n').map(t => t.trim()).filter(t => t && !t.startsWith('#'))
  let hosts = 0
  for (const l of lines) {
    const m = l.match(/\/(\d{1,2})$/)
    if (m) {
      const bits = Number(m[1])
      hosts += bits >= 16 ? Math.pow(2, 32 - bits) : 1
    } else {
      hosts += 1
    }
  }
  const parsed = parsePorts(form.ports)
  const fullRange = form.fullRange || parsed.fullRange
  let ports: number
  if (form.mode !== 'deep') {
    ports = parsed.ports.length || 9
  } else if (fullRange) {
    ports = 65535
  } else {
    ports = parsed.ports.length || 100
  }
  return { hosts, ports, combos: hosts * ports, fullRange }
})

const filterHint = computed(() =>
  onlyThisTask.value ? '只显示最近一次任务发现的资产，取消勾选查看全部历史' : '显示所有任务的资产'
)

let unsub: (() => void) | null = null

// 绑定注入是异步的（34115 浏览器桥），轮询检测，就位后重载设置与资产
const isNative = ref(isNativeNow())

onMounted(async () => {
  const poll = setInterval(() => {
    if (isNativeNow() === isNative.value) return
    isNative.value = isNativeNow()
    clearInterval(poll)
    api.GetSettings().then(s => {
      settings.value = s
      form.targets = s.whitelist
      form.allowPublic = s.allowPublic
    }).catch(() => {})
    refreshAssets()
  }, 500)
  setTimeout(() => clearInterval(poll), 20000)

  try {
    settings.value = await api.GetSettings()
    form.targets = settings.value.whitelist
    form.allowPublic = settings.value.allowPublic
  } catch (e) {
    errorMsg.value = `加载设置失败: ${e}`
  }
  unsub = onProgress((p: Progress) => {
    progress.value = p
    if (p.stage === 'failed' || p.stage === 'crashed') {
      errorMsg.value = p.error || '任务异常终止'
      scanning.value = false
    }
    if (p.stage === 'finished' || p.stage === 'summary') {
      scanning.value = false
      refreshAssets()
    }
  })
  refreshAssets()
})

onUnmounted(() => { unsub?.() })

async function saveSettings() {
  settings.value.whitelist = form.targets
  settings.value.allowPublic = form.allowPublic
  settings.value.maxRate = 200
  await api.SaveSettings(settings.value)
  errorMsg.value = ''
}

async function startScan() {
  errorMsg.value = ''
  const targets = form.targets.split('\n').map(t => t.trim()).filter(t => t && !t.startsWith('#'))
  if (targets.length === 0) {
    errorMsg.value = '请填写至少一个目标（IP / CIDR / 域名）'
    return
  }
  const parsed = parsePorts(form.ports)
  // 全端口可由勾选框或端口框关键字（all / 1-65535）任一触发
  const fullRange = form.fullRange || parsed.fullRange
  if (fullRange && form.mode !== 'deep') {
    errorMsg.value = '全端口扫描只在「深度」模式下支持（快速模式仅直探 Web 端口）'
    return
  }
  scanning.value = true
  progress.value = { taskId: '', stage: 'starting', done: 0, total: 0, found: 0, current: '' }
  try {
    await saveSettings()
    await api.StartScan({
      targets,
      ports: parsed.ports,
      concurrency: Math.min(form.concurrency, 200),
      allowPublic: form.allowPublic,
      mode: form.mode,
      fullRange
    })
  } catch (e: any) {
    errorMsg.value = String(e?.message ?? e)
    scanning.value = false
  }
}

async function stopScan() {
  try {
    await api.StopScan()
  } finally {
    scanning.value = false
  }
}

async function refreshAssets() {
  refreshing.value = true
  try {
    const list = await api.GetAssets(500)
    assets.value = list
    refreshNote.value = `已加载 ${list.length} 条（${new Date().toLocaleTimeString()}）`
    errorMsg.value = ''
  } catch (e: any) {
    refreshNote.value = ''
    errorMsg.value = `加载资产失败: ${e?.message ?? e}`
  } finally {
    refreshing.value = false
  }
}

function pct(): number {
  const p = progress.value
  if (!p.total) return 0
  return Math.min(100, Math.round((p.done / p.total) * 100))
}
</script>

<template>
  <div class="layout">
    <header class="topbar">
      <div class="brand">
        <span class="logo"></span>
        <h1>点兵 · AI 资产测绘</h1>
        <span class="mode-badge" :class="isNative ? 'native' : 'mock'">
          {{ isNative ? '引擎已连接' : '浏览器演示模式' }}
        </span>
      </div>
      <button class="btn ghost" @click="showSettings = !showSettings">
        {{ showSettings ? '收起设置' : '目标与白名单' }}
      </button>
    </header>

    <div v-if="showSettings" class="card">
      <h2>目标范围（护栏）</h2>
      <p class="hint">
        每行一个目标，支持 IP、CIDR、域名。默认仅允许私网（10/172.16-31/192.168/127/169.254），
        公网探测需勾选解锁且命中白名单，双重校验在引擎层强制执行。
      </p>
      <textarea v-model="form.targets" rows="4" spellcheck="false"
        placeholder="192.168.1.0/24&#10;10.0.0.5&#10;nas.home.lan"></textarea>
      <div class="row">
        <label class="check">
          <input type="checkbox" v-model="form.allowPublic" />
          解锁公网探测（需白名单命中，默认关闭）
        </label>
        <span class="hint">并发硬顶 200，防止扫瘫内网</span>
      </div>
    </div>

    <div class="card">
      <h2>探测任务</h2>
      <div class="row">
        <label class="check">
          <input type="radio" value="fast" v-model="form.mode" />
          快速（Web 端口直探）
        </label>
        <label class="check" title="先 TCP 探活主机，再做端口扫描，最后对开放端口做 Web 探测；非 HTTP 端口也入库（SSH/SMB/RDP 等）">
          <input type="radio" value="deep" v-model="form.mode" />
          深度（主机发现 + 端口扫描）
        </label>
        <label>端口</label>
        <input v-model="form.ports"
          :placeholder="form.mode === 'deep' ? '留空用内置常用集；支持 8000-8100 范围、all=全端口' : '留空用默认：80,443,8080,8443,8000,8888,9090,7001,9080'" />
        <label class="check" :title="form.mode === 'deep' ? '扫描全部 1-65535 端口，单台主机约 1-3 分钟，有防火墙时更久' : '仅深度模式支持'">
          <input type="checkbox" v-model="form.fullRange" :disabled="form.mode !== 'deep'" />
          全端口 1-65535
        </label>
        <label>并发</label>
        <input class="num" type="number" v-model.number="form.concurrency" min="1" max="200" />
      </div>
      <div class="hint scope">
        本次扫描范围：约 {{ scopePreview.hosts }} 台主机 × {{ scopePreview.ports }} 个端口
        ≈ {{ scopePreview.combos.toLocaleString() }} 次连接
        <span v-if="form.mode === 'deep'">（关闭端口毫秒级返回，被防火墙丢弃的端口每次约 1–2 秒）</span>
        <span v-if="scopePreview.fullRange" class="tag">全端口</span>
      </div>
      <div class="row actions">
        <button class="btn primary" :disabled="scanning" @click="startScan">
          {{ scanning ? '探测中…' : '开始探测' }}
        </button>
        <button class="btn danger" :disabled="!scanning" @click="stopScan">停止</button>
        <button class="btn ghost" :disabled="refreshing" @click="refreshAssets">
          {{ refreshing ? '加载中…' : '刷新资产' }}
        </button>
        <span v-if="refreshNote" class="dim">{{ refreshNote }}</span>
      </div>
      <div v-if="progress.stage && progress.stage !== 'finished'" class="progress-block">
        <div class="bar"><div class="fill" :style="{ width: pct() + '%' }"></div></div>
        <div class="progress-text">
          {{ stageNames[progress.stage] || progress.stage }} · {{ progress.done }}/{{ progress.total }}
          · 已发现 {{ progress.found }} 条
          <span v-if="progress.current" class="dim">· {{ progress.current }}</span>
        </div>
      </div>
      <div v-if="errorMsg" class="error">{{ errorMsg }}</div>
    </div>

    <div class="card grow">
      <div class="table-header">
        <h2>资产列表（显示 {{ shownAssets.length }} / 共 {{ assets.length }}）</h2>
        <label class="check" :title="filterHint">
          <input type="checkbox" v-model="onlyThisTask" />
          只看本次任务
        </label>
      </div>
      <div v-if="onlyThisTask && assets.length > shownAssets.length" class="hint">
        已按本次任务筛选，另有 {{ assets.length - shownAssets.length }} 条历史资产被隐藏
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>目标</th><th>协议</th><th>状态</th><th>标题</th>
              <th>Server</th><th>指纹</th><th>最近发现</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in shownAssets" :key="a.id">
              <td class="mono">{{ a.host }}:{{ a.port }}</td>
              <td>{{ a.scheme }}</td>
              <td><span v-if="a.scheme === 'tcp'" class="dim">TCP开放</span><span v-else class="status" :class="a.status < 400 ? 'ok' : 'warn'">{{ a.status }}</span></td>
              <td class="title-cell">{{ a.title || '—' }}</td>
              <td>{{ a.server || '—' }}</td>
              <td>
                <span v-for="f in a.fingerprint" :key="f" class="tag">{{ f }}</span>
                <span v-if="!a.fingerprint?.length" class="dim">—</span>
              </td>
              <td class="dim">{{ a.lastSeen?.slice(0, 19).replace('T', ' ') }}</td>
            </tr>
            <tr v-if="!shownAssets.length">
              <td colspan="7" class="empty">
                {{ assets.length ? '本次任务无资产（其他任务的资产被筛选隐藏了）' : '暂无资产：目标在默认端口（80/443/8080 等）上没有响应 HTTP 的服务，或网络不可达' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.layout { display: flex; flex-direction: column; gap: 12px; padding: 16px; height: 100vh; box-sizing: border-box; }
.topbar { display: flex; justify-content: space-between; align-items: center; }
.brand { display: flex; align-items: center; gap: 10px; }
.brand h1 { font-size: 18px; margin: 0; font-weight: 600; }
.logo { width: 14px; height: 14px; border-radius: 4px; background: #185fa5; display: inline-block; }
.mode-badge { font-size: 12px; padding: 2px 10px; border-radius: 999px; }
.mode-badge.native { background: #e1f5ee; color: #0f6e56; }
.mode-badge.mock { background: #faeeda; color: #854f0b; }
.card { background: #fff; border: 1px solid rgba(0,0,0,.12); border-radius: 12px; padding: 14px 16px; }
.card.grow { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
.card h2 { font-size: 14px; font-weight: 600; margin: 0 0 8px; }
.hint { font-size: 12px; color: #888780; margin: 4px 0 8px; }
textarea { width: 100%; box-sizing: border-box; font-family: var(--font-mono, monospace); font-size: 13px; padding: 8px 10px; border: 1px solid rgba(0,0,0,.2); border-radius: 8px; resize: vertical; }
input[type="text"], input:not([type]) { flex: 1; font-size: 13px; padding: 6px 10px; border: 1px solid rgba(0,0,0,.2); border-radius: 8px; }
input.num { width: 80px; flex: none; }
.row { display: flex; align-items: center; gap: 10px; margin-top: 8px; }
.row label { font-size: 13px; }
.check { display: flex; align-items: center; gap: 6px; }
.actions { margin-top: 12px; }
.btn { font-size: 13px; padding: 7px 16px; border-radius: 8px; border: 1px solid rgba(0,0,0,.15); background: #f1efe8; cursor: pointer; }
.btn.primary { background: #185fa5; border-color: #185fa5; color: #fff; }
.btn.primary:disabled { opacity: .5; cursor: not-allowed; }
.btn.danger { background: #fcebeb; border-color: #e24b4a; color: #a32d2d; }
.btn.danger:disabled { opacity: .5; cursor: not-allowed; }
.btn.ghost { background: transparent; }
.progress-block { margin-top: 12px; }
.bar { height: 8px; background: #eceae4; border-radius: 999px; overflow: hidden; }
.fill { height: 100%; background: #1d9e75; transition: width .3s; border-radius: 999px; }
.progress-text { font-size: 12px; color: #5f5e5a; margin-top: 6px; }
.error { margin-top: 10px; font-size: 13px; color: #a32d2d; background: #fcebeb; border: 1px solid #f7c1c1; border-radius: 8px; padding: 8px 12px; }
.table-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.table-header h2 { margin: 0; }
.table-wrap { flex: 1; overflow: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; font-weight: 500; color: #5f5e5a; padding: 6px 8px; border-bottom: 1px solid rgba(0,0,0,.12); position: sticky; top: 0; background: #fff; }
td { padding: 6px 8px; border-bottom: 1px solid rgba(0,0,0,.06); vertical-align: top; }
.mono { font-family: var(--font-mono, monospace); }
.title-cell { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tag { display: inline-block; background: #eeedfe; color: #3c3489; font-size: 12px; padding: 1px 8px; border-radius: 999px; margin: 1px 4px 1px 0; }
.status.ok { color: #0f6e56; }
.status.warn { color: #a32d2d; }
.dim { color: #888780; font-size: 12px; }
.empty { text-align: center; color: #888780; padding: 24px 0; }
</style>
