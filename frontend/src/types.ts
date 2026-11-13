// 与 Go 侧 internal/model 对应的类型定义
export interface ScanRequest {
  targets: string[]
  ports: number[]
  concurrency: number
  allowPublic: boolean
  mode: 'fast' | 'deep'
  fullRange: boolean
}

export interface Asset {
  id: number
  host: string
  port: number
  scheme: string
  status: number
  title: string
  server: string
  fingerprint: string[]
  taskId: string
  firstSeen: string
  lastSeen: string
}

export interface Progress {
  taskId: string
  stage: string
  done: number
  total: number
  found: number
  current: string
  error?: string
}

export interface Settings {
  whitelist: string
  allowPublic: boolean
  maxRate: number
}
