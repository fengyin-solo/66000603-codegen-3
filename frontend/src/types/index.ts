export interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
}

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface Pattern {
  name: string
  severity: Severity
  pattern: string
  description: string
  suggestion: string
}

export interface ImportItemResult {
  index: number
  name: string | null
  status: 'success' | 'failed'
  action?: 'added' | 'updated'
  message?: string
  reason?: string
}

export interface ImportResult {
  total: number
  imported: number
  failed: number
  results: ImportItemResult[]
}
