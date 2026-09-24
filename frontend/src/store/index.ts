import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import type { ApiResponse, Pattern, ImportResult } from '@/types'

export interface AuditResult {
  id: string
  filename: string
  score: number
  vulnerabilities: Vulnerability[]
  gasIssues: GasIssue[]
  timestamp: string
}

export interface Vulnerability {
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  line: number
  description: string
  suggestion: string
}

export interface GasIssue {
  functionName: string
  currentGas: number
  optimizedGas: number
  suggestion: string
}

export const useAuditStore = defineStore('audit', () => {
  const results = ref<AuditResult[]>([])
  const currentResult = ref<AuditResult | null>(null)
  const patterns = ref<Pattern[]>([])

  async function uploadAndAudit(code: string, filename: string) {
    const res = await axios.post<ApiResponse<AuditResult>>('/api/audit', { code, filename })
    currentResult.value = res.data.data
    results.value.unshift(res.data.data)
    return res.data.data
  }

  async function fetchPatterns() {
    const res = await axios.get<ApiResponse<Pattern[]>>('/api/patterns')
    patterns.value = res.data.data
  }

  async function importPatterns(items: unknown[]): Promise<ImportResult> {
    const res = await axios.post<ApiResponse<ImportResult>>('/api/patterns/import', { patterns: items })
    // 合并完成后刷新，保证模式库展示与库中当前规则一致
    await fetchPatterns()
    return res.data.data
  }

  return { results, currentResult, patterns, uploadAndAudit, fetchPatterns, importPatterns }
})
