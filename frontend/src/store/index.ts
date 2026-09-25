import { defineStore } from 'pinia'
import { ref, watch } from 'vue'
import axios from 'axios'
import type { ApiResponse } from '@/types'
import { loadPatterns, savePatterns, mergePatterns } from '@/patterns'
import type { Pattern, MergeOutcome } from '@/patterns'

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
  // 漏洞模式库的唯一状态来源，漏洞模式库页面与合约审计页面共用
  const patterns = ref<Pattern[]>(loadPatterns())

  // 规则变化即持久化，刷新页面与另一个页面看到的都是同一份规则
  watch(patterns, (next) => savePatterns(next), { deep: true })

  async function uploadAndAudit(code: string, filename: string) {
    const res = await axios.post<ApiResponse<AuditResult>>('/api/audit', { code, filename })
    currentResult.value = res.data.data
    results.value.unshift(res.data.data)
    return res.data.data
  }

  /**
   * 导入一批规则与现有模式合并。
   * 由调用方先用 parseImportText 解析出条目数组；逐条校验结果在 MergeOutcome 中返回。
   * 只有校验通过的条目会落入规则库。
   */
  function importPatterns(entries: unknown[]): MergeOutcome {
    const outcome = mergePatterns(patterns.value, entries)
    patterns.value = outcome.merged
    return outcome
  }

  return { results, currentResult, patterns, uploadAndAudit, importPatterns }
})
