/**
 * 漏洞模式库的唯一定义来源，漏洞模式库页面与合约审计页面共用。
 * 规则结构：name / severity / description / regex
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface Pattern {
  name: string
  severity: Severity
  description: string
  regex: string
}

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as string[]).includes(value)
}

/** 内置规则，顺序即页面原始展示顺序，请勿调整 */
export const DEFAULT_PATTERNS: Pattern[] = [
  { name: '重入攻击', severity: 'critical', description: '使用低级call/send转移ETH，未做重入防护', regex: '.*\\.call\\{.*\\}\\(.*\\).*;' },
  { name: '整数溢出', severity: 'high', description: 'Solidity 0.7中可能发生整数溢出', regex: '\\+\\s*=|\\-\\s*=|\\*\\s*=' },
  { name: '未授权访问', severity: 'high', description: '关键函数缺少访问控制修饰符', regex: 'function\\s+\\w+\\s*\\([^)]*\\)\\s*(?:public)?\\s*(?:payable)?\\s*\\{[^}]*\\}' },
  { name: '自杀指令', severity: 'medium', description: 'selfdestruct可被用于销毁合约', regex: 'selfdestruct|suicide' },
  { name: 'tx.origin钓鱼', severity: 'high', description: '使用tx.origin进行身份验证可被钓鱼', regex: 'tx\\.origin' },
  { name: '精确度损失', severity: 'medium', description: '除法运算可能导致精度损失', regex: '/\\s*\\d+' },
]

/* ----------------------------- 导入校验与合并 ----------------------------- */

export type ItemStatus = 'added' | 'updated' | 'failed'

/** 失败时回传候选字段，供界面回填后修正重导 */
export interface CandidateFields {
  name: string
  severity: string
  description: string
  regex: string
}

export interface ItemResult {
  /** 条目在本次导入中的序号（从 1 开始） */
  index: number
  name: string
  status: ItemStatus
  message: string
  candidate?: CandidateFields
}

export interface MergeOutcome {
  merged: Pattern[]
  results: ItemResult[]
  added: number
  updated: number
  failed: number
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * 将一批外部条目合并进已有规则：
 * - 逐条校验，任一格式问题只影响该条目
 * - 同名条目：以导入内容为准（描述/正则被覆盖），但保留原有严重程度，位置不变
 * - 新条目按导入顺序追加在末尾
 */
export function mergePatterns(existing: Pattern[], entries: unknown[]): MergeOutcome {
  const merged: Pattern[] = existing.map((p) => ({ ...p }))
  const position = new Map<string, number>()
  merged.forEach((p, i) => position.set(p.name, i))
  /** 本批次已出现的名称 -> 首次出现的序号（一批数据内部不允许重名） */
  const seenInBatch = new Map<string, number>()

  const results: ItemResult[] = []
  let added = 0
  let updated = 0
  let failed = 0

  entries.forEach((entry, i) => {
    const index = i + 1
    const candidate: CandidateFields = {
      name: isPlainObject(entry) && typeof entry.name === 'string' ? entry.name.trim() : '',
      severity: isPlainObject(entry) && typeof entry.severity === 'string' ? entry.severity.trim().toLowerCase() : '',
      description: isPlainObject(entry) && typeof entry.description === 'string' ? entry.description.trim() : '',
      regex: isPlainObject(entry) && typeof entry.regex === 'string' ? entry.regex.trim() : '',
    }

    const reject = (reason: string) => {
      failed += 1
      results.push({ index, name: candidate.name, status: 'failed', message: reason, candidate: { ...candidate } })
    }

    if (!isPlainObject(entry)) {
      return reject('条目必须是 JSON 对象，例如 {"name":"规则名","severity":"high","description":"...","regex":"..."}')
    }
    if (!candidate.name) {
      return reject('缺少 name（规则名称）或名称为空')
    }
    if (!candidate.description) {
      return reject('缺少 description（规则描述）或内容为空')
    }
    if (!candidate.regex) {
      return reject('缺少 regex（正则表达式）或内容为空')
    }
    try {
      // eslint-disable-next-line no-new
      new RegExp(candidate.regex)
    } catch (e) {
      return reject(`正则表达式无效：${(e as Error).message}`)
    }

    const priorIndex = seenInBatch.get(candidate.name)
    if (priorIndex !== undefined) {
      return reject(`与本次导入中的第 ${priorIndex} 条重名，同一批数据中不允许重名`)
    }

    const existingIndex = position.get(candidate.name)
    if (existingIndex === undefined) {
      // 新增条目必须带合法的严重程度
      if (!isSeverity(candidate.severity)) {
        const shown = candidate.severity ? `“${candidate.severity}”` : '空'
        return reject(`严重程度 ${shown} 无效，新增规则必须取 critical / high / medium / low 之一`)
      }
      merged.push({
        name: candidate.name,
        severity: candidate.severity,
        description: candidate.description,
        regex: candidate.regex,
      })
      position.set(candidate.name, merged.length - 1)
      seenInBatch.set(candidate.name, index)
      added += 1
      results.push({ index, name: candidate.name, status: 'added', message: '新增成功' })
    } else {
      // 同名覆盖：内容以导入为准，严重程度保留原值
      const oldSeverity = merged[existingIndex].severity
      merged[existingIndex] = {
        name: candidate.name,
        severity: oldSeverity,
        description: candidate.description,
        regex: candidate.regex,
      }
      seenInBatch.set(candidate.name, index)
      updated += 1
      let message = `已更新同名规则，保留原有严重程度：${oldSeverity}`
      if (!isSeverity(candidate.severity)) {
        message += '（导入文件中的严重程度无效，已忽略）'
      } else if (candidate.severity !== oldSeverity) {
        message += `（导入值 ${candidate.severity} 已忽略）`
      }
      results.push({ index, name: candidate.name, status: 'updated', message })
    }
  })

  return { merged, results, added, updated, failed }
}

/* ------------------------------- 文件解析 --------------------------------- */

/**
 * 接受两种文件形态：
 * 1) 规则数组 [{...}]
 * 2) 包含 patterns 数组的对象 { "patterns": [{...}] }
 * 解析/结构错误统一抛出带中文说明的 Error。
 */
export function parseImportText(text: string): unknown[] {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (e) {
    throw new Error(`JSON 解析失败：${(e as Error).message}`)
  }

  if (Array.isArray(data)) {
    if (data.length === 0) throw new Error('文件内容为空数组，没有可导入的规则')
    return data
  }
  if (isPlainObject(data) && Array.isArray(data.patterns)) {
    if (data.patterns.length === 0) throw new Error('patterns 数组为空，没有可导入的规则')
    return data.patterns as unknown[]
  }
  throw new Error('文件格式不正确：顶层应为规则数组，或包含 patterns 数组的对象')
}

/** 导出内容与库中当前规则一一对应，且只包含规则本身的四个字段 */
export function serializePatterns(patterns: Pattern[]): string {
  const data = patterns.map((p) => ({
    name: p.name,
    severity: p.severity,
    description: p.description,
    regex: p.regex,
  }))
  return JSON.stringify(data, null, 2)
}

/* ------------------------------ 本地持久化 -------------------------------- */

const STORAGE_KEY = 'vulnerability-patterns:v1'

/** 严格校验一条已缓存的规则（含严重程度与正则合法性），任一不过则整体回退默认规则 */
function isValidStoredPattern(value: unknown): value is Pattern {
  if (!isPlainObject(value)) return false
  if (typeof value.name !== 'string' || !value.name.trim()) return false
  if (typeof value.description !== 'string' || !value.description.trim()) return false
  if (typeof value.regex !== 'string' || !value.regex.trim()) return false
  if (!isSeverity(value.severity)) return false
  try {
    // eslint-disable-next-line no-new
    new RegExp(value.regex)
  } catch {
    return false
  }
  return true
}

export function loadPatterns(): Pattern[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return DEFAULT_PATTERNS.map((p) => ({ ...p }))
    const parsed: unknown = JSON.parse(raw)
    if (Array.isArray(parsed) && parsed.length > 0 && parsed.every(isValidStoredPattern)) {
      return parsed.map((p) => ({
        name: p.name.trim(),
        severity: p.severity,
        description: p.description.trim(),
        regex: p.regex.trim(),
      }))
    }
  } catch {
    // 落到默认规则
  }
  return DEFAULT_PATTERNS.map((p) => ({ ...p }))
}

export function savePatterns(patterns: Pattern[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, serializePatterns(patterns))
  } catch {
    // 隐私模式等场景下持久化失败不影响内存中的规则库
  }
}
