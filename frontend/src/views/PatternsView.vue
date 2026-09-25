<template>
  <div class="patterns">
    <div class="page-head">
      <div>
        <h2>漏洞模式库</h2>
        <div class="page-sub">共 {{ store.patterns.length }} 条规则，导出/导入均以此处当前规则为准</div>
      </div>
      <div class="head-actions">
        <button class="btn-secondary" @click="exportPatterns">导出当前规则</button>
        <button class="btn-primary" @click="openImport">导入规则</button>
      </div>
    </div>

    <div class="pattern-grid">
      <div v-for="p in store.patterns" :key="p.name" class="pattern-card">
        <div class="pattern-name">{{ p.name }}</div>
        <div class="pattern-severity" :class="p.severity">{{ p.severity }}</div>
        <div class="pattern-desc">{{ p.description }}</div>
        <div class="pattern-regex">正则: <code>{{ p.regex }}</code></div>
      </div>
    </div>

    <!-- 导入弹窗 -->
    <div v-if="importVisible" class="modal-mask" @click.self="closeImport">
      <div class="modal">
        <div class="modal-head">
          <span>导入漏洞规则</span>
          <button class="modal-close" @click="closeImport">×</button>
        </div>

        <!-- 第一步：选择文件 / 粘贴内容 -->
        <div v-if="phase === 'select'" class="modal-body">
          <p class="modal-tip">
            支持规则数组 <code>[{...}]</code> 或 <code>{"patterns":[{...}]}</code> 两种 JSON 形态。
            每条规则包含 name / severity / description / regex；同名规则以导入内容为准，但保留原有严重程度。
          </p>
          <div class="file-row">
            <input ref="fileInputEl" type="file" accept=".json,application/json" class="file-input" @change="onFileChange" />
            <button class="btn-secondary btn-sm" @click="loadFile">读取文件</button>
            <span v-if="fileName" class="file-name">{{ fileName }}</span>
          </div>
          <div class="or-line">或直接粘贴 JSON 内容：</div>
          <textarea v-model="importText" class="json-input" rows="10" placeholder='[{"name":"新规则","severity":"low","description":"规则描述","regex":"xxx"}]'></textarea>
          <div v-if="parseError" class="alert-error">{{ parseError }}</div>
          <div class="modal-actions">
            <button class="btn-secondary" @click="closeImport">取消</button>
            <button class="btn-primary" :disabled="!importText.trim()" @click="startImport">开始导入</button>
          </div>
        </div>

        <!-- 第二步：逐条结果 -->
        <div v-else class="modal-body">
          <div class="summary">
            <span class="sum-added">新增 {{ totals.added }}</span>
            <span class="sum-updated">更新 {{ totals.updated }}</span>
            <span class="sum-failed">失败 {{ totals.failed }}</span>
          </div>
          <div class="result-list">
            <div v-for="row in rows" :key="row.rid" class="result-row" :class="row.status">
              <div class="result-line">
                <span class="result-index">#{{ row.index }}</span>
                <span class="result-name">{{ row.name || '(未命名)' }}</span>
                <span class="result-badge" :class="row.status">{{ statusText(row.status) }}</span>
                <button
                  v-if="row.status === 'failed' && rows.filter(r => r.status === 'failed').length > 1"
                  class="btn-retry-one"
                  @click="retryRows([row])"
                >重试此条</button>
              </div>
              <div class="result-msg" :class="row.status">{{ row.message }}</div>

              <!-- 失败条目：可就地修正后重新导入 -->
              <div v-if="row.status === 'failed' && row.candidate" class="fix-form">
                <div class="fix-grid">
                  <label>名称
                    <input v-model="row.candidate.name" placeholder="规则名称（必填）" />
                  </label>
                  <label>严重程度
                    <select v-model="row.candidate.severity">
                      <option value="" disabled>选择严重程度</option>
                      <option value="critical">critical</option>
                      <option value="high">high</option>
                      <option value="medium">medium</option>
                      <option value="low">low</option>
                    </select>
                  </label>
                  <label class="fix-full">描述
                    <input v-model="row.candidate.description" placeholder="规则描述（必填）" />
                  </label>
                  <label class="fix-full">正则表达式
                    <input v-model="row.candidate.regex" placeholder="正则表达式（必填且需合法）" class="mono" />
                  </label>
                </div>
                <div class="fix-actions">
                  <button class="btn-primary btn-sm" @click="retryRows([row])">修正后重新导入</button>
                </div>
              </div>
            </div>
          </div>
          <div class="modal-actions">
            <button class="btn-secondary" @click="backToSelect">继续导入其他文件</button>
            <button v-if="failedRows.length > 0" class="btn-secondary" @click="retryRows(failedRows)">
              重试全部失败项 ({{ failedRows.length }})
            </button>
            <button class="btn-primary" @click="closeImport">完成</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from "vue"
import { useAuditStore } from "@/store"
import {
  parseImportText,
  serializePatterns,
} from "@/patterns"
import type { ItemStatus, ItemResult, CandidateFields, MergeOutcome } from "@/patterns"

const store = useAuditStore()

/* --------------------------------- 导出 ---------------------------------- */

function exportPatterns() {
  const blob = new Blob([serializePatterns(store.patterns)], { type: "application/json;charset=utf-8" })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  const stamp = new Date().toISOString().slice(0, 10)
  a.href = url
  a.download = `vulnerability-patterns-${stamp}.json`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

/* --------------------------------- 导入 ---------------------------------- */

interface ResultRow {
  rid: number
  index: number
  name: string
  status: ItemStatus
  message: string
  candidate?: CandidateFields
}

let ridSeq = 0
const importVisible = ref(false)
const phase = ref<"select" | "result">("select")
const importText = ref("")
const fileName = ref("")
const parseError = ref("")
const rows = ref<ResultRow[]>([])
const totals = ref({ added: 0, updated: 0, failed: 0 })
const pendingFile = ref<File | null>(null)
const fileInputEl = ref<HTMLInputElement | null>(null)

const failedRows = computed(() => rows.value.filter((r) => r.status === "failed"))

function statusText(status: ItemStatus): string {
  return status === "added" ? "新增" : status === "updated" ? "更新" : "失败"
}

function openImport() {
  importVisible.value = true
  phase.value = "select"
  importText.value = ""
  fileName.value = ""
  parseError.value = ""
  rows.value = []
  totals.value = { added: 0, updated: 0, failed: 0 }
  pendingFile.value = null
  if (fileInputEl.value) fileInputEl.value.value = ""
}

function closeImport() {
  importVisible.value = false
}

function backToSelect() {
  phase.value = "select"
  importText.value = ""
  fileName.value = ""
  parseError.value = ""
  pendingFile.value = null
  if (fileInputEl.value) fileInputEl.value.value = ""
  // 已产生的逐条结果保留在弹窗中，重新选择文件后继续追加
}

function onFileChange(e: Event) {
  const input = e.target as HTMLInputElement
  pendingFile.value = input.files && input.files.length > 0 ? input.files[0] : null
  parseError.value = ""
}

function loadFile() {
  if (!pendingFile.value) {
    parseError.value = "请先选择一个 JSON 文件"
    return
  }
  const reader = new FileReader()
  reader.onload = () => {
    importText.value = String(reader.result ?? "")
    fileName.value = pendingFile.value?.name ?? ""
    parseError.value = ""
  }
  reader.onerror = () => {
    parseError.value = `读取文件失败：${reader.error?.message ?? "未知错误"}`
  }
  reader.readAsText(pendingFile.value, "utf-8")
}

function toRows(results: ItemResult[]): ResultRow[] {
  return results.map((r) => ({
    rid: ++ridSeq,
    index: r.index,
    name: r.name,
    status: r.status,
    message: r.message,
    candidate: r.candidate ? { ...r.candidate } : undefined,
  }))
}

function startImport() {
  parseError.value = ""
  let entries: unknown[]
  try {
    entries = parseImportText(importText.value)
  } catch (e) {
    parseError.value = (e as Error).message
    return
  }
  appendOutcome(store.importPatterns(entries))
}

/** 把一次导入（或重试）的逐条结果追加到结果区并累计统计 */
function appendOutcome(outcome: MergeOutcome) {
  rows.value.push(...toRows(outcome.results))
  totals.value.added += outcome.added
  totals.value.updated += outcome.updated
  totals.value.failed += outcome.failed
  phase.value = "result"
}

/**
 * 修正后重新导入：失败条目逐条再次走同一套校验/合并流程。
 * 重试前先把这些行原有的“失败”计数扣除，再按新结果累计。
 */
function retryRows(targets: ResultRow[]) {
  parseError.value = ""
  const prevFailed = targets.length
  const entries = targets.map((row) => ({
    name: row.candidate?.name ?? "",
    severity: row.candidate?.severity ?? "",
    description: row.candidate?.description ?? "",
    regex: row.candidate?.regex ?? "",
  }))

  let outcome: MergeOutcome
  try {
    outcome = store.importPatterns(entries)
  } catch (e) {
    parseError.value = (e as Error).message
    return
  }

  // 结果顺序与 targets 一一对应；保留每条原有的展示序号，便于对照
  const replacement: ResultRow[] = outcome.results.map((r, i) => ({
    rid: ++ridSeq,
    index: targets[i].index,
    name: r.name,
    status: r.status,
    message: r.message,
    candidate: r.candidate
      ? { ...r.candidate }
      : r.status === "failed"
        ? { ...(targets[i].candidate as CandidateFields) }
        : undefined,
  }))

  replaceRows(targets, replacement)
  totals.value.failed -= prevFailed
  totals.value.added += outcome.added
  totals.value.updated += outcome.updated
  totals.value.failed += outcome.failed
}

function replaceRows(targets: ResultRow[], replacement: ResultRow[]) {
  const rids = new Set(targets.map((t) => t.rid))
  const next: ResultRow[] = []
  let cursor = 0
  for (const row of rows.value) {
    if (rids.has(row.rid)) {
      if (cursor < replacement.length) {
        next.push(replacement[cursor])
        cursor += 1
      }
    } else {
      next.push(row)
    }
  }
  rows.value = next
}
</script>

<style scoped>
.patterns { max-width: 1000px; }
.page-head { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.25rem; gap: 1rem; }
.page-head h2 { margin: 0 0 0.25rem; }
.page-sub { color: #6b7280; font-size: 0.875rem; }
.head-actions { display: flex; gap: 0.75rem; flex-shrink: 0; }
.pattern-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }
.pattern-card { background: white; border-radius: 12px; padding: 1.25rem; }
.pattern-name { font-weight: 600; margin-bottom: 0.5rem; }
.pattern-severity { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; margin-bottom: 0.75rem; }
.pattern-severity.critical { background: #fee2e2; color: #dc2626; }
.pattern-severity.high { background: #fef3c7; color: #d97706; }
.pattern-severity.medium { background: #dbeafe; color: #1d4ed8; }
.pattern-severity.low { background: #f3f4f6; color: #374151; }
.pattern-desc { color: #6b7280; font-size: 0.875rem; margin-bottom: 0.75rem; }
.pattern-regex { font-size: 0.75rem; word-break: break-all; }
.pattern-regex code { background: #f3f4f6; padding: 0.125rem 0.375rem; border-radius: 4px; font-family: monospace; }

.btn-primary { background: #8b5cf6; color: white; border: none; padding: 0.625rem 1.5rem; border-radius: 8px; cursor: pointer; white-space: nowrap; }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-secondary { background: white; color: #4b5563; border: 1px solid #d1d5db; padding: 0.625rem 1.5rem; border-radius: 8px; cursor: pointer; white-space: nowrap; }
.btn-secondary:hover { border-color: #8b5cf6; color: #8b5cf6; }
.btn-sm { padding: 0.375rem 0.875rem; font-size: 0.8125rem; }

.modal-mask { position: fixed; inset: 0; background: rgba(0,0,0,0.45); display: flex; align-items: center; justify-content: center; z-index: 100; }
.modal { background: white; border-radius: 12px; width: 720px; max-width: calc(100vw - 2rem); max-height: 85vh; display: flex; flex-direction: column; }
.modal-head { display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.25rem; border-bottom: 1px solid #f0f0f0; font-weight: 600; }
.modal-close { border: none; background: none; font-size: 1.5rem; line-height: 1; color: #9ca3af; cursor: pointer; }
.modal-body { padding: 1.25rem; overflow-y: auto; }
.modal-tip { color: #6b7280; font-size: 0.8125rem; margin: 0 0 1rem; line-height: 1.6; }
.modal-tip code { background: #f3f4f6; padding: 0.0625rem 0.375rem; border-radius: 4px; font-family: monospace; }
.file-row { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
.file-input { font-size: 0.8125rem; flex: 1; }
.file-name { color: #6b7280; font-size: 0.8125rem; }
.or-line { color: #6b7280; font-size: 0.8125rem; margin: 0.75rem 0 0.5rem; }
.json-input { width: 100%; font-family: "Fira Code", monospace; font-size: 0.8125rem; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 8px; resize: vertical; box-sizing: border-box; }
.alert-error { margin-top: 0.75rem; padding: 0.625rem 0.875rem; background: #fef2f2; border: 1px solid #fecaca; color: #dc2626; border-radius: 8px; font-size: 0.8125rem; }
.modal-actions { display: flex; justify-content: flex-end; gap: 0.75rem; margin-top: 1.25rem; }

.summary { display: flex; gap: 1rem; margin-bottom: 1rem; font-size: 0.875rem; font-weight: 600; }
.sum-added { color: #059669; }
.sum-updated { color: #1d4ed8; }
.sum-failed { color: #dc2626; }
.result-list { display: flex; flex-direction: column; gap: 0.75rem; }
.result-row { border: 1px solid #e5e7eb; border-radius: 10px; padding: 0.75rem 1rem; }
.result-row.added { border-left: 4px solid #10b981; }
.result-row.updated { border-left: 4px solid #3b82f6; }
.result-row.failed { border-left: 4px solid #ef4444; background: #fffdfd; }
.result-line { display: flex; align-items: center; gap: 0.625rem; }
.result-index { color: #9ca3af; font-size: 0.8125rem; font-family: monospace; }
.result-name { font-weight: 600; font-size: 0.875rem; flex: 1; }
.result-badge { padding: 0.125rem 0.625rem; border-radius: 9999px; font-size: 0.75rem; }
.result-badge.added { background: #d1fae5; color: #065f46; }
.result-badge.updated { background: #dbeafe; color: #1e40af; }
.result-badge.failed { background: #fee2e2; color: #991b1b; }
.btn-retry-one { background: none; border: none; color: #8b5cf6; font-size: 0.75rem; cursor: pointer; padding: 0; }
.result-msg { font-size: 0.8125rem; margin-top: 0.375rem; color: #374151; }
.result-msg.failed { color: #dc2626; }
.fix-form { margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px dashed #e5e7eb; }
.fix-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.625rem 0.875rem; }
.fix-grid label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.75rem; color: #6b7280; }
.fix-grid .fix-full { grid-column: 1 / -1; }
.fix-grid input, .fix-grid select { padding: 0.4rem 0.625rem; border: 1px solid #d1d5db; border-radius: 6px; font-size: 0.8125rem; }
.fix-grid input.mono { font-family: "Fira Code", monospace; }
.fix-actions { margin-top: 0.625rem; display: flex; justify-content: flex-end; }
</style>
