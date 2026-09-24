<template>
  <div class="patterns">
    <div class="patterns-header">
      <h2>漏洞模式库</h2>
      <div class="actions">
        <button class="btn" @click="exportPatterns">导出规则</button>
        <button class="btn btn-primary" @click="triggerFileSelect">导入规则</button>
        <input ref="fileInput" type="file" accept=".json,application/json" class="file-input" @change="onFileChange" />
      </div>
    </div>

    <div v-if="importError" class="import-error">{{ importError }}</div>

    <div v-if="importResult" class="import-result">
      <div class="import-summary">
        导入结果：共 {{ importResult.total }} 条，
        <span class="ok">成功 {{ importResult.imported }} 条</span>，
        <span class="bad">失败 {{ importResult.failed }} 条</span>
      </div>
      <div v-for="r in importResult.results" :key="r.index" class="result-item" :class="r.status">
        <span class="result-index">#{{ r.index + 1 }}</span>
        <span class="result-name">{{ r.name || "(未命名)" }}</span>
        <span class="result-status">{{ r.status === "success" ? (r.action === "updated" ? "已更新" : "已新增") : "失败" }}</span>
        <span class="result-detail">{{ r.status === "success" ? r.message : r.reason }}</span>
      </div>
      <div v-if="retryText !== null" class="retry-section">
        <h4>失败条目（修正后可重新导入）</h4>
        <textarea v-model="retryText" class="retry-editor" rows="8" spellcheck="false"></textarea>
        <button class="btn btn-primary" :disabled="importing" @click="retryImport">重新导入修正条目</button>
      </div>
    </div>

    <div class="pattern-grid">
      <div v-for="p in patterns" :key="p.name" class="pattern-card">
        <div class="pattern-name">{{ p.name }}</div>
        <div class="pattern-severity" :class="p.severity">{{ p.severity }}</div>
        <div class="pattern-desc">{{ p.description }}</div>
        <div class="pattern-regex">正则: <code>{{ p.pattern }}</code></div>
        <div class="pattern-suggest">建议: {{ p.suggestion }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue"
import axios from "axios"
import { storeToRefs } from "pinia"
import { useAuditStore } from "@/store"
import type { ImportResult } from "@/types"

const store = useAuditStore()
const { patterns } = storeToRefs(store)

const fileInput = ref<HTMLInputElement | null>(null)
const importing = ref(false)
const importError = ref("")
const importResult = ref<ImportResult | null>(null)
const retryText = ref<string | null>(null)

onMounted(() => {
  store.fetchPatterns()
})

async function exportPatterns() {
  const res = await axios.get("/api/patterns/export", { responseType: "blob" })
  const url = URL.createObjectURL(res.data)
  const a = document.createElement("a")
  a.href = url
  a.download = "patterns.json"
  a.click()
  URL.revokeObjectURL(url)
}

function triggerFileSelect() {
  fileInput.value?.click()
}

function onFileChange(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  const reader = new FileReader()
  reader.onload = () => doImport(String(reader.result ?? ""))
  reader.onerror = () => { importError.value = "文件读取失败" }
  reader.readAsText(file)
  input.value = ""
}

function collectFailedItems(items: unknown[], result: ImportResult): unknown[] {
  return result.results.filter(r => r.status === "failed").map(r => items[r.index])
}

async function doImport(text: string) {
  importError.value = ""
  let payload: any
  try {
    payload = JSON.parse(text)
  } catch {
    importError.value = "文件内容不是合法的 JSON，请修正后重新导入"
    return
  }
  const items = Array.isArray(payload) ? payload : payload?.patterns
  if (!Array.isArray(items)) {
    importError.value = "文件内容必须是规则数组，或包含 patterns 数组字段的对象"
    return
  }

  importing.value = true
  try {
    const result = await store.importPatterns(items)
    importResult.value = result
    const failedItems = collectFailedItems(items, result)
    retryText.value = failedItems.length > 0 ? JSON.stringify(failedItems, null, 2) : null
  } catch (err: any) {
    importError.value = err?.response?.data?.detail || "导入失败，请确认后端服务已启动"
  } finally {
    importing.value = false
  }
}

function retryImport() {
  if (retryText.value !== null) doImport(retryText.value)
}
</script>

<style scoped>
.patterns { max-width: 1000px; }
.patterns-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.actions { display: flex; gap: 0.75rem; }
.btn { background: #e5e7eb; border: none; padding: 0.5rem 1.25rem; border-radius: 8px; cursor: pointer; font-size: 0.875rem; }
.btn-primary { background: #8b5cf6; color: white; }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.file-input { display: none; }
.import-error { background: #fee2e2; color: #991b1b; border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 1rem; }
.import-result { background: white; border-radius: 12px; padding: 1.25rem; margin-bottom: 1.5rem; }
.import-summary { font-weight: 600; margin-bottom: 0.75rem; }
.import-summary .ok { color: #059669; }
.import-summary .bad { color: #dc2626; }
.result-item { display: flex; gap: 0.75rem; align-items: baseline; padding: 0.5rem 0; border-bottom: 1px solid #f3f4f6; font-size: 0.875rem; }
.result-item:last-of-type { border-bottom: none; }
.result-index { color: #9ca3af; min-width: 2.5rem; }
.result-name { font-weight: 600; min-width: 10rem; }
.result-status { padding: 0.125rem 0.625rem; border-radius: 9999px; font-size: 0.75rem; white-space: nowrap; }
.result-item.success .result-status { background: #d1fae5; color: #065f46; }
.result-item.failed .result-status { background: #fee2e2; color: #991b1b; }
.result-detail { color: #6b7280; }
.result-item.failed .result-detail { color: #dc2626; }
.retry-section { margin-top: 1rem; }
.retry-section h4 { margin-bottom: 0.5rem; font-size: 0.875rem; }
.retry-editor { width: 100%; font-family: monospace; font-size: 0.8rem; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 8px; margin-bottom: 0.75rem; resize: vertical; }
.pattern-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }
.pattern-card { background: white; border-radius: 12px; padding: 1.25rem; }
.pattern-name { font-weight: 600; margin-bottom: 0.5rem; }
.pattern-severity { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; margin-bottom: 0.75rem; }
.pattern-severity.critical { background: #fee2e2; color: #dc2626; }
.pattern-severity.high { background: #fef3c7; color: #d97706; }
.pattern-severity.medium { background: #dbeafe; color: #1d4ed8; }
.pattern-severity.low { background: #f3f4f6; color: #4b5563; }
.pattern-desc { color: #6b7280; font-size: 0.875rem; margin-bottom: 0.75rem; }
.pattern-regex { font-size: 0.75rem; margin-bottom: 0.5rem; word-break: break-all; }
.pattern-regex code { background: #f3f4f6; padding: 0.125rem 0.375rem; border-radius: 4px; font-family: monospace; }
.pattern-suggest { font-size: 0.75rem; color: #6b7280; }
</style>
