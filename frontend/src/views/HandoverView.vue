<template>
  <section class="page" data-module="handover">
    <header class="page-head">
      <div>
        <h2>调查交割清单</h2>
        <p class="page-desc">
          巡护日志经审阅后才能成为签发证据；草稿只能登记缺件。导出包按导出时刻的快照冻结，
          迟到的更正单独登记，由评估员决定从已交割材料继续或取更正后重核收。
        </p>
      </div>
    </header>

    <p v-if="message" class="hint" data-testid="handover-message">{{ message }}</p>
    <p v-if="errorMessage" class="error-text" data-testid="handover-error">{{ errorMessage }}</p>

    <div class="stat-row">
      <article class="stat-card">
        <span class="stat-label">交割总数</span>
        <strong class="stat-value">{{ handovers.length }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">有效交割</span>
        <strong class="stat-value">{{ handovers.filter((h) => h.有效).length }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">待核收更正</span>
        <strong class="stat-value">{{ pendingCorrections }}</strong>
      </article>
    </div>

    <section class="panel">
      <h3>从已审阅巡护日志发交割</h3>
      <table class="data-table">
        <thead>
          <tr>
            <th>选择</th><th>id</th><th>巡护路线</th><th>威胁类型</th>
            <th>威胁位置</th><th>坐标描述</th><th>证据来源</th><th>状态</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in patrolRows" :key="row.id" :data-testid="`patrol-${row.id}`" :data-status="String(row.status)">
            <td><input v-model="selected" type="checkbox" :value="Number(row.id)" :data-testid="`select-patrol-${row.id}`" /></td>
            <td>{{ row.id }}</td>
            <td>{{ row.巡护路线 }}</td>
            <td>{{ row.威胁类型 }}</td>
            <td>{{ row.威胁位置 }}</td>
            <td>{{ row.坐标描述 }}</td>
            <td>{{ row.证据来源 }}</td>
            <td>{{ row.status }}</td>
          </tr>
        </tbody>
      </table>
      <div class="page-actions">
        <button class="btn primary" data-testid="issue-handover" type="button" :disabled="!selected.length" @click="issue('issue')">
          正式发交割
        </button>
        <button class="btn" data-testid="missing-handover" type="button" :disabled="!selected.length" @click="issue('missing')">
          缺件登记
        </button>
      </div>
    </section>

    <section v-for="record in handovers" :key="record.交割编号" class="panel" :data-testid="`handover-${record.交割编号}`">
      <h3>
        {{ record.交割编号 }}
        <span class="tag">{{ record.状态 }}</span>
        <span class="tag">v{{ record.版本 }}</span>
        <span v-if="record.正式证据" class="tag ok">正式证据</span>
      </h3>
      <dl class="detail-grid">
        <div><dt>巡护日志</dt><dd>{{ record.巡护日志.join('、') }}</dd></div>
        <div><dt>交接人 → 接收人</dt><dd>{{ record.交接人 }} → {{ record.接收人 }}</dd></div>
        <div><dt>后续勘查范围</dt><dd>{{ record.后续勘查范围 }}</dd></div>
        <div><dt>复核次数</dt><dd>{{ record.复核次数 }}</dd></div>
        <div><dt>导出状态</dt><dd>{{ record.导出状态 }}</dd></div>
        <div><dt>更正关联</dt><dd>{{ record.更正关联.length ? record.更正关联.join('、') : '—' }}</dd></div>
        <div v-if="record.缺件.length" class="wide"><dt>缺件</dt><dd>{{ record.缺件.join('；') }}</dd></div>
      </dl>

      <table class="data-table compact">
        <thead>
          <tr><th>日志</th><th>威胁位置</th><th>坐标描述</th><th>证据来源</th></tr>
        </thead>
        <tbody>
          <tr v-for="item in record.有效快照" :key="`${record.交割编号}-${item.id}`">
            <td>#{{ item.id }}</td><td>{{ item.威胁位置 }}</td>
            <td>{{ item.坐标描述 }}</td><td>{{ item.证据来源 }}</td>
          </tr>
        </tbody>
      </table>

      <div class="page-actions">
        <button class="btn" :data-testid="`download-${record.交割编号}`" type="button" @click="download(record.交割编号)">
          下载交割包
        </button>
        <button
          class="btn"
          :data-testid="`register-${record.交割编号}`"
          type="button"
          :disabled="!record.有效 || record.正式证据"
          @click="register(record.交割编号)"
        >
          登记为正式证据
        </button>
        <button class="btn ghost" :data-testid="`basis-${record.交割编号}`" type="button" @click="showBasis(record.交割编号)">
          回查复核依据
        </button>
      </div>

      <form class="inline-form" @submit.prevent="submitCorrection(record.交割编号)">
        <label>
          <span>日志</span>
          <input v-model.number="correctionForm[record.交割编号].patrol_id" type="number" :data-testid="`corr-patrol-${record.交割编号}`" />
        </label>
        <label>
          <span>更正后威胁位置</span>
          <input v-model="correctionForm[record.交割编号].threat_position" :data-testid="`corr-position-${record.交割编号}`" />
        </label>
        <label>
          <span>更正后坐标</span>
          <input v-model="correctionForm[record.交割编号].coordinate" :data-testid="`corr-coord-${record.交割编号}`" />
        </label>
        <label>
          <span>补传来源</span>
          <input v-model="correctionForm[record.交割编号].source" :data-testid="`corr-source-${record.交割编号}`" />
        </label>
        <button class="btn" :data-testid="`submit-correction-${record.交割编号}`" type="submit">补传更正</button>
      </form>
    </section>

    <section v-if="basis" class="panel" data-testid="basis-panel">
      <h3>复核依据回查 · {{ basis.交割编号 }} v{{ basis.版本 }}</h3>
      <table class="data-table compact">
        <thead><tr><th>快照</th><th>日志</th><th>威胁位置</th><th>坐标描述</th><th>证据来源</th></tr></thead>
        <tbody>
          <tr v-for="item in basis.原快照" :key="`o-${item.id}`">
            <td>原快照</td><td>#{{ item.id }}</td><td>{{ item.威胁位置 }}</td><td>{{ item.坐标描述 }}</td><td>{{ item.证据来源 }}</td>
          </tr>
          <tr v-for="item in basis.有效快照" :key="`e-${item.id}`">
            <td>有效快照</td><td>#{{ item.id }}</td><td>{{ item.威胁位置 }}</td><td>{{ item.坐标描述 }}</td><td>{{ item.证据来源 }}</td>
          </tr>
        </tbody>
      </table>
      <h4>导出留档（对外材料按交割编号取回）</h4>
      <table v-if="basis.导出记录.length" class="data-table compact">
        <thead><tr><th>导出版本</th><th>导出时间</th><th>日志</th><th>威胁位置</th><th>坐标描述</th><th>证据来源</th></tr></thead>
        <tbody>
          <template v-for="exportRecord in basis.导出记录" :key="`${exportRecord.导出版本}-${exportRecord.导出时间}`">
            <tr v-for="item in exportRecord.快照" :key="`x-${exportRecord.导出版本}-${item.id}`">
              <td>v{{ exportRecord.导出版本 }}</td><td>{{ exportRecord.导出时间 }}</td>
              <td>#{{ item.id }}</td><td>{{ item.威胁位置 }}</td>
              <td>{{ item.坐标描述 }}</td><td>{{ item.证据来源 }}</td>
            </tr>
          </template>
        </tbody>
      </table>
      <p v-else class="hint">尚未导出。</p>
      <h4>更正</h4>
      <table v-if="basis.更正.length" class="data-table compact">
        <thead><tr><th>编号</th><th>日志</th><th>原位置</th><th>新位置</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="item in basis.更正" :key="String(item.更正编号)">
            <td>{{ item.更正编号 }}</td><td>#{{ item.巡护日志 }}</td>
            <td>{{ item.原威胁位置 }}</td><td>{{ item.新威胁位置 }}</td><td>{{ item.状态 }}</td>
            <td>
              <button class="link" :data-testid="`reaccept-${item.更正编号}`" type="button" @click="reaccept(String(basis!.交割编号), Number(item.id))">
                取更正后重核收
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="hint">暂无更正，可直接从已交割材料继续。</p>
      <h4>签发引用</h4>
      <table v-if="basis.签发引用.length" class="data-table compact">
        <thead><tr><th>评估</th><th>状态</th><th>有效威胁位置</th><th>复核依据</th></tr></thead>
        <tbody>
          <tr v-for="item in basis.签发引用" :key="String(item.评估id)">
            <td>#{{ item.评估id }} {{ item.评估对象 }}</td><td>{{ item.状态 }}</td>
            <td>{{ item.有效威胁位置 }}</td><td>{{ item.复核依据 }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="hint">该交割尚未被任何签发引用。</p>
    </section>

    <section class="panel">
      <h3>现场补勘待办</h3>
      <table class="data-table compact">
        <thead><tr><th>待办</th><th>评估</th><th>交割</th><th>勘查段</th><th>坐标</th><th>状态</th></tr></thead>
        <tbody>
          <tr v-for="todo in todos" :key="String(todo.待办编号)" :data-testid="`todo-${todo.待办编号}`">
            <td>{{ todo.待办编号 }}</td><td>#{{ todo.评估id }}</td><td>{{ todo.交割编号 }}</td>
            <td>{{ todo.勘查段 }}</td><td>{{ todo.坐标描述 }}</td><td>{{ todo.状态 }}</td>
          </tr>
          <tr v-if="!todos.length"><td colspan="6" class="empty-state">暂无补勘待办</td></tr>
        </tbody>
      </table>
    </section>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'

import {
  addHandoverCorrection,
  createHandover,
  downloadHandover,
  listEntries,
  listHandovers,
  loadHandoverBasis,
  loadHandoverTodos,
  reacceptHandover,
  registerHandoverEvidence,
  type HandoverBasis,
  type HandoverRecord,
} from '@/api/backend-service'
import type { EntryRow } from '@/data/types'

const patrolRows = ref<EntryRow[]>([])
const handovers = ref<HandoverRecord[]>([])
const todos = ref<Record<string, string | number>[]>([])
const basis = ref<HandoverBasis | null>(null)
const selected = ref<number[]>([])
const message = ref('')
const errorMessage = ref('')
const correctionForm = reactive<Record<string, { patrol_id: number; threat_position: string; coordinate: string; source: string }>>({})

const pendingCorrections = computed(() =>
  handovers.value.reduce((sum, record) => sum + Number(record.待核收更正 ?? 0), 0),
)

function formFor(handoverNo: string) {
  if (!correctionForm[handoverNo]) {
    correctionForm[handoverNo] = { patrol_id: 0, threat_position: '', coordinate: '', source: '' }
  }
  return correctionForm[handoverNo]
}

async function reload() {
  const [patrols, records, todoPayload] = await Promise.all([
    listEntries('patrol_record'),
    listHandovers(),
    loadHandoverTodos(),
  ])
  patrolRows.value = patrols.items
  handovers.value = records.items
  todos.value = todoPayload.items
  for (const record of records.items) {
    formFor(record.交割编号)
    if (formFor(record.交割编号).patrol_id === 0 && record.巡护日志.length) {
      formFor(record.交割编号).patrol_id = record.巡护日志[0]
    }
  }
}

async function issue(mode: 'issue' | 'missing') {
  await guard(async () => {
    const result = await createHandover({ patrol_ids: selected.value, mode, operator: '巡护组' })
    message.value = result.message
    selected.value = []
    await reload()
  })
}

async function download(handoverNo: string) {
  await guard(async () => {
    await downloadHandover(handoverNo)
    message.value = `已下载 ${handoverNo} 交割包，导出内容按下载时刻冻结`
    await reload()
  })
}

async function register(handoverNo: string) {
  await guard(async () => {
    const result = await registerHandoverEvidence(handoverNo)
    message.value = result.message
    await reload()
  })
}

async function submitCorrection(handoverNo: string) {
  await guard(async () => {
    const form = formFor(handoverNo)
    const result = await addHandoverCorrection(handoverNo, {
      patrol_id: Number(form.patrol_id),
      threat_position: form.threat_position,
      coordinate: form.coordinate,
      source: form.source,
    })
    message.value = result.message + (result.arrived_after_export ? '（到达时导出已开始，未进入已下载的包）' : '')
    await reload()
    await showBasis(handoverNo)
  })
}

async function showBasis(handoverNo: string) {
  await guard(async () => {
    basis.value = await loadHandoverBasis(handoverNo)
  })
}

async function reaccept(handoverNo: string, correctionId: number) {
  await guard(async () => {
    const result = await reacceptHandover(handoverNo, correctionId)
    message.value = result.message
    await reload()
    await showBasis(handoverNo)
  })
}

async function guard(task: () => Promise<void>) {
  errorMessage.value = ''
  try {
    await task()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '操作失败'
  }
}

onMounted(() => guard(reload))
</script>
