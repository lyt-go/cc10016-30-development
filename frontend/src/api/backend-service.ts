import { request } from './client'
import { moduleMeta } from '@/data/modules'
import type { ActionResult, EntryRow, OverviewResult, PageResult } from '@/data/types'

export { moduleMeta }

export async function listEntries(
  key: string,
  filters: Record<string, string> = {},
): Promise<PageResult> {
  const query = new URLSearchParams(filters).toString()
  const response = await request(`/api/${key}?${query}`)
  if (!response.ok) throw new Error('业务数据读取失败')
  return await response.json()
}

export async function createEntry(
  key: string,
  values: Record<string, string>,
): Promise<ActionResult> {
  const response = await request(`/api/${key}`, {
    method: 'POST',
    body: JSON.stringify({ values }),
  })
  return await response.json()
}

export async function runAction(
  key: string,
  id: number,
  action: string,
): Promise<ActionResult> {
  const response = await request(`/api/${key}/${id}/actions`, {
    method: 'POST',
    body: JSON.stringify({ action }),
  })
  return await response.json()
}

export async function downloadEntries(
  key: string,
  filters: Record<string, string> = {},
): Promise<void> {
  const query = new URLSearchParams(filters).toString()
  const response = await request(`/api/${key}/export?${query}`)
  if (!response.ok) throw new Error('业务数据导出失败')
  const url = URL.createObjectURL(await response.blob())
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `${key}.csv`
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}

// 调查交割清单：建立、导出、登记正式证据、补传更正、重核收、回查。
export type HandoverRecord = {
  id: number
  交割编号: string
  状态: string
  交接人: string
  接收人: string
  巡护日志: number[]
  日志摘要: Record<string, string | number>[]
  有效快照: Record<string, string | number>[]
  后续勘查范围: string
  缺件: string[]
  正式证据: boolean
  有效: boolean
  版本: number
  导出状态: string
  更正关联: string[]
  重投记录: Record<string, string>[]
  复核次数: number
  待核收更正?: number
  备注: string
}

export type HandoverBasis = {
  交割编号: string
  状态: string
  版本: number
  有效: boolean
  原快照: Record<string, string | number>[]
  有效快照: Record<string, string | number>[]
  导出记录: { 导出版本: number; 导出时间: string; 操作人: string; 快照: Record<string, string | number>[] }[]
  更正: Record<string, string | number>[]
  复核次数: number
  签发引用: Record<string, string | number>[]
}

async function jsonOrThrow<T>(response: Response, fallback: string): Promise<T> {
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    const detail = payload?.detail
    const message = typeof detail === 'string' ? detail : detail?.message
    throw new Error(message || fallback)
  }
  return payload as T
}

export async function listHandovers(): Promise<{ items: HandoverRecord[]; total: number }> {
  const response = await request('/api/handover')
  return jsonOrThrow(response, '交割清单读取失败')
}

export async function createHandover(payload: {
  patrol_ids: number[]
  mode: 'issue' | 'missing'
  operator: string
}): Promise<{ ok: boolean; message: string; deduplicated?: boolean; handover: HandoverRecord }> {
  const response = await request('/api/handover', { method: 'POST', body: JSON.stringify(payload) })
  return jsonOrThrow(response, '交割清单建立失败')
}

export async function downloadHandover(handoverNo: string): Promise<void> {
  const response = await request(`/api/handover/${encodeURIComponent(handoverNo)}/export`)
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}))
    throw new Error(typeof payload?.detail === 'string' ? payload.detail : '交割包导出失败')
  }
  const url = URL.createObjectURL(await response.blob())
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `${handoverNo}.csv`
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}

export async function registerHandoverEvidence(handoverNo: string): Promise<{ ok: boolean; message: string }> {
  const response = await request(`/api/handover/${encodeURIComponent(handoverNo)}/register-evidence`, {
    method: 'POST',
    body: JSON.stringify({ operator: '夜班' }),
  })
  return jsonOrThrow(response, '正式证据登记失败')
}

export async function addHandoverCorrection(
  handoverNo: string,
  payload: { patrol_id: number; threat_position: string; coordinate: string; source: string },
): Promise<{ ok: boolean; message: string; arrived_after_export: boolean; correction: Record<string, string | number> }> {
  const response = await request(`/api/handover/${encodeURIComponent(handoverNo)}/corrections`, {
    method: 'POST',
    body: JSON.stringify(payload),
  })
  return jsonOrThrow(response, '更正登记失败')
}

export async function reacceptHandover(
  handoverNo: string,
  correctionId: number,
): Promise<{ ok: boolean; message: string }> {
  const response = await request(`/api/handover/${encodeURIComponent(handoverNo)}/reaccept`, {
    method: 'POST',
    body: JSON.stringify({ correction_id: correctionId }),
  })
  return jsonOrThrow(response, '重核收失败')
}

export async function loadHandoverBasis(handoverNo: string): Promise<HandoverBasis> {
  const response = await request(`/api/handover/${encodeURIComponent(handoverNo)}/basis`)
  return jsonOrThrow(response, '复核依据读取失败')
}

export async function loadHandoverTodos(): Promise<{ items: Record<string, string | number>[] }> {
  const response = await request('/api/handover/todos')
  return jsonOrThrow(response, '补勘待办读取失败')
}

export async function runActionWithParams(
  key: string,
  id: number,
  action: string,
  params: Record<string, unknown>,
): Promise<ActionResult & { entry?: Record<string, unknown> }> {
  const response = await request(`/api/${key}/${id}/actions`, {
    method: 'POST',
    body: JSON.stringify({ action, params }),
  })
  return jsonOrThrow(response, '操作失败')
}

export async function loadOverview(): Promise<OverviewResult> {
  const response = await request('/api/overview')
  if (!response.ok) throw new Error('运营概览读取失败')
  return await response.json()
}

// 跨模块数据流 API
export async function buildMigrationFromLocations(trackIndividual: string): Promise<any> {
  const response = await request(`/api/cross/migration/from-locations?track_individual=${encodeURIComponent(trackIndividual)}`)
  if (!response.ok) throw new Error('迁徙路线生成失败')
  return await response.json()
}

export async function analyzeBehavior(speciesName: string): Promise<any> {
  const response = await request(`/api/cross/analysis/from-behavior?species_name=${encodeURIComponent(speciesName)}`)
  if (!response.ok) throw new Error('行为分析失败')
  return await response.json()
}

export async function triggerThreatFromPatrol(patrolId: number): Promise<any> {
  const response = await request(`/api/cross/threat/from-patrol/${patrolId}`, { method: 'POST' })
  if (!response.ok) throw new Error('威胁评估触发失败')
  return await response.json()
}

export async function updateSpeciesFromCensus(censusId: number): Promise<any> {
  const response = await request(`/api/cross/species/from-census/${censusId}`, { method: 'POST' })
  if (!response.ok) throw new Error('普查同步失败')
  return await response.json()
}

export async function linkRescueToSpecies(rescueId: number): Promise<any> {
  const response = await request(`/api/cross/species/from-rescue/${rescueId}`, { method: 'POST' })
  if (!response.ok) throw new Error('救护关联失败')
  return await response.json()
}

export async function checkDeviceLocations(deviceCode: string): Promise<any> {
  const response = await request(`/api/cross/locations/from-device?device_code=${encodeURIComponent(deviceCode)}`)
  if (!response.ok) throw new Error('设备信号检查失败')
  return await response.json()
}

export async function createResearchFromGenetic(sampleId: number): Promise<any> {
  const response = await request(`/api/cross/research/from-genetic/${sampleId}`, { method: 'POST' })
  if (!response.ok) throw new Error('研究成果生成失败')
  return await response.json()
}

export async function buildAnnualSummary(year: number): Promise<any> {
  const response = await request(`/api/cross/annual-summary?year=${year}`)
  if (!response.ok) throw new Error('年度总结生成失败')
  return await response.json()
}

export async function loadDataQuality(): Promise<any> {
  const response = await request('/api/cross/overview/data-quality')
  if (!response.ok) throw new Error('数据质量概览读取失败')
  return await response.json()
}
