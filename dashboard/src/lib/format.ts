/** Форматирование дат и длительностей — только реальные данные. */

const MONTHS = ['янв', 'фев', 'мар', 'апр', 'мая', 'июн', 'июл', 'авг', 'сен', 'окт', 'ноя', 'дек']

export function fmtDateTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const dd = String(d.getDate()).padStart(2, '0')
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  return `${dd} ${MONTHS[d.getMonth()]}, ${hh}:${mm}`
}

export function fmtDuration(fromIso: string, toIso?: string): string {
  const from = Date.parse(fromIso)
  const to = toIso ? Date.parse(toIso) : Date.now()
  if (Number.isNaN(from) || Number.isNaN(to)) return '—'
  return fmtSec(Math.max(0, Math.floor((to - from) / 1000)))
}

export function fmtSec(total: number): string {
  if (!Number.isFinite(total) || total < 0) return '—'
  // Round once in integer milliseconds before splitting: no floating point tails.
  const ms = Math.round(total * 1000)
  if (ms < 60000) return `${ms / 1000} с`
  const m = Math.floor(ms / 60000)
  const s = (ms % 60000) / 1000
  if (m < 60) return s ? `${m} мин ${s} с` : `${m} мин`
  const h = Math.floor(m / 60)
  return `${h} ч ${m % 60} мин`
}

export function sinceNow(iso: string): string {
  return fmtDuration(iso)
}
