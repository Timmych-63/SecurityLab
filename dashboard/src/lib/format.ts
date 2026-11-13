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
  if (total < 60) return `${total} с`
  const m = Math.floor(total / 60)
  const s = total % 60
  if (m < 60) return s ? `${m} мин ${s} с` : `${m} мин`
  const h = Math.floor(m / 60)
  return `${h} ч ${m % 60} мин`
}

export function sinceNow(iso: string): string {
  return fmtDuration(iso)
}
