/**
 * DTO-слой «ядро SecurityLab S7.4 → UI».
 *
 * Ядро отдаёт summary/receipts со СВОИМИ полями (status, security_verdict,
 * finding_status, error). UI работает с типами Run/Verdict/Finding из types.ts.
 * Этот модуль — единственное место преобразования; правила задокументированы
 * и подлежат сверке с реальными сохранёнными результатами ядра (см. README,
 * раздел «DTO-мэппинг»). Политики и runner не ослабляются.
 *
 * Правила:
 *  1. Raw-поля сохраняются: неизвестные значения не выбрасываются.
 *  2. Неизвестное значение → 'UNKNOWN' + raw в verdictRaw/findingRaw;
 *     UI показывает нейтрально, не зелёным.
 *  3. STOP-причины (BLOCKED/TIMEOUT) — в exec/error, не в verdict.
 *  4. finding_status может быть null («не оценивалось») — null не превращается
 *     ни в успех, ни в отказ.
 *  5. Отсутствующий recheck не превращает проверку в успех (Check.final).
 */

import type { ExecStatus, Finding, Run, Verdict } from './types'

/** Известные security_verdict ядра (по описанию S7.4; сверить с bundle). */
const KNOWN_VERDICTS: ReadonlyArray<Exclude<Verdict, 'UNKNOWN'>> = ['POLICY_VIOLATION_OBSERVED', 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX', 'REPRODUCED', 'NOT_EVALUATED']

/** Известные finding_status ядра (сверить с bundle; null валиден). */
const KNOWN_FINDINGS: ReadonlyArray<Exclude<Finding, null | 'UNKNOWN'>> = [
  'FIXED', 'REPRODUCED',
  'POLICY_VIOLATION_OBSERVED',
  'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX',
  'NEEDS_REVIEW',
  'NOT_EVALUATED',
]

export function mapVerdict(raw: string | null | undefined): { verdict: Verdict; verdictRaw?: string } {
  if (!raw) return { verdict: 'NOT_EVALUATED' }
  const v = raw.trim()
  if ((KNOWN_VERDICTS as ReadonlyArray<string>).includes(v)) return { verdict: v as Verdict }
  // честно: значение не из известного набора — нейтральный статус + исходная строка
  return { verdict: 'UNKNOWN', verdictRaw: v }
}

export function mapFinding(raw: string | null | undefined): { finding: Finding; findingRaw?: string } {
  if (raw === null || raw === undefined) return { finding: null }
  const f = raw.trim()
  if (!f) return { finding: null }
  if ((KNOWN_FINDINGS as ReadonlyArray<string>).includes(f)) return { finding: f as Finding }
  return { finding: 'UNKNOWN', findingRaw: f }
}

/**
 * Соответствие STOP-причин ядра статусу выполнения. Причина из run.error;
 * если ядро отдаёт status="BLOCKED"/"TIMEOUT" в summary, они маппятся сюда.
 */
const EXEC_BY_CORE_STATUS: Record<string, ExecStatus> = {
  pass: 'completed', done: 'completed', stopped: 'cancelled', needs_review: 'blocked', interrupted: 'blocked',
  queued: 'queued',
  running: 'running',
  completed: 'completed',
  ok: 'completed',
  failed: 'failed',
  error: 'failed',
  blocked: 'blocked',
  timeout: 'timeout',
  cancelled: 'cancelled',
  canceled: 'cancelled',
}

export function mapExec(raw: string | null | undefined, error?: string): ExecStatus {
  const key = (raw ?? '').trim().toLowerCase()
  if (key && EXEC_BY_CORE_STATUS[key]) return EXEC_BY_CORE_STATUS[key]
  // STOP-причина может приходить только текстом error
  const err = (error ?? '').toUpperCase()
  if (err.startsWith('BLOCKED')) return 'blocked'
  if (err.startsWith('TIMEOUT')) return 'timeout'
  return 'failed'
}

/**
 * Преобразует raw-запись из сохранённого результата ядра в Run для UI.
 * Поля, которых ядро не отдало, остаются пустыми — UI показывает
 * «не выполнялось / нет данных», а не выдуманное содержимое.
 */
export function mapCoreRun(raw: Record<string, unknown>): Partial<Run> {
  const error = typeof raw.error === 'string' ? raw.error : undefined
  const { verdict, verdictRaw } = mapVerdict((raw.security_verdict ?? raw.verdict) as string | undefined)
  const { finding, findingRaw } = mapFinding(('finding_status' in raw ? raw.finding_status : raw.finding) as string | null | undefined)
  return {
    id: String(raw.run_id ?? raw.id ?? ''),
    exec: mapExec((raw.status as string) ?? (raw.exec as string), error),
    error,
    verdict,
    verdictRaw,
    finding,
    findingRaw,
  }
}
