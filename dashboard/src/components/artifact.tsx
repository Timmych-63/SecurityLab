import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { Artifact } from '../adapter/types'
import { Button, Chip, Overline } from './ui'

/* ============ копирование в буфер обмена ============ */

/** Clipboard API, а при file:// или отказе доступа — резервный путь через textarea. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // падаем в резервный путь ниже
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    ta.remove()
    return ok
  } catch {
    return false
  }
}

/* ============ JSON: форматирование и безопасная подсветка ============ */

/** Токен JSON: ключ (строка перед двоеточием), строка, ключевое слово, число. */
const JSON_TOKEN_RE = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g

/** Подсветка без innerHTML: только span'ы поверх textContent. Крупные файлы — без подсветки. */
const HIGHLIGHT_LIMIT = 262_144

function JsonHighlighted({ text }: { text: string }) {
  const nodes: ReactNode[] = []
  let last = 0
  let i = 0
  let m: RegExpExecArray | null
  const re = new RegExp(JSON_TOKEN_RE.source, 'g')
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index))
    const cls = m[2] !== undefined ? 'text-accent' : m[1] !== undefined ? 'text-ink' : m[3] !== undefined ? 'text-warnink' : 'text-mintink'
    nodes.push(<span key={i++} className={cls}>{m[0]}</span>)
    last = m.index + m[0].length
    if (m[0].length === 0) re.lastIndex++ // защита от зацикливания на пустом совпадении
  }
  if (last < text.length) nodes.push(text.slice(last))
  return <>{nodes}</>
}

/* ============ таблица HTTP-наблюдений стадии ============ */

type Row = Record<string, unknown>

const cellText = (v: unknown): string => (v === null || v === undefined ? '' : String(v))

function ObservationsTable({ items }: { items: Row[] }) {
  return (
    <section>
      <Overline>Наблюдения стадии · {items.length}</Overline>
      <div className="mt-3 overflow-x-auto rounded-field bg-dim p-1.5">
        <table className="tbl min-w-[560px]">
          <thead>
            <tr>
              <th>Актор</th>
              <th>Запрос</th>
              <th>Ожид.</th>
              <th>Факт</th>
              <th>Итог</th>
            </tr>
          </thead>
          <tbody className="bg-surface">
            {items.map((o, i) => {
              const actor = cellText(o.actor)
              const path = cellText(o.path) || cellText(o.route)
              const error = cellText(o.error)
              return (
                <tr key={i}>
                  <td className="font-mono text-[12.5px]">{actor || (o.actor === null ? 'anonymous' : '—')}</td>
                  <td className="font-mono text-[12.5px]">
                    {path || '—'}
                    {error && <span className="mt-0.5 block text-[11px] leading-snug text-dangerink">{error}</span>}
                  </td>
                  <td className="font-mono text-[12.5px]">{cellText(o.expected_status) || '—'}</td>
                  <td className="font-mono text-[12.5px]">{cellText(o.actual_status) || '—'}</td>
                  <td>
                    {o.passed === true ? (
                      <Chip small tone="mint">совпало</Chip>
                    ) : o.passed === false ? (
                      <Chip small tone="danger">расхождение</Chip>
                    ) : (
                      <span className="text-ink3">—</span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </section>
  )
}

/* ============ просмотр артефакта (модалка «Доказательства») ============ */

function fmtSize(bytes: number): string {
  return bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} КБ` : `${bytes} Б`
}

export function ArtifactViewer({ artifact }: { artifact: Artifact }) {
  const raw = artifact.content ?? ''
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current) }, [])

  // JSON форматируется и подсвечивается; логи/патчи/тексты показываются как есть
  let parsed: unknown
  const head = raw.trimStart().slice(0, 1)
  if (head === '{' || head === '[') {
    try { parsed = JSON.parse(raw) } catch { parsed = undefined }
  }
  const isJson = parsed !== undefined
  const pretty = isJson ? `${JSON.stringify(parsed, null, 2)}\n` : null
  const highlight = isJson && raw.length <= HIGHLIGHT_LIMIT
  const lineCount = pretty ? pretty.split('\n').length - 1 : 0

  // для стадий http_NN: сводная таблица наблюдений над сырым JSON
  let observations: Row[] | null = null
  if (isJson && parsed && typeof parsed === 'object') {
    const obs: unknown = (parsed as Row).observations
    if (Array.isArray(obs)) {
      const items = obs.filter((it: unknown): it is Row => it !== null && typeof it === 'object')
      if (items.length > 0) observations = items
    }
  }

  const onCopy = async () => {
    const ok = await copyText(raw)
    if (ok) {
      setCopied(true)
      if (timer.current) clearTimeout(timer.current)
      timer.current = setTimeout(() => setCopied(false), 2000)
    }
    return ok
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <div className="flex flex-wrap items-center gap-2.5">
          <Chip small mono>{isJson ? 'JSON' : artifact.kind.toUpperCase()}</Chip>
          {isJson && (
            <span className="text-[12px] text-ink3">
              отформатировано · {lineCount} строк · {fmtSize(raw.length)}
            </span>
          )}
        </div>
        <Button variant="ghost" icon="copy" onClick={() => void onCopy()} disabled={raw.length === 0}>
          {copied ? 'Скопировано' : 'Скопировать'}
        </Button>
      </div>

      {observations && <ObservationsTable items={observations} />}

      <pre className="untrusted max-h-[55vh] overflow-y-auto" aria-label="Содержимое артефакта">
        {pretty !== null ? (highlight ? <JsonHighlighted text={pretty} /> : pretty) : raw}
      </pre>
    </div>
  )
}
