import { useEffect, useId, useRef } from 'react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import type { ExecStatus, Finding, PreflightState, Verdict } from '../adapter/types'

/* ============ иконки: тонкие штриховые SVG, никаких эмодзи ============ */

const S = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const }

export function Icon({ name, size = 16 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    arrow: <path d="M5 12h14m-6-6 6 6-6 6" {...S} />,
    plus: <path d="M12 5v14M5 12h14" {...S} />,
    play: <path d="M8 6.5v11l9-5.5-9-5.5Z" {...S} />,
    stop: <rect x="8" y="8" width="8" height="8" rx="1.5" {...S} />,
    download: <path d="M12 5v10m0 0 4-4m-4 4-4-4M5 19h14" {...S} />,
    copy: <><rect x="9" y="9" width="10" height="10" rx="2" {...S} /><path d="M5 15V6a1.5 1.5 0 0 1 1.5-1.5H15" {...S} /></>,
    chevron: <path d="m9 6 6 6-6 6" {...S} />,
    chevronDown: <path d="m6 9 6 6 6-6" {...S} />,
    check: <path d="m5 13 4 4L19 7" {...S} />,
    cross: <path d="M6 6l12 12M18 6 6 18" {...S} />,
    alert: <><path d="M12 4 21 19H3L12 4Z" {...S} /><path d="M12 10v4m0 3v.5" {...S} /></>,
    clock: <><circle cx="12" cy="12" r="8" {...S} /><path d="M12 8v4l3 2" {...S} /></>,
    file: <><path d="M7 3h7l4 4v14H7V3Z" {...S} /><path d="M14 3v4h4" {...S} /></>,
    box: <><path d="M12 3 21 8v8l-9 5-9-5V8l9-5Z" {...S} /><path d="M12 12 21 8m-9 4v9m0-9L3 8" {...S} /></>,
    gear: <><circle cx="12" cy="12" r="3" {...S} /><path d="M12 5V3m0 18v-2m7-7h2M3 12h2m12.5-5.5 1.4-1.4M5.1 18.9l1.4-1.4m0-11L5.1 5.1m13.8 13.8-1.4-1.4" {...S} /></>,
    plug: <path d="M9 7V4m6 3V4M7 7h10v4a5 5 0 0 1-10 0V7Zm5 9v4" {...S} />,
    sun: <><circle cx="12" cy="12" r="4" {...S} /><path d="M12 3v2m0 14v2M3 12h2m14 0h2M5.6 5.6l1.4 1.4m10 10 1.4 1.4m0-12.8-1.4 1.4m-10 10L5.6 18.4" {...S} /></>,
    moon: <path d="M20 14A8 8 0 0 1 10 4a8 8 0 1 0 10 10Z" {...S} />,
    menu: <path d="M4 7h16M4 12h16M4 17h16" {...S} />,
    branch: <><circle cx="7" cy="6" r="2" {...S} /><circle cx="7" cy="18" r="2" {...S} /><circle cx="17" cy="6" r="2" {...S} /><path d="M7 8v8m0-8a10 10 0 0 1 8-2" {...S} /></>,
    eye: <><path d="M2.5 12S6 6.5 12 6.5 21.5 12 21.5 12 18 17.5 12 17.5 2.5 12 2.5 12Z" {...S} /><circle cx="12" cy="12" r="2.5" {...S} /></>,
    search: <><circle cx="11" cy="11" r="7" {...S} /><path d="m20 20-3.5-3.5" {...S} /></>,
    layers: <><path d="m12 3 9 5-9 5-9-5 9-5Z" {...S} /><path d="m3 13 9 5 9-5" {...S} /></>,
    trash: <><path d="M4.5 7h15" {...S} /><path d="M9.5 7V5.5A1.5 1.5 0 0 1 11 4h2a1.5 1.5 0 0 1 1.5 1.5V7" {...S} /><path d="M6.5 7l1 12.5A1.5 1.5 0 0 0 9 21h6a1.5 1.5 0 0 0 1.5-1.5L17.5 7" {...S} /><path d="M10 11v6m4-6v6" {...S} /></>,
  }
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      {paths[name]}
    </svg>
  )
}

/* ============ кнопки: скруглённые поля, чернильная заливка основной ============ */

type BtnVariant = 'primary' | 'secondary' | 'ghost' | 'danger'

interface BtnProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: BtnVariant
  icon?: string
}

const btnBase =
  'pressable inline-flex select-none items-center gap-2 rounded-field px-4 font-semibold tracking-[-0.01em] transition-all disabled:pointer-events-none disabled:opacity-40 h-10 text-[13.5px]'

const btnStyles: Record<BtnVariant, string> = {
  primary: 'bg-ink text-page hover:shadow-[0_12px_22px_-10px_var(--shadow-strong)]',
  secondary: 'bg-surface text-ink shadow-[inset_0_0_0_1px_var(--line2)] hover:shadow-[inset_0_0_0_1px_var(--ink3)]',
  ghost: 'text-accent hover:bg-accentsoft',
  danger: 'bg-surface text-dangerink shadow-[inset_0_0_0_1px_var(--line2)] hover:shadow-[inset_0_0_0_1px_var(--danger)]',
}

export function Button({ variant = 'secondary', icon, children, className = '', ...rest }: BtnProps) {
  return (
    <button type="button" className={`${btnBase} ${btnStyles[variant]} ${className}`} {...rest}>
      {icon && <Icon name={icon} />}
      {children}
    </button>
  )
}

/* ============ статусы: цвет всегда сопровождается текстом ============ */

export const execLabel: Record<ExecStatus, string> = {
  queued: 'в очереди',
  running: 'выполняется',
  completed: 'завершён',
  failed: 'ошибка выполнения',
  blocked: 'проверка остановлена',
  timeout: 'превышено время ожидания',
  cancelled: 'отменён',
}

/** Метки значений ядра. Неизвестные значения показываются нейтрально с raw-строкой (#7). */
export function verdictLabel(v: Verdict, raw?: string): string {
  if (v === 'POLICY_VIOLATION_OBSERVED') return 'нарушение политики наблюдается'
  if (v === 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX') return 'нарушение не наблюдается на проверенном исправлении'
  if (v === 'REPRODUCED') return 'нарушение воспроизведено'
  if (v === 'NOT_EVALUATED') return 'не оценивалось'
  return `неизвестный вердикт${raw ? `: ${raw}` : ''} · UNKNOWN`
}

export function findingLabel(v: Finding, raw?: string): string {
  if (v === 'FIXED') return 'исправление прошло независимую проверку'
  if (v === 'REPRODUCED') return 'нарушение воспроизведено'
  if (v === 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX') return 'нарушение не наблюдается на проверенном исправлении'
  if (v === 'POLICY_VIOLATION_OBSERVED') return 'нарушение наблюдается на исправлении'
  if (v === 'NEEDS_REVIEW') return 'нужно решение оператора'
  if (v === 'NOT_EVALUATED') return 'не оценивалось'
  if (v === null) return 'оценка не выполнялась'
  return `неизвестный статус${raw ? `: ${raw}` : ''} · UNKNOWN`
}

type Tone = 'mint' | 'danger' | 'warn' | 'accent' | 'smoke'

const toneClasses: Record<Tone, string> = {
  mint: 'bg-mintsoft text-mintink',
  danger: 'bg-dangersoft text-dangerink',
  warn: 'bg-warnsoft text-warnink',
  accent: 'bg-accentsoft text-accent',
  smoke: 'bg-smokesoft text-smokeink',
}

/** lucian-чип: мягкая подложка, жирный текст, точка цвета статуса */
export function Chip({ tone = 'smoke', children, small = false, mono = false }: { tone?: Tone; children: ReactNode; small?: boolean; mono?: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-chip font-bold leading-tight tracking-[-0.005em] ${toneClasses[tone]} ${
        small ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-[12px]'
      }`}
    >
      <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-current" aria-hidden="true" />
      <span className={mono ? 'font-mono font-semibold tracking-normal' : ''}>{children}</span>
    </span>
  )
}

export function ExecChip({ v, small = false }: { v: ExecStatus; small?: boolean }) {
  const tone: Tone = v === 'running' ? 'accent' : v === 'timeout' ? 'warn' : v === 'failed' || v === 'blocked' ? 'danger' : 'smoke'
  return <Chip tone={tone} small={small}>{execLabel[v]}</Chip>
}

export function VerdictChip({ v, raw, small = false }: { v: Verdict; raw?: string; small?: boolean }) {
  // зелёного тона у вердикта нет вообще: REPRODUCED — нейтральный, unknown — нейтральный с raw
  const tone: Tone = v === 'UNKNOWN' ? 'warn' : 'smoke'
  return <Chip tone={tone} small={small} mono>{verdictLabel(v, raw)}</Chip>
}

export function FindingChip({ v, raw, small = false }: { v: Finding; raw?: string; small?: boolean }) {
  const tone: Tone = (v === 'FIXED' || v === 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX') ? 'mint' : v === 'POLICY_VIOLATION_OBSERVED' ? 'danger' : v === 'NEEDS_REVIEW' || v === 'UNKNOWN' ? 'warn' : 'smoke'
  return <Chip tone={tone} small={small} mono>{findingLabel(v, raw)}</Chip>
}

export function PreflightChip({ v }: { v: PreflightState }) {
  const map: Record<PreflightState, { tone: Tone; label: string }> = {
    detected: { tone: 'smoke', label: 'обнаружен' },
    verified: { tone: 'mint', label: 'проверен' },
    error: { tone: 'danger', label: 'ошибка' },
    untested: { tone: 'smoke', label: 'не проверялся' },
  }
  const { tone, label } = map[v]
  return <Chip tone={tone}>{label}</Chip>
}

/* ============ служебные блоки ============ */

export function Overline({ children }: { children: ReactNode }) {
  return <div className="overline">{children}</div>
}

/** lucian-карточка: кольцевая тень вместо бордера */
export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-card bg-surface shadow-[0_0_0_1px_var(--line)] p-5 sm:p-6 ${className}`}>
      {children}
    </div>
  )
}

export function Note({ tone = 'info', title, children }: { tone?: 'info' | 'warn' | 'ok'; title?: string; children: ReactNode }) {
  const cls = tone === 'warn' ? 'bg-warnsoft' : tone === 'ok' ? 'bg-mintsoft' : 'bg-dim'
  const titleCls = tone === 'warn' ? 'text-warnink' : tone === 'ok' ? 'text-mintink' : 'text-ink'
  const icon = tone === 'warn' ? 'alert' : tone === 'ok' ? 'check' : 'eye'
  return (
    <div className={`flex items-start gap-3 rounded-field px-4 py-3.5 text-[13.5px] leading-relaxed text-ink2 ${cls}`}>
      <span className={`mt-0.5 shrink-0 ${titleCls}`}>
        <Icon name={icon} size={15} />
      </span>
      <div>
        {title && <div className={`font-bold ${titleCls}`}>{title}</div>}
        {children}
      </div>
    </div>
  )
}

export function Field({ label, hint, error, children }: { label: string; hint?: string; error?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[13px] font-bold text-ink">{label}</span>
      {children}
      {hint && !error && <span className="mt-1.5 block text-[12px] leading-snug text-ink3">{hint}</span>}
      {error && (
        <span className="mt-1.5 flex items-start gap-1.5 text-[12.5px] font-semibold leading-snug text-dangerink">
          <Icon name="alert" size={13} /> {error}
        </span>
      )}
    </label>
  )
}

export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`fieldctl ${props.className ?? ''}`} />
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <span className="relative block">
      <select {...props} className={`fieldctl cursor-pointer appearance-none pr-10 ${props.className ?? ''}`} />
      <span className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-ink3" aria-hidden="true">
        <Icon name="chevronDown" size={15} />
      </span>
    </span>
  )
}

export function EmptyState({ title, children, icon = 'layers' }: { title: string; children?: ReactNode; icon?: string }) {
  return (
    <div className="py-14 text-center">
      <div className="emptyorb">
        <Icon name={icon} size={26} />
      </div>
      <div className="mt-5 text-[17px] font-extrabold tracking-[-0.02em] text-ink2">{title}</div>
      {children && <div className="mx-auto mt-2 max-w-md text-[13.5px] leading-relaxed text-ink3">{children}</div>}
    </div>
  )
}

export function Skeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="space-y-3.5 py-2" aria-busy="true" aria-label="загрузка">
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="breathing h-5 rounded-field bg-dim" style={{ width: `${90 - i * 13}%` }} />
      ))}
    </div>
  )
}

/** Недоверенный контент: только <pre> + textContent, без innerHTML. */
export function Untrusted({ text, label }: { text: string; label?: string }) {
  return (
    <figure>
      {label && <figcaption className="overline mb-2">{label}</figcaption>}
      <pre className="untrusted">{text}</pre>
    </figure>
  )
}

/* ============ модальное окно ============ */

export function Modal({ open, onClose, title, wide = false, children }: { open: boolean; onClose: () => void; title: string; /** wide — для крупного содержимого (доказательства, JSON) */ wide?: boolean; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  const restoreTo = useRef<HTMLElement | null>(null)
  // onClose в ref: эффект не пересоздаётся на каждый рендер родителя,
  // фокус-трап и возврат фокуса живут стабильно
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose
  const id = useId()
  // пока модалка закрыта — помним последний сфокусированный элемент:
  // при открытии вызывающая кнопка может уйти в disabled и потерять фокус
  useEffect(() => {
    if (open) return
    const onFocus = () => { restoreTo.current = document.activeElement as HTMLElement | null }
    document.addEventListener('focusin', onFocus, true)
    return () => document.removeEventListener('focusin', onFocus, true)
  }, [open])
  useEffect(() => {
    if (!open) return
    const focusables = () =>
      [...(ref.current?.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])') ?? [])].filter(
        (el) => !el.hasAttribute('disabled') && el.offsetParent !== null,
      )
    focusables()[0]?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        onCloseRef.current()
        return
      }
      // focus trap: Tab не выходит за пределы диалога
      if (e.key === 'Tab') {
        const items = focusables()
        if (items.length === 0) return
        const first = items[0]
        const last = items[items.length - 1]
        const active = document.activeElement
        if (e.shiftKey && (active === first || !ref.current?.contains(active))) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && active === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }
    document.addEventListener('keydown', onKey, true)
    return () => {
      document.removeEventListener('keydown', onKey, true)
      // возврат фокуса на вызвавший элемент после возврата его в интерактивное состояние
      const el = restoreTo.current
      requestAnimationFrame(() => {
        if (el && el.isConnected && !el.hasAttribute('disabled')) el.focus?.()
      })
    }
  }, [open])
  if (!open) return null
  return (
    <div
      className="fixed inset-0 z-50 flex items-end justify-center bg-ink/45 p-4 backdrop-blur-[2px] sm:items-center"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
      role="presentation"
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={id}
        className={`anim-in flex max-h-[min(88vh,56rem)] w-full flex-col rounded-card bg-surface p-6 shadow-[0_0_0_1px_var(--line),0_40px_80px_-40px_var(--shadow-strong)] ${wide ? 'max-w-3xl' : 'max-w-xl'}`}
      >
        <div className="mb-4 flex shrink-0 items-start justify-between gap-4">
          <h2 id={id} className="text-[19px] font-extrabold tracking-[-0.03em]">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Закрыть"
            className="pressable grid h-9 w-9 place-items-center rounded-full text-ink2 transition-colors hover:bg-dim hover:text-ink"
          >
            <Icon name="cross" />
          </button>
        </div>
        {/* длинное содержимое прокручивается внутри окна, заголовок остаётся видимым */}
        <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
      </div>
    </div>
  )
}

/* ============ вкладки: пилюли в опояске, клавиатурные стрелки ============ */

export function Tabs({ tabs, active, onChange }: { tabs: { id: string; label: string; badge?: string }[]; active: string; onChange: (id: string) => void }) {
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return
    e.preventDefault()
    const idx = tabs.findIndex((t) => t.id === active)
    const next = e.key === 'ArrowRight' ? (idx + 1) % tabs.length : (idx - 1 + tabs.length) % tabs.length
    onChange(tabs[next].id)
    ;(e.currentTarget.querySelector<HTMLElement>(`[data-tab="${tabs[next].id}"]`))?.focus()
  }
  return (
    <div role="tablist" aria-label="Разделы прогона" onKeyDown={onKeyDown} className="navrail w-fit max-w-full">
      {tabs.map((t) => {
        const sel = t.id === active
        return (
          <button
            key={t.id}
            data-tab={t.id}
            role="tab"
            aria-selected={sel}
            tabIndex={sel ? 0 : -1}
            onClick={() => onChange(t.id)}
            className={`navlink ${sel ? 'tabactive' : ''}`}
          >
            {t.label}
            {t.badge && <span className="rounded-full bg-accentsoft px-1.5 py-0.5 font-mono text-[10.5px] font-bold text-accent">{t.badge}</span>}
          </button>
        )
      })}
    </div>
  )
}

/* ============ тройной статус прогона: три lucian-карточки ============ */

export function StatusTriple({ exec, verdict, verdictRaw, finding, findingRaw }: { exec: ExecStatus; verdict: Verdict; verdictRaw?: string; finding: Finding; findingRaw?: string }) {
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      {[
        { k: 'Выполнение', mono: false, v: <ExecChip v={exec} /> },
        { k: 'Результат проверки безопасности', mono: true, v: <VerdictChip v={verdict} raw={verdictRaw} /> },
        { k: 'Результат исправления', mono: true, v: <FindingChip v={finding} raw={findingRaw} /> },
      ].map((cell) => (
        <div key={cell.k} className="rounded-card bg-surface p-4 shadow-[0_0_0_1px_var(--line)]">
          <div className={`text-[10.5px] font-bold uppercase tracking-[0.1em] text-ink3 ${cell.mono ? 'font-mono tracking-normal' : ''}`}>{cell.k}</div>
          <div className="mt-2">{cell.v}</div>
        </div>
      ))}
    </div>
  )
}

/* ============ пара «поле — значение» для мобильных таблиц ============ */

export function KV({ rows }: { rows: Array<{ k: string; v: ReactNode; mono?: boolean }> }) {
  return (
    <dl className="grid grid-cols-[minmax(96px,38%)_1fr] gap-x-4 gap-y-2 text-[13px]">
      {rows.map((r, i) => (
        <div key={i} className="contents">
          <dt className="text-ink3">{r.k}</dt>
          <dd className={`min-w-0 ${r.mono ? 'font-mono text-[12.5px]' : ''} break-words`}>{r.v}</dd>
        </div>
      ))}
    </dl>
  )
}
