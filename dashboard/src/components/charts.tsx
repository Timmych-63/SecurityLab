import { useId, useLayoutEffect, useRef, useState } from 'react'
import type { Run, Stage } from '../adapter/types'
import { fmtSec } from '../lib/format'
import { translateStageText } from '../lib/ru'
import { stagePresentation } from '../lib/stagePresentation'

/**
 * Графики в стилистике lucian-uxui-prompt (элементы #095 bar-chart-hover,
 * #096 line-chart-scrub): кольцевые карточки, чернильные тултипы,
 * пружинная анимация баров, пульсирующая точка на скрабе.
 * Все данные — реальные из адаптера; цвет статуса всегда подписан текстом.
 */

const dayKey = (d: Date) => `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`

const MONTHS_SHORT = ['янв', 'фев', 'мар', 'апр', 'мая', 'июн', 'июл', 'авг', 'сен', 'окт', 'ноя', 'дек']

const STATUS_COLOR: Record<string, string> = {
  running: 'var(--accent)',
  completed: 'var(--mint)',
  failed: 'var(--danger)',
  blocked: 'var(--danger)',
  timeout: 'var(--warn)',
  cancelled: 'var(--raise)',
  queued: 'var(--raise)',
}
const STATUS_LABEL: Record<string, string> = {
  running: 'выполняется',
  completed: 'завершён',
  failed: 'ошибка',
  blocked: 'остановлено (BLOCKED)',
  timeout: 'лимит времени',
  cancelled: 'отменён',
  queued: 'в очереди',
}

/* ===================== бары по дням (lucian #095) ===================== */

export function DailyBars({ runs }: { runs: Run[] }) {
  const [hover, setHover] = useState<number | null>(null)
  const DAYS = 14

  const buckets = Array.from({ length: DAYS }, (_, i) => {
    const d = new Date(Date.now() - (DAYS - 1 - i) * 864e5)
    d.setHours(0, 0, 0, 0)
    return { date: d, counts: {} as Record<string, number> }
  })
  const byKey = new Map(buckets.map((b) => [dayKey(b.date), b]))
  for (const r of runs) {
    const b = byKey.get(dayKey(new Date(r.startedAt)))
    if (b) b.counts[r.exec] = (b.counts[r.exec] ?? 0) + 1
  }
  const maxTotal = Math.max(1, ...buckets.map((b) => Object.values(b.counts).reduce((a, c) => a + c, 0)))
  const todayKey = dayKey(new Date())
  // порядок слоёв снизу вверх: успех — процесс — ожидание — сбой — прочее
  const LAYER_ORDER = ['completed', 'running', 'timeout', 'failed', 'cancelled', 'queued']

  return (
    <div>
      <div className="relative h-[196px] pr-10" role="img" aria-label="прогоны по дням за две недели, столбцы, цвета статусов подписаны в легенде">
        {/* сетка */}
        {[25, 50, 75].map((p) => (
          <div key={p} className="absolute left-0 right-10 border-t border-dashed border-line2" style={{ bottom: `${p}%` }} aria-hidden="true" />
        ))}
        <div className="absolute right-0 top-0 font-mono text-[10.5px] font-bold text-ink3" aria-hidden="true">{maxTotal}</div>
        <div className="absolute left-0 right-10 top-0 border-t border-line" aria-hidden="true" />

        {/* тултип (чернильный, lucian) */}
        {hover !== null && (
          <div
            className="pointer-events-none absolute z-10 flex -translate-x-1/2 flex-col items-center gap-0.5 whitespace-nowrap rounded-lg bg-ink px-3 py-2 text-[11.5px] font-bold text-page"
            style={{ left: `${((hover + 0.5) / DAYS) * 100}%`, bottom: '104%' }}
            aria-hidden="true"
          >
            <span>
              {buckets[hover].date.getDate()} {MONTHS_SHORT[buckets[hover].date.getMonth()]}
              {' · '}
              {Object.values(buckets[hover].counts).reduce((a, c) => a + c, 0) || 'нет'} прогон(ов)
            </span>
            {Object.entries(buckets[hover].counts).length > 0 && (
              <span className="flex gap-2 font-semibold text-[10.5px] opacity-80">
                {Object.entries(buckets[hover].counts).map(([k, v]) => (
                  <span key={k} className="flex items-center gap-1">
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: STATUS_COLOR[k] ?? 'var(--raise)' }} />
                    {STATUS_LABEL[k] ?? k} {v}
                  </span>
                ))}
              </span>
            )}
          </div>
        )}

        {/* столбцы */}
        <div className="absolute inset-0 right-10 flex items-stretch" onMouseLeave={() => setHover(null)}>
          {buckets.map((b, i) => {
            const total = Object.values(b.counts).reduce((a, c) => a + c, 0)
            const isToday = dayKey(b.date) === todayKey
            return (
              <button
                key={i}
                type="button"
                className="group relative flex min-w-0 flex-1 cursor-default flex-col justify-end px-[3px] pb-0.5 outline-none"
                onMouseEnter={() => setHover(i)}
                onFocus={() => setHover(i)}
                aria-label={`${b.date.getDate()} ${MONTHS_SHORT[b.date.getMonth()]}: ${total || 'нет'} прогонов`}
              >
                {total === 0 ? (
                  <span className="mx-auto block h-[3px] w-full rounded-t-sm bg-raise" />
                ) : (
                  <span className="flex min-h-0 flex-1 flex-col justify-end gap-[2px]">
                    {[...LAYER_ORDER].reverse().filter((k) => b.counts[k]).map((k, li) => (
                      <span
                        key={k}
                        className="chartseg block w-full rounded-[4px]"
                        style={{ height: `${(b.counts[k] / maxTotal) * 100}%`, background: STATUS_COLOR[k], animationDelay: `${i * 26 + li * 14}ms` }}
                      />
                    ))}
                  </span>
                )}
                <span
                  className={`mt-1.5 block text-center text-[10.5px] font-bold tabular-nums transition-colors ${
                    hover === i ? 'text-ink' : isToday ? 'text-accent' : 'text-ink3'
                  }`}
                >
                  {b.date.getDate()}
                </span>
              </button>
            )
          })}
        </div>
      </div>
      <Legend items={Object.entries(STATUS_COLOR).map(([k, c]) => ({ color: c, label: STATUS_LABEL[k] }))} />
    </div>
  )
}

/* ===================== линия длительностей (lucian #096) ===================== */

interface DurPoint {
  id: string
  label: string
  min: number
}

export function DurationLine({ runs }: { runs: Run[] }) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [w, setW] = useState(420)
  const [hover, setHover] = useState<number | null>(null)
  const gid = useId()

  useLayoutEffect(() => {
    const el = svgRef.current
    if (!el) return
    const measure = () => setW(el.parentElement?.clientWidth ?? 420)
    measure()
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [])

  const points: DurPoint[] = runs
    .filter((r) => r.finishedAt && (r.exec === 'completed' || r.exec === 'failed' || r.exec === 'timeout'))
    .sort((a, b) => Date.parse(a.startedAt) - Date.parse(b.startedAt))
    .map((r) => ({
      id: r.id,
      label: `${new Date(r.startedAt).getDate()} ${MONTHS_SHORT[new Date(r.startedAt).getMonth()]}`,
      min: (Date.parse(r.finishedAt!) - Date.parse(r.startedAt)) / 60000,
    }))

  const H = 168
  const PAD = { x: 10, y: 16 }
  const maxMin = Math.max(1, ...points.map((p) => p.min))
  const px = (i: number) => (points.length < 2 ? w / 2 : PAD.x + (i * (w - 2 * PAD.x)) / (points.length - 1))
  const py = (v: number) => H - PAD.y - (v / maxMin) * (H - 2 * PAD.y)

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${px(i).toFixed(1)},${py(p.min).toFixed(1)}`).join(' ')
  const areaPath = points.length > 1 ? `${linePath} L${px(points.length - 1).toFixed(1)},${H - PAD.y} L${px(0).toFixed(1)},${H - PAD.y} Z` : ''

  const mean = points.length ? points.reduce((a, p) => a + p.min, 0) / points.length : 0
  const sorted = [...points].sort((a, b) => a.min - b.min)
  const median = points.length ? (points.length % 2 ? sorted[(points.length - 1) / 2].min : (sorted[points.length / 2 - 1].min + sorted[points.length / 2].min) / 2) : 0

  const scrub = (e: React.PointerEvent<SVGSVGElement>) => {
    if (points.length === 0) return
    const rect = svgRef.current!.getBoundingClientRect()
    const x = e.clientX - rect.left
    const step = points.length < 2 ? 0 : (w - 2 * PAD.x) / (points.length - 1)
    const idx = step ? Math.round((x - PAD.x) / step) : 0
    setHover(Math.max(0, Math.min(points.length - 1, idx)))
  }

  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between">
        <div>
          <div className="text-[12.5px] font-bold text-ink3">средняя длительность завершённых прогонов</div>
          <div className="text-[30px] font-extrabold leading-tight tracking-[-0.045em] tabular-nums">
            {points.length ? `~${mean.toFixed(0)} мин` : '—'}
          </div>
          <div className="text-[12.5px] font-bold tabular-nums">
            <b className="text-mint">{points.length ? `медиана ${median.toFixed(0)} мин` : 'нет данных'}</b>
            <span className="text-ink3"> · {points.length} завершённых</span>
          </div>
        </div>
        <div className="text-right font-mono text-[10.5px] font-bold text-ink3" aria-hidden="true">
          max {maxMin.toFixed(0)} мин
        </div>
      </div>

      {points.length === 0 ? (
        <div className="grid h-[168px] place-items-center rounded-field bg-dim text-[13px] text-ink3">
          Завершённых прогонов пока нет — линия появится из реальных данных
        </div>
      ) : (
        <div className="relative cursor-crosshair touch-pan-y" onPointerLeave={() => setHover(null)}>
          {/* тег значения при скрабе */}
          <div
            className={`pointer-events-none absolute top-0 z-10 flex h-[22px] -translate-x-1/2 items-center whitespace-nowrap rounded-md bg-ink px-2 text-[11px] font-bold text-page transition-opacity ${
              hover !== null ? 'opacity-100' : 'opacity-0'
            }`}
            style={{ left: hover !== null ? px(hover) : 0 }}
            aria-hidden="true"
          >
            {hover !== null && `${points[hover].min.toFixed(0)} мин · ${points[hover].id}`}
          </div>
          <svg
            ref={svgRef}
            width="100%"
            height={H}
            viewBox={`0 0 ${w} ${H}`}
            role="img"
            aria-label={`длительность завершённых прогонов, ${points.length} точек; при наведении показывается значение`}
            onPointerMove={scrub}
            onFocus={() => setHover(points.length - 1)}
            tabIndex={0}
          >
            <defs>
              <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--mint)" stopOpacity="0.2" />
                <stop offset="100%" stopColor="var(--mint)" stopOpacity="0" />
              </linearGradient>
            </defs>
            {[25, 50, 75].map((p) => (
              <line key={p} x1={0} x2={w} y1={PAD.y + (p / 100) * (H - 2 * PAD.y)} y2={PAD.y + (p / 100) * (H - 2 * PAD.y)} stroke="var(--line2)" strokeDasharray="3 5" />
            ))}
            {areaPath && <path d={areaPath} fill={`url(#${gid})`} />}
            {points.length > 1 && (
              <path d={linePath} fill="none" stroke="var(--mint)" strokeWidth="2.6" strokeLinejoin="round" strokeLinecap="round" />
            )}
            {/* вертикаль при скрабе */}
            {hover !== null && (
              <line x1={px(hover)} x2={px(hover)} y1={PAD.y - 6} y2={H - PAD.y} stroke="var(--ink3)" strokeOpacity="0.55" strokeWidth="1" />
            )}
            {points.map((p, i) => (
              <circle
                key={p.id}
                cx={px(i)}
                cy={py(p.min)}
                r={hover === i ? 5 : 3.5}
                fill="var(--mint)"
                stroke="var(--surface)"
                strokeWidth="2.5"
              />
            ))}
            {/* пульс на последней точке — живой график (lucian #096) */}
            {points.length > 1 && hover === null && (
              <circle className="chartpulse" cx={px(points.length - 1)} cy={py(points[points.length - 1].min)} r="5" fill="none" stroke="var(--mint)" strokeWidth="2" />
            )}
            {/* подписи первой/последней даты */}
            <text x={PAD.x} y={H - 2} fontSize="10" fontWeight="700" fill="var(--ink3)">{points[0].label}</text>
            <text x={w - PAD.x} y={H - 2} fontSize="10" fontWeight="700" fill="var(--ink3)" textAnchor="end">{points[points.length - 1].label}</text>
          </svg>
        </div>
      )}
    </div>
  )
}

/* ===================== длительности этапов (горизонтальные бары) ===================== */

const STAGE_COLOR: Record<string, string> = {
  neutral: 'var(--ink3)',
  violation: 'var(--warn)',
  matched: 'var(--mint)',
  running: 'var(--accent)',
  wait_model: 'var(--warn)',
  failed: 'var(--danger)',
  blocked: 'var(--danger)',
  skipped: 'var(--raise)',
}
const STAGE_LABEL: Record<string, string> = {
  neutral: 'этап завершён / пропущен; не вердикт безопасности',
  violation: 'нарушение воспроизведено',
  matched: 'проверенные случаи соответствуют политике',
  running: 'выполняется',
  wait_model: 'ожидаем ответ',
  failed: 'ошибка',
  blocked: 'остановлено',
  skipped: 'не выполнен',
}

export function StageBars({ stages, elapsedSec }: { stages: Stage[]; elapsedSec: number }) {
  // тайминги этапов — секунды от старта прогона; идущий этап длится
  // elapsedSec - startedAt, а не «Unix now - startedAt» (#10)
  const timed = stages
    .filter((s) => s.startedAt !== undefined && s.state !== 'pending')
    .map((s) => ({
      ...s,
      dur: Math.max(0, (s.finishedAt ?? elapsedSec) - s.startedAt!),
      // «идёт» — только действительно выполняющиеся этапы; отменённый этап не тикает
      live: s.finishedAt === undefined && (s.state === 'running' || s.state === 'wait_model'),
    }))
  if (timed.length === 0) return null
  const maxDur = Math.max(...timed.map((t) => t.dur), 1)

  return (
    <div>
      <div className="space-y-3.5" role="img" aria-label="длительность этапов прогона, пропорциональные полосы">
        {timed.map((t) => (
          <div key={t.id} className="flex items-center gap-3">
            <div className="w-[170px] shrink-0 truncate text-[12.5px] font-semibold" title={translateStageText(t.label)}>
              {translateStageText(t.label)}
              {t.role && <span className="ml-1.5 text-[10.5px] font-bold text-ink3">{translateStageText(t.role)}</span>}
            </div>
            <div className="h-2.5 min-w-0 flex-1 overflow-hidden rounded-full bg-raise">
              <div
                className="chartbar h-full rounded-full"
                style={{ width: `${Math.max(2, (t.dur / maxDur) * 100)}%`, background: STAGE_COLOR[stagePresentation(t).tone] ?? 'var(--raise)', animationDelay: '40ms' }}
              />
            </div>
            <div className={`w-[110px] shrink-0 text-right font-mono text-[11.5px] font-semibold ${t.state === 'failed' ? 'text-dangerink' : t.state === 'wait_model' ? 'text-warnink' : 'text-ink3'}`}>
              {fmtSec(Math.round(t.dur))}
              {t.live && <span className="block text-[10px] font-bold text-warn">идёт</span>}
            </div>
          </div>
        ))}
      </div>
      <Legend
        items={[...new Set(timed.map((t) => stagePresentation(t).tone))].map((k) => ({ color: STAGE_COLOR[k], label: STAGE_LABEL[k] ?? k }))}
      />
    </div>
  )
}

/* ===================== легенда: цвет всегда с текстом ===================== */

function Legend({ items }: { items: Array<{ color: string; label: string }> }) {
  const seen = new Set<string>()
  const unique = items.filter((i) => !seen.has(i.label) && seen.add(i.label))
  return (
    <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5" aria-hidden="false">
      {unique.map((i) => (
        <span key={i.label} className="flex items-center gap-1.5 text-[11.5px] font-semibold text-ink3">
          <span className="h-2 w-2 rounded-full" style={{ background: i.color }} />
          {i.label}
        </span>
      ))}
    </div>
  )
}
