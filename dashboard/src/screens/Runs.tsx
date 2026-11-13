import { useCallback, useEffect, useMemo, useState } from 'react'
import type { AiConfig, Run } from '../adapter/types'
import { useStore } from '../state/store'
import { ScreenHead } from '../components/layout'
import { Button, Chip, EmptyState, ExecChip, Note, Skeleton, VerdictChip, KV, Card, Overline } from '../components/ui'
import { DailyBars, DurationLine } from '../components/charts'
import { fmtDateTime, fmtDuration } from '../lib/format'

const MODE_LABEL: Record<string, string> = {
  ai_red_blue: 'Red/Blue · AI',
  S7_2_ACCESS_AI_SINGLE_MODULE: 'Red/Blue · AI · S7.2',
  smoke_only: 'smoke',
}

const selectCls =
  'fieldctl h-10 text-[13px]'

export function Runs({ navigate }: { navigate: (to: string) => void }) {
  const { adapter, nowMs, dataVersion, liveRun, mode, reportConnection, connectionLost } = useStore()
  const [runs, setRuns] = useState<Run[] | null>(null)
  const [configs, setConfigs] = useState<AiConfig[]>([])
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const [stale, setStale] = useState(false)
  const [mobile, setMobile] = useState(() => window.innerWidth < 900)
  const [fProject, setFProject] = useState('all')
  const [fStatus, setFStatus] = useState('all')
  const [fMode, setFMode] = useState('all')
  const [fDate, setFDate] = useState<'all' | '24h' | '7d'>('all')

  useEffect(() => {
    const onResize = () => setMobile(window.innerWidth < 900)
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  // загрузка: ошибка сети не превращается в «прогонов не было» (#8) —
  // без данных показывается ошибка, с данными — пометка «устарели»
  const load = useCallback(async () => {
    if (document.hidden) return
    try {
      const rs = await adapter.listRuns()
      setRuns(rs)
      setLoadErr(null)
      setStale(false)
      reportConnection(true)
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'ошибка связи'
      setRuns((cur) => {
        if (cur === null) setLoadErr(msg)
        else setStale(true)
        return cur
      })
      reportConnection(false)
    }
  }, [adapter, reportConnection])

  useEffect(() => {
    load()
    adapter.listAiConfigs().then(setConfigs).catch(() => setConfigs([]))
  }, [load, dataVersion])

  // polling в HTTP-режиме, пока есть незавершённые прогоны (#2)
  const hasActive = (runs ?? []).some((r) => r.exec === 'running' || r.exec === 'queued')
  useEffect(() => {
    if (mode === 'demo' || !hasActive) return
    const t = setInterval(load, 3000)
    return () => clearInterval(t)
  }, [mode, hasActive, load])

  // потеря связи: перечитываем, чтобы показать баннер «данные устарели» с «Повторить» (#8)
  useEffect(() => {
    if (mode !== 'demo' && connectionLost) load()
  }, [connectionLost, mode, load])

  const projectsOptions = useMemo(() => {
    const ids = new Set((runs ?? []).map((r) => r.projectId))
    return [...ids]
  }, [runs])

  const filtered = useMemo(() => {
    // развёртка сценария активного демо-прогона — иначе колонка «Сейчас» пуста
    let out = (runs ?? []).map(liveRun)
    if (fProject !== 'all') out = out.filter((r) => r.projectId === fProject)
    if (fStatus !== 'all') out = out.filter((r) => r.exec === fStatus)
    if (fMode !== 'all') out = out.filter((r) => r.mode === fMode)
    if (fDate !== 'all') {
      const cutoff = Date.now() - (fDate === '24h' ? 864e5 : 7 * 864e5)
      out = out.filter((r) => Date.parse(r.startedAt) >= cutoff)
    }
    return out
  }, [runs, liveRun, fProject, fStatus, fMode, fDate])

  const filtersEmpty = fProject === 'all' && fStatus === 'all' && fMode === 'all' && fDate === 'all'

  const modelOf = (r: Run) => configs.find((c) => c.id === r.aiConfigId)?.model ?? r.aiConfigId
  const currentStage = (r: Run) => r.stages.find((s) => s.state === 'running' || s.state === 'wait_model')
  const duration = (r: Run) => r.timingKnown === false ? 'нет данных' : fmtDuration(r.startedAt, r.finishedAt ?? new Date(nowMs).toISOString())

  const Filter = ({ label, value, onChange, children }: { label: string; value: string; onChange: (v: string) => void; children: React.ReactNode }) => (
    <label className="flex flex-col gap-1.5">
      <span className="overline">{label}</span>
      <select className={selectCls} value={value} onChange={(e) => onChange(e.target.value)}>
        {children}
      </select>
    </label>
  )

  return (
    <>
      <ScreenHead
        no="03 · Журнал"
        title="Запуски"
        meta={<>Каждый прогон — воспроизведение нарушения и проверка патча на зафиксированном снимке. Длительная генерация без событий показывается как «ожидаем ответ», без псевдопроцентов.</>}
      />

      <div className="mb-7 flex flex-wrap items-end gap-x-4 gap-y-4">
        <Filter label="Проект" value={fProject} onChange={setFProject}>
          <option value="all">все</option>
          {projectsOptions.map((id) => <option key={id} value={id}>{id.replace('proj-', '')}</option>)}
        </Filter>
        <Filter label="Статус" value={fStatus} onChange={setFStatus}>
          <option value="all">все</option>
          <option value="running">выполняется</option>
          <option value="completed">завершён</option>
          <option value="failed">ошибка</option>
          <option value="blocked">остановлено: BLOCKED</option>
          <option value="timeout">лимит времени</option>
        </Filter>
        <Filter label="Режим" value={fMode} onChange={setFMode}>
          <option value="all">все</option>
          <option value="ai_red_blue">Red/Blue · AI</option>
          <option value="S7_2_ACCESS_AI_SINGLE_MODULE">Red/Blue · S7.2 (ядро)</option>
          <option value="smoke_only">smoke</option>
        </Filter>
        <Filter label="Дата" value={fDate} onChange={(v) => setFDate(v as 'all' | '24h' | '7d')}>
          <option value="all">за всё время</option>
          <option value="24h">за 24 часа</option>
          <option value="7d">за 7 дней</option>
        </Filter>
        {!filtersEmpty && <Button variant="ghost" onClick={() => { setFProject('all'); setFStatus('all'); setFMode('all'); setFDate('all') }}>Сбросить</Button>}
      </div>

      {runs === null && loadErr ? (
        <EmptyState icon="alert" title="Реестр прогонов недоступен: ошибка связи">
          {loadErr}. Список не получен — показывать пустой реестр было бы неверно.{' '}
          <button type="button" className="font-bold text-accent underline underline-offset-2" onClick={load}>Повторить</button>
        </EmptyState>
      ) : runs === null ? (
        <Skeleton lines={7} />
      ) : (
        <>
          {stale && (
            <div className="mb-5">
              <Note tone="warn" title="Связь с сервером потеряна — показаны последние полученные данные:">
                обновление остановлено; список может не отражать текущее состояние прогонов.{' '}
                <button type="button" className="font-bold text-accent underline underline-offset-2" onClick={load}>Повторить</button>
              </Note>
            </div>
          )}
          {filtered.length === 0 ? (
        <EmptyState icon="clock" title={runs.length === 0 ? 'Прогонов ещё не было' : 'Под фильтры ничего не попало'}>
          {runs.length === 0
            ? 'Соберите первый запуск в разделе «Новый запуск».'
            : 'Ослабьте фильтры — часть статусов может встречаться только в другие даты.'}
        </EmptyState>
          ) : mobile ? (
        <div className="space-y-3.5">
          {filtered.map((r) => {
            const stage = currentStage(r)
            return (
              <button key={r.id} type="button" onClick={() => navigate(`/runs/${r.id}`)}
                className="pressable block w-full rounded-card bg-surface p-4 text-left shadow-[0_0_0_1px_var(--line)] transition-shadow hover:shadow-[0_0_0_1px_var(--line2),0_16px_30px_-22px_var(--shadow-strong)]">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-mono text-[13px] font-semibold">{r.id}</span>
                  <ExecChip v={r.exec} small />
                </div>
                <div className="mt-3">
                  <KV rows={[
                    { k: 'Проект', v: r.projectId.replace('proj-', '') },
                    { k: 'Снимок', v: r.snapshotId, mono: true },
                    { k: 'Режим', v: MODE_LABEL[r.mode] ?? r.mode },
                    { k: 'Модель', v: modelOf(r), mono: true },
                    { k: 'Старт', v: fmtDateTime(r.startedAt) },
                    { k: 'Длительность', v: duration(r) },
                    ...(stage ? [{ k: 'Сейчас', v: `${stage.role ?? ''} ${stage.label}`.trim() }] : []),
                  ]} />
                </div>
                <div className="mt-3"><VerdictChip v={r.verdict} raw={r.verdictRaw} small /></div>
              </button>
            )
          })}
        </div>
      ) : (
        <Card className="overflow-hidden p-0!">
          <div className="overflow-x-auto">
            <table className="tbl min-w-[820px]">
              <thead>
                <tr>
                  <th>Прогон</th>
                  <th>Проект · снимок</th>
                  <th>Режим · модель</th>
                  <th>Старт · длительность</th>
                  <th>Сейчас</th>
                  <th>Статусы</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => {
                  const stage = currentStage(r)
                  return (
                    <tr key={r.id} className="cursor-pointer" onClick={() => navigate(`/runs/${r.id}`)}>
                      <td className="whitespace-nowrap font-mono text-[12.5px] font-semibold">
                        <span className="underline decoration-line2 decoration-dotted underline-offset-4">{r.id}</span>
                        {r.demo && <span className="mt-1.5 block"><Chip small>демо</Chip></span>}
                      </td>
                      <td className="text-ink2">
                        {r.projectId.replace('proj-', '')}
                        <span className="mt-0.5 block font-mono text-[11.5px] text-ink3">{r.snapshotId}</span>
                      </td>
                      <td className="text-ink2">
                        {MODE_LABEL[r.mode] ?? r.mode}
                        <span className="mt-0.5 block font-mono text-[11.5px] text-ink3">{modelOf(r)}</span>
                      </td>
                      <td className="text-ink2">
                        {fmtDateTime(r.startedAt)}
                        <span className="mt-0.5 block text-[12px] text-ink3">{duration(r)}</span>
                      </td>
                      <td className="text-ink2">
                        {stage ? (
                          <>
                            {stage.role && <span className="block text-[11.5px] font-bold text-ink3">{stage.role}</span>}
                            <span>{stage.label}</span>
                            <span className="mt-0.5 block font-mono text-[11px] text-warn">лимит {r.timeLimitMin} мин</span>
                          </>
                        ) : (
                          <span className="text-ink3">—</span>
                        )}
                      </td>
                      <td><div className="flex flex-col items-start gap-1.5"><ExecChip v={r.exec} small /><VerdictChip v={r.verdict} raw={r.verdictRaw} small /></div></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>
          )}
        </>
      )}

      {/* обзор по реальным данным журнала — ниже списка: активные прогоны и
          результаты первичны, графики вторичны (замечание аудита) */}
      {runs !== null && filtered.length > 0 && !loadErr && (
        <div className="mt-7 grid gap-5 lg:grid-cols-2">
          <Card>
            <Overline>Прогоны по дням · 14 дней</Overline>
            <div className="mt-4">
              <DailyBars runs={filtered} />
            </div>
          </Card>
          <Card>
            <Overline>Длительность прогонов</Overline>
            <div className="mt-4">
              <DurationLine runs={filtered} />
            </div>
          </Card>
        </div>
      )}
    </>
  )
}
