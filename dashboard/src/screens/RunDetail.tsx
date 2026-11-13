import { useEffect, useState } from 'react'
import type { Artifact, Check, CheckGroup, Run, Stage, StageOutcome } from '../adapter/types'
import { useStore } from '../state/store'
import { ScreenHead } from '../components/layout'
import {
  Button, Chip, EmptyState, Icon, KV, Modal, Note, Skeleton, StatusTriple, Tabs, Untrusted, Card, Overline,
} from '../components/ui'
import { StageBars } from '../components/charts'
import { useIsMobile } from '../lib/hooks'
import { fmtDateTime, fmtSec } from '../lib/format'

/* ---------- время этапа ---------- */

function StageTime({ s }: { s: Stage }) {
  if (s.state === 'pending') return <span className="text-ink3">—</span>
  if (s.finishedAt !== undefined && s.startedAt !== undefined) {
    return <span className="font-mono text-[11.5px] text-ink3">{fmtSec(s.startedAt)} → {fmtSec(s.finishedAt)}</span>
  }
  // «идёт» — только для действительно выполняющихся этапов; остановленный/отменённый этап без finishedAt — «—»
  if (s.startedAt !== undefined && (s.state === 'running' || s.state === 'wait_model')) {
    return <span className="font-mono text-[11.5px] text-warn">с {fmtSec(s.startedAt)} с, идёт</span>
  }
  return <span className="text-ink3">—</span>
}

/* ---------- ячейки проверки ---------- */

const outcomeMeta: Record<StageOutcome, { cls: string; mark: string }> = {
  pass: { cls: 'text-mintink', mark: '✓' },
  fail: { cls: 'text-dangerink', mark: '✗' },
  not_run: { cls: 'text-ink3', mark: '—' },
}

function ProbeCell({ http, outcome, bodyHashOk, note }: { http: number | null; outcome: StageOutcome; bodyHashOk?: boolean | null; note?: string }) {
  if (outcome === 'not_run') {
    // отсутствующий этап обозначается «не выполнен», а не «успешен»
    return <span className="text-[12px] text-ink3" title={note}>{note ?? 'не выполнен'}</span>
  }
  const m = outcomeMeta[outcome]
  return (
    <span className={`font-mono text-[12.5px] font-semibold ${m.cls}`} title={note}>
      {http ?? '—'} {m.mark}
      {bodyHashOk === true && <span className="ml-1 text-[10.5px] text-mintink">хеш✓</span>}
      {bodyHashOk === false && <span className="ml-1 text-[10.5px] text-dangerink">хеш≠</span>}
    </span>
  )
}

const GROUP_LABEL: Record<CheckGroup, string> = {
  owner: 'Контрольные случаи владельца',
  foreign: 'Запрет чужого доступа',
  anon: 'Анонимный доступ',
  regress: 'Регрессии 401 / 404 и легитимные маршруты',
}
const GROUP_ORDER: CheckGroup[] = ['owner', 'foreign', 'anon', 'regress']

function CheckTable({ checks, mobile }: { checks: Check[]; mobile: boolean }) {
  if (mobile) {
    return (
      <div className="space-y-3.5">
        {checks.map((c) => (
          <div key={c.id} className="rounded-card bg-surface p-4 shadow-[0_0_0_1px_var(--line)]">
            <div className="flex items-start justify-between gap-3">
              <div className="text-[14px] font-bold">{c.scenario}</div>
              {c.final === 'pass' ? <Chip small tone="mint">пройдено</Chip> : c.final === 'fail' ? <Chip small tone="danger">нарушено</Chip> : <Chip small tone="smoke">не выполнено</Chip>}
            </div>
            <div className="mt-3">
              <KV rows={[
                { k: 'Актор', v: c.actor },
                { k: 'Запрос', v: `${c.method} ${c.path}`, mono: true },
                { k: 'Ожидается', v: `HTTP ${c.expectStatus}` },
                { k: 'baseline', v: <ProbeCell {...c.baseline} /> },
                { k: 'candidate', v: <ProbeCell {...c.candidate} /> },
                ...(c.candidateRetry ? [{ k: 'попытка 2', v: <ProbeCell {...c.candidateRetry} /> }] : []),
                ...(c.recheck ? [{ k: 'recheck', v: <ProbeCell {...c.recheck} /> }] : []),
              ]} />
            </div>
            {c.note && <p className="mt-2.5 text-[12px] leading-snug text-ink3">{c.note}</p>}
          </div>
        ))}
      </div>
    )
  }
  return (
    <Card className="overflow-hidden p-0!">
      <div className="overflow-x-auto">
        <table className="tbl min-w-[760px]">
          <thead>
            <tr>
              <th>Сценарий</th>
              <th>Актор · запрос</th>
              <th>Ожид.</th>
              <th>baseline</th>
              <th>candidate</th>
              <th>попытка 2</th>
              <th>recheck</th>
            </tr>
          </thead>
          <tbody>
            {checks.map((c) => (
              <tr key={c.id}>
                <td className="min-w-[180px] font-semibold">
                  {c.scenario}
                  <span className="mt-1 block font-normal">{c.final === 'pass' ? <Chip small tone="mint">итог: пройдено</Chip> : c.final === 'fail' ? <Chip small tone="danger">итог: нарушено</Chip> : <Chip small tone="smoke">итог: не выполнено</Chip>}</span>
                  {c.note && <span className="mt-1.5 block text-[11.5px] font-normal leading-snug text-ink3">{c.note}</span>}
                </td>
                <td className="text-ink2">
                  {c.actor}
                  <span className="mt-0.5 block font-mono text-[11.5px] text-ink3">{c.method} {c.path}</span>
                </td>
                <td className="font-mono text-[12.5px]">{c.expectStatus}</td>
                <td><ProbeCell {...c.baseline} /></td>
                <td><ProbeCell {...c.candidate} /></td>
                <td>{c.candidateRetry ? <ProbeCell {...c.candidateRetry} /> : <span className="text-ink3">—</span>}</td>
                <td>{c.recheck ? <ProbeCell {...c.recheck} /> : <span className="text-ink3">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

/* ---------- главный экран ---------- */

export function RunDetail({ runId, navigate }: { runId: string; navigate: (to: string) => void }) {
  const { adapter, liveRun, pushToast, bumpData, nowMs, dataVersion, mode, reportConnection } = useStore()
  const [raw, setRaw] = useState<Run | null | undefined>(undefined)
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const [tab, setTab] = useState('progress')
  const [openArtifact, setOpenArtifact] = useState<Artifact | null>(null)
  const [artBusy, setArtBusy] = useState(false)
  const mobile = useIsMobile()

  useEffect(() => {
    let alive = true
    setRaw(undefined)
    setLoadErr(null)
    adapter.getRun(runId)
      .then((r) => { if (alive) { setRaw(r); reportConnection(true) } })
      .catch((e) => { if (alive) { setRaw(null); setLoadErr(e instanceof Error ? e.message : 'ошибка связи'); reportConnection(false) } })
    return () => { alive = false }
  }, [adapter, runId, bumpData, dataVersion, reportConnection])

  // polling активного прогона в HTTP-режиме (#2): обновление без перезагрузки,
  // экспоненциальный backoff при ошибке, остановка на терминальном статусе.
  // Завершение НЕ симулируется по локальным часам — состояние приходит с сервера.
  const execNow = raw?.exec
  useEffect(() => {
    if (mode === 'demo') return
    if (!raw || !(execNow === 'running' || execNow === 'queued')) return
    let alive = true
    let timer: ReturnType<typeof setTimeout>
    let delay = 2500
    const tick = async () => {
      try {
        const r = await adapter.getRun(runId)
        if (!alive) return
        setRaw(r)
        setLoadErr(null)
        reportConnection(true)
        delay = 2500
      } catch (e) {
        if (!alive) return
        setLoadErr(e instanceof Error ? e.message : 'ошибка связи')
        reportConnection(false)
        delay = Math.min(delay * 2, 15000)
      }
      if (alive) timer = setTimeout(tick, delay)
    }
    timer = setTimeout(tick, delay)
    return () => { alive = false; clearTimeout(timer) }
  }, [adapter, runId, mode, execNow, reportConnection])

  const run = raw ? liveRun(raw) : null

  if (raw === undefined) return <Skeleton lines={8} />
  if (!run) {
    return loadErr ? (
      // ошибка связи не маскируется под «не найден» (#8)
      <EmptyState icon="alert" title="Прогон недоступен: ошибка связи">
        {loadErr}. Данных нет и не было — повторить запрос можно без перезагрузки страницы.
        <div className="mt-5 flex gap-3"><Button onClick={bumpData}>Повторить</Button><Button variant="ghost" onClick={() => navigate('/runs')}>К списку прогонов</Button></div>
      </EmptyState>
    ) : (
      <EmptyState icon="search" title={`Прогон ${runId} не найден`}>
        Возможно, идентификатор введён с ошибкой — откройте список прогонов.
        <div className="mt-5"><Button onClick={() => navigate('/runs')}>К списку прогонов</Button></div>
      </EmptyState>
    )
  }

  // длительность этапов на единой шкале секунд от старта прогона (#10)
  const elapsedSec = run.finishedAt
    ? Math.max(0, (Date.parse(run.finishedAt) - Date.parse(run.startedAt)) / 1000)
    : Math.max(0, (nowMs - Date.parse(run.startedAt)) / 1000)

  const cancelRun = async () => {
    const res = await adapter.cancelRun(run.id)
    if (!res.ok) {
      pushToast(res.reason, 'error')
      return
    }
    // сервер подтвердил остановку — перечитываем замороженное состояние
    pushToast(`Прогон ${res.runId}: отмена подтверждена сервером (${res.state}).`, 'ok')
    bumpData()
  }

  const exportPatch = async () => {
    const res = await adapter.exportPatch(run.id)
    if ('ok' in res) {
      pushToast(res.reason, 'error')
      return
    }
    const blob = new Blob([res.content], { type: 'text/x-diff' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = res.fileName
    a.click()
    URL.revokeObjectURL(a.href)
    pushToast(`Патч сохранён как ${res.fileName}. Содержимое — демо-данные, помеченные в интерфейсе.`, 'ok')
  }

  const showArtifact = async (a: Artifact) => {
    setArtBusy(true)
    const res = await adapter.getArtifact(run.id, a.id)
    setArtBusy(false)
    if ('ok' in res) {
      pushToast(res.reason, 'error')
      return
    }
    setOpenArtifact(res)
  }

  const meta = (
    <>
      {run.projectId.replace('proj-', '')} · снимок <span className="font-mono text-[12.5px]">{run.snapshotId}</span> · режим{' '}
      {run.mode === 'ai_red_blue' || run.mode === 'S7_2_ACCESS_AI_SINGLE_MODULE' ? 'Red/Blue · AI' : run.mode} · entry{' '}
      <span className="font-mono text-[12.5px]">{run.entryModule}</span>
    </>
  )

  const waitStage = run.stages.find((s) => s.state === 'wait_model')

  return (
    <>
      <div className="mb-4">
        <Button variant="ghost" onClick={() => navigate('/runs')}>
          <span className="rotate-180"><Icon name="chevron" size={14} /></span>
          Запуски
        </Button>
      </div>
      <ScreenHead
        no={`${mode === 'demo' ? 'демо в браузере · ' : mode === 'sim-server' ? 'сервер симуляции · ' : ''}${run.timingKnown === false ? 'дата файла summary (время запуска неизвестно)' : 'старт'} ${fmtDateTime(run.startedAt)}${run.finishedAt ? ` · завершён ${fmtDateTime(run.finishedAt)}` : ' · ещё идёт'}`}
        title={<span className="font-mono text-[26px] sm:text-[30px]">{run.id}</span>}
        meta={meta}
        actions={
          <>
            {run.commit && (
              <Button icon="download" onClick={exportPatch} title="экспорт подтверждённого патча">
                Патч
              </Button>
            )}
            {(run.exec === 'running' || run.exec === 'queued') && (
              <Button variant="danger" icon="stop" onClick={cancelRun} disabled={!run.demo} title={!run.demo ? "Безопасная отмена access-ai ещё не подключена" : ""}>Отменить</Button>
            )}
          </>
        }
      />

      <div className="mb-5">
        <StatusTriple exec={run.exec} verdict={run.verdict} verdictRaw={run.verdictRaw} finding={run.finding} findingRaw={run.findingRaw} />
      </div>

      {/* связь потеряна поверх данных (#8): последние данные помечаются устаревшими */}
      {loadErr && (
        <div className="mb-5 max-w-3xl">
          <Note tone="warn" title="Связь с сервером потеряна — данные могли устареть:">
            {loadErr}. Ниже — последние полученные данные. <button type="button" className="font-bold text-accent underline underline-offset-2" onClick={bumpData}>Повторить</button>
          </Note>
        </div>
      )}

      {/* объяснение статуса: причины из run.error/attempts, не универсальный шаблон (#7) */}
      <div className="mb-8 space-y-2.5">
        {run.exec === 'running' && (
          <Note title="Прогон выполняется:">страница не перезапускает задачу; в HTTP-режиме состояние опрашивается, длительная генерация без событий показывается как «ожидаем ответ», без псевдопроцентов.</Note>
        )}
        {run.mode === 'smoke_only' && run.exec === 'completed' && (
          <Note tone="warn" title="PASS smoke — не «уязвимостей нет»:">успех smoke-проверки подтверждает только работоспособность стенда; оценка безопасности не выполнялась.</Note>
        )}
        {run.exec === 'blocked' && (
          <Note tone="warn" title="BLOCKED — не «проект безопасен»:">
            {run.error ?? 'проверка не доведена до результата'}.
            {run.verdict === 'REPRODUCED' && ' Нарушение уже воспроизведено на baseline; исправление не завершено.'}
            {run.attempts.some((a) => a.rejectionReasons.length > 0) && ' Причины отклонения попыток — на вкладке «Предложения и попытки».'}
          </Note>
        )}
        {run.exec === 'timeout' && (
          <Note tone="warn" title="TIMEOUT — причина остановки выполнения, а не оценка патча:">{run.error ?? 'превышен лимит времени прогона'}{run.finding === null && '. Оценка не выполнялась.'}</Note>
        )}
        {run.finding === 'NEEDS_REVIEW' && (
          <Note tone="warn" title="NEEDS_REVIEW:">{run.error ?? 'требуется решение оператора'} — статус остаётся жёлтым и не показывается как успех.</Note>
        )}
        {(run.finding === 'FIXED' || run.finding === 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX') && (
          <Note tone="ok" title="Нарушение не наблюдается на проверенном исправлении:">
            независимая проверка и recheck не воспроизвели нарушение на патче; это ограничение проверенной политики, а не гарантия отсутствия всех уязвимостей. Патч — отдельный коммит в изолированной копии, исходный репозиторий не изменён.
          </Note>
        )}
        {run.finding === 'POLICY_VIOLATION_OBSERVED' && run.exec !== 'blocked' && (
          <Note tone="warn" title="Нарушение наблюдается на исправлении:">{run.error ?? 'проверка зафиксировала нарушение политики после применения патча'}</Note>
        )}
        {run.verdict === 'UNKNOWN' && (
          <Note tone="warn" title="Неизвестное значение security_verdict:">показано нейтрально с исходной строкой: {run.verdictRaw ?? '—'}. Обновите DTO-мэппинг после сверки с ядром.</Note>
        )}
        {run.finding === 'UNKNOWN' && (
          <Note tone="warn" title="Неизвестное значение finding_status:">показано нейтрально с исходной строкой: {run.findingRaw ?? '—'}.</Note>
        )}
      </div>

      <Tabs
        active={tab}
        onChange={setTab}
        tabs={[
          { id: 'progress', label: 'Ход выполнения' },
          { id: 'checks', label: 'Проверки', badge: run.checks.length ? String(run.checks.length) : undefined },
          { id: 'attempts', label: 'Предложения и попытки', badge: run.attempts.length ? String(run.attempts.length) : undefined },
          { id: 'evidence', label: 'Доказательства' },
        ]}
      />

      <div className="pt-7">
        {/* ============ ход выполнения ============ */}
        {tab === 'progress' && (
          <div className="grid gap-x-10 gap-y-8 lg:grid-cols-[1.1fr_1fr]">
            <Card>
              <Overline>Этапы · порядок из реальных данных</Overline>
              {waitStage && (
                <div className="mt-4 rounded-field bg-warnsoft px-4 py-3 text-[13.5px] leading-relaxed text-ink2">
                  <span className="breathing font-bold text-warnink">Ожидаем ответ модели</span> — событий нет; процент готовности не показывается.
                </div>
              )}
              <ol className="mt-6 list-none">
                {run.stages.map((s) => (
                  <li key={s.id} className="stagerow" data-state={s.state}>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-0.5">
                        <span className={`text-[14px] font-semibold ${s.state === 'pending' || s.state === 'skipped' ? 'text-ink3' : ''} ${s.state === 'wait_model' ? 'breathing' : ''}`}>
                          {s.label}
                          {s.role && <span className="ml-2 text-[11.5px] font-bold text-ink3">{s.role}</span>}
                        </span>
                        <StageTime s={s} />
                      </div>
                      {s.detail && <p className="mt-0.5 text-[12.5px] leading-snug text-ink2">{s.detail}</p>}
                    </div>
                  </li>
                ))}
              </ol>
            </Card>
            <Card>
              <Overline>Журнал событий</Overline>
              <div className="untrusted mt-4" role="log" aria-label="Журнал событий прогона">
                {run.events.length === 0 ? <span className="text-ink3">событий пока нет</span> : null}
                {run.events.map((e, i) => (
                  <div key={i} className="py-0.5">
                    <span className="text-ink3">[T+{fmtSec(e.t)}] </span>
                    <span className="font-semibold text-accent">{e.source}</span>
                    <span>: </span>
                    <span>{e.text}</span>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        )}

        {/* длительность этапов: пропорции из реальных таймингов */}
        {tab === 'progress' && (
          <div className="mt-5">
            <Card>
              <Overline>Длительность этапов · пропорции реальных таймингов</Overline>
              <div className="mt-5">
                <StageBars stages={run.stages} elapsedSec={elapsedSec} />
              </div>
            </Card>
          </div>
        )}

        {/* ============ проверки ============ */}
        {tab === 'checks' && (
          <div className="space-y-8">
            {run.checks.length === 0 ? (
              <EmptyState icon="file" title="Проверки не выполнялись">
                Прогон завершился раньше этапа проверок — таблица пуста по реальной причине, а не скрыта.
              </EmptyState>
            ) : (
              GROUP_ORDER.map((g) => {
                const items = run.checks.filter((c) => c.group === g)
                if (!items.length) return null
                return (
                  <section key={g}>
                    <Overline>{GROUP_LABEL[g]} · {items.length}</Overline>
                    <div className="mt-3">
                      <CheckTable checks={items} mobile={mobile} />
                    </div>
                  </section>
                )
              })
            )}
          </div>
        )}

        {/* ============ предложения и попытки ============ */}
        {tab === 'attempts' && (
          <div className="space-y-8">
            {run.redProposal && (
              <Card>
                <Overline>Red · описание проблемы</Overline>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <Chip tone="accent" mono>предложение AI · сценарий {run.redProposal.scenarioNo}</Chip>
                </div>
                <p className="mt-4 max-w-3xl text-[14.5px] leading-relaxed">{run.redProposal.summary}</p>
                <div className="mt-3 max-w-3xl">
                  <KV rows={[
                    { k: 'Точка входа', v: run.redProposal.entry, mono: true },
                    { k: 'Запрос сценария', v: `${run.redProposal.method} ${run.redProposal.path}`, mono: true },
                  ]} />
                </div>
                <p className="mt-4 text-[12.5px] leading-snug text-ink3">
                  Red предлагает сценарий проверки и не внедряет уязвимость в пользовательский проект; сценарий
                  воспроизводится независимо.
                </p>
              </Card>
            )}

            <section>
              <Overline>Blue · все попытки, включая отклонённые</Overline>
              {run.attempts.length === 0 ? (
                <p className="mt-3 text-[14px] text-ink2">Попыток не было: прогон завершился до этапа патча.</p>
              ) : (
                <div className="mt-4 space-y-5">
                  {run.attempts.map((a) => (
                    <Card key={a.n}>
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                        <span className="text-[15px] font-extrabold tracking-[-0.02em]">Попытка {a.n}</span>
                        <Chip tone={a.status === 'accepted' ? 'mint' : a.status === 'rejected' ? 'danger' : 'smoke'} mono>
                          {a.role} · {a.status === 'accepted' ? 'принята' : a.status === 'rejected' ? 'отклонена' : 'не создана'}
                        </Chip>
                      </div>
                      {a.rejectionReasons.length > 0 && (
                        <ul className="mt-3.5 space-y-1.5 text-[13.5px] font-semibold text-dangerink">
                          {a.rejectionReasons.map((r) => (
                            <li key={r} className="flex gap-2"><Icon name="cross" size={13} /><span>{r}</span></li>
                          ))}
                        </ul>
                      )}
                      {a.checkSummary && <p className="mt-3 text-[13px] leading-relaxed text-ink2">{a.checkSummary}</p>}
                      {a.status !== 'not_produced' && (
                        <div className="mt-4">
                          <Untrusted text={a.diff} label="diff относительно снимка (недоверенный контент)" />
                        </div>
                      )}
                    </Card>
                  ))}
                </div>
              )}
            </section>

            <Card>
              <Overline>Коммит</Overline>
              {run.commit ? (
                <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2 text-[14px]">
                  <span className="text-mint"><Icon name="branch" size={15} /></span>
                  <span className="font-mono text-[13px] font-semibold">{run.commit.ref}</span>
                  <span className="font-mono text-[13px] text-ink2">{run.commit.sha}</span>
                  <span className="text-[12.5px] text-ink3">отдельный коммит в изолированной копии; merge и push не выполнялись</span>
                </div>
              ) : (
                <p className="mt-3 text-[14px] text-ink2">Подтверждённого коммита нет — прогон не дошёл до принятия патча.</p>
              )}
            </Card>
          </div>
        )}

        {/* ============ доказательства ============ */}
        {tab === 'evidence' && (
          <div className="space-y-8">
            <Card>
              <Overline>Привязки и окружение</Overline>
              <div className="mt-4 max-w-3xl">
                <KV rows={[
                  { k: 'AI-профиль', v: run.aiConfigId },
                  { k: 'Модель прогона', v: run.aiConfiguration?.model ?? 'нет данных', mono: true },
                  { k: 'Digest модели', v: run.aiConfiguration?.model_digest ?? 'нет данных', mono: true },
                  { k: 'Образ', v: `${run.tech.image} · ${run.tech.imageDigest}`, mono: true },
                  { k: 'Сеть', v: run.tech.network },
                  { k: 'Хеш конфигурации', v: run.tech.configHash, mono: true },
                  { k: 'Снимок (pin)', v: run.tech.snapshotPin, mono: true },
                  { k: 'Очистка', v: run.tech.cleanup },
                ]} />
              </div>
              <div className="mt-5 max-w-3xl">
                <Note>{run.tech.hashDisclaimer}</Note>
              </div>
            </Card>

            <Card>
              <Overline>Артефакты</Overline>
              <div className="mt-3 divide-y divide-line">
                {run.artifacts.map((a) => (
                  <div key={a.id} className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 py-3.5 first:pt-1 last:pb-0">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2.5">
                        <span className="text-ink3"><Icon name="file" size={15} /></span>
                        <span className={`font-mono text-[13px] font-semibold ${a.present ? '' : 'text-ink3 line-through'}`}>{a.name}</span>
                        <Chip small>{a.kind}</Chip>
                        {!a.present && <Chip small tone="smoke">отсутствует</Chip>}
                      </div>
                      {!a.present && a.absentReason && (
                        <p className="mt-1 pl-6 text-[12.5px] leading-snug text-ink3">{a.absentReason}</p>
                      )}
                    </div>
                    {a.present && (
                      <Button variant="ghost" icon="eye" onClick={() => showArtifact(a)} disabled={artBusy}>
                        Открыть
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            </Card>
          </div>
        )}
      </div>

      {/* модальное окно артефакта */}
      <Modal open={openArtifact !== null} onClose={() => setOpenArtifact(null)} title={openArtifact?.name ?? ''}>
        {openArtifact && (
          <div className="space-y-4">
            {openArtifact.kind === 'html' && (
              <Note tone="warn" title="HTML-отчёт не рендерится:">
                содержимое отчётов недоверенное — показывается текст, теги не исполняются.
              </Note>
            )}
            <Untrusted text={openArtifact.content ?? ''} />
            <p className="text-[12px] text-ink3">
              {mode === 'demo' ? 'Демо-содержимое из браузера.' : mode === 'sim-server' ? 'Источник: сервер симуляции (demo: true) — коммиты и события сценария фиктивные.' : 'Содержимое отдаёт backend по идентификатору.'}
            </p>
          </div>
        )}
      </Modal>
    </>
  )
}
