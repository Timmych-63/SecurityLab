import { useCallback, useEffect, useMemo, useState } from 'react'
import type { AiConfig, NewRunInput, Policy, PreflightResult, Project } from '../adapter/types'
import { useStore, useActiveRun } from '../state/store'
import { ScreenHead } from '../components/layout'
import { Button, Field, Note, PreflightChip, Select, Skeleton, TextInput } from '../components/ui'
import { fmtDateTime } from '../lib/format'

/** Номерованный раздел формы: чернильный номер-медальон + заголовок */
function Step({ no, title, aside, children }: { no: string; title: string; aside?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="rounded-card bg-surface p-5 shadow-[0_0_0_1px_var(--line)] sm:p-6">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-x-6 gap-y-2">
        <div className="flex items-center gap-3">
          <span
            className="grid h-7 w-7 shrink-0 place-items-center rounded-full bg-ink font-mono text-[11px] font-bold text-page"
            aria-hidden="true"
          >
            {no}
          </span>
          <h2 className="text-[15.5px] font-extrabold tracking-[-0.02em]">{title}</h2>
        </div>
        {aside}
      </div>
      {children}
    </section>
  )
}

function NumRow({ k, v, mono = false }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-6 py-2">
      <span className="text-[13px] text-ink3">{k}</span>
      <span className={`text-right text-[13.5px] font-semibold ${mono ? 'font-mono text-[12.5px]' : ''}`}>{v}</span>
    </div>
  )
}

const PREFLIGHT_KEYS = ['docker', 'images', 'model'] as const

/** Предпроверка считается готовой, когда все проверки verified (#6). */
function preflightReady(pf: PreflightResult | null): boolean {
  return !!pf && PREFLIGHT_KEYS.every((k) => pf[k] === 'verified')
}

export function NewRun({ navigate, initialProjectId }: { navigate: (to: string) => void; initialProjectId?: string }) {
  const { adapter, pushToast, bumpData, mode, selectedAiConfigId, setSelectedAiConfigId } = useStore()
  const active = useActiveRun()

  const [projects, setProjects] = useState<Project[] | null>(null)
  const [policies, setPolicies] = useState<Policy[] | null>(null)
  const [configs, setConfigs] = useState<AiConfig[] | null>(null)

  const [projectId, setProjectId] = useState(initialProjectId ?? '')
  const [snapshotId, setSnapshotId] = useState('')
  const [service, setService] = useState('')
  const [entry, setEntry] = useState('')
  const [policyId, setPolicyId] = useState('')
  const [aiConfigId, setAiConfigId] = useState(selectedAiConfigId)

  const [attempted, setAttempted] = useState(false)
  const [preflight, setPreflight] = useState<PreflightResult | null>(null)
  const [preflightErr, setPreflightErr] = useState<string | null>(null)
  const [preflightBusy, setPreflightBusy] = useState(false)
  const [launchRefusal, setLaunchRefusal] = useState<string | null>(null)
  const [launching, setLaunching] = useState(false)

  useEffect(() => {
    let alive = true
    Promise.all([adapter.listProjects(), adapter.listPolicies(), adapter.listAiConfigs()])
      .then(([p, pol, cfg]) => {
        if (!alive) return
        setProjects(p.filter((x) => x.supported))
        setPolicies(pol)
        setConfigs(cfg)
      })
      .catch((e) => {
        // ошибка загрузки справочников не превращается в вечный скелет (#8)
        if (!alive) return
        setProjects([])
        setPolicies([])
        setConfigs([])
        pushToast(`Справочники недоступны: ${e instanceof Error ? e.message : 'ошибка связи'}. `, 'error')
      })
    return () => { alive = false }
  }, [adapter, pushToast])

  const project = projects?.find((p) => p.id === projectId) ?? null
  const policy = policies?.find((x) => x.id === policyId) ?? null
  const aiConfig = configs?.find((c) => c.id === aiConfigId) ?? null

  /** Точки входа из принятого набора проекта (#3): путь файла и import string разделены. */
  const entries = project?.services ?? []
  const stateDir = project?.stateDir ?? ''

  const errors = useMemo(() => {
    const e: Record<string, string> = {}
    if (!projectId) e.project = 'Выберите проект — запуск создаётся только для проекта с профилем'
    if (projectId && !snapshotId) e.snapshot = 'Выберите зафиксированный снимок: запуск воспроизводит нарушение на снимке, а не на «текущем» коде'
    if (!service) e.service = 'Выберите сервис из набора проекта'
    if (!entry) e.entry = 'Выберите точку входа из набора проекта (путь файла или import string)'
    // валидация по загруженным спискам, а не «непустая строка» (#3)
    if (!policyId) e.policy = 'Политика обязательна: без неё проверка не собирается'
    else if (policies && !policies.some((x) => x.id === policyId)) e.policy = 'Выбранной политики нет в загруженном реестре'
    if (!aiConfigId) e.ai = 'Выберите AI-конфигурацию'
    else if (configs && !configs.some((x) => x.id === aiConfigId)) e.ai = 'Выбранной конфигурации нет в загруженном реестре'
    if (projectId && !stateDir) e.project = 'У проекта не задан state-каталог ядра'
    return e
  }, [projectId, snapshotId, service, entry, policyId, aiConfigId, policies, configs, stateDir])

  const formOk = Object.keys(errors).length === 0

  const formInput = useMemo(
    () => ({ projectId, snapshotId, service, entryModule: entry, profileId: project?.profile ?? '', policyId, aiConfigId, stateDir }),
    [projectId, snapshotId, service, entry, project, policyId, aiConfigId, stateDir],
  )

  // предпроверка привязана к точным параметрам (#6): изменение формы делает её недействительной
  const preflightStale = useMemo(() => {
    if (!preflight) return false
    return JSON.stringify((preflight as PreflightResult & { params?: unknown }).params ?? null) !== JSON.stringify(formInput)
  }, [preflight, formInput])

  const runPreflight = useCallback(async () => {
    setAttempted(true)
    if (!formOk) return
    setPreflightBusy(true)
    setPreflightErr(null)
    setPreflight(null)
    try {
      const res = await adapter.preflight(formInput)
      setPreflight(res)
    } catch (e) {
      setPreflightErr(e instanceof Error ? e.message : 'ошибка связи')
    } finally {
      setPreflightBusy(false)
    }
  }, [adapter, formOk, formInput])

  const launch = useCallback(async () => {
    setAttempted(true)
    setLaunchRefusal(null)
    if (!formOk || !preflightReady(preflight) || preflightStale) return
    setLaunching(true)
    try {
      const res = await adapter.createRun(formInput)
      if ('ok' in res) {
        setLaunchRefusal(res.reason)
        return
      }
      bumpData()
      pushToast(
        mode === 'demo'
          ? `Демо-прогон ${res.runId} создан (симуляция в браузере; backend не задействован).`
          : mode === 'core' ? `Прогон ${res.runId} принят ядром SecurityLab.` : `Прогон ${res.runId} принят сервером симуляции (demo: true).`,
        'ok',
      )
      navigate(`/runs/${res.runId}`)
    } finally {
      setLaunching(false)
    }
  }, [adapter, formOk, preflight, preflightStale, formInput, bumpData, pushToast, navigate, mode])

  if (!projects || !policies || !configs) return <Skeleton lines={8} />

  const canLaunchReal = formOk && preflightReady(preflight) && !preflightStale
  const showSimulate = mode !== 'core' && formOk && !!preflight && !preflightReady(preflight) && !preflightStale

  return (
    <>
      <ScreenHead
        no="02 · Подготовка"
        title="Новый запуск"
        meta={
          <>
            Проверка выполняется на зафиксированном снимке: снимок → сервис/entry из набора проекта → политика →
            AI-конфигурация → предпроверка → запуск. Политика редактируется оператором вне интерфейса.
          </>
        }
      />

      {active.run && (
        <div className="mb-7">
          <Note tone="warn" title={`Активный прогон: ${active.run.id}`}>
            Очередь фоновых заданий не реализована — разрешён один активный запуск, второй отклонит сервер.
            {active.error && ' Проверка списка активных прогонов не удалась (ошибка связи) — сервер может отклонить запуск.'}
          </Note>
        </div>
      )}

      <div className="space-y-5">
        {/* 01 · проект, снимок и state-каталог */}
        <Step no="01" title="Проект, снимок и state-каталог">
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Проект" error={attempted ? errors.project : undefined}>
              <Select
                value={projectId}
                onChange={(e) => {
                  setProjectId(e.target.value)
                  setSnapshotId('')
                  setService('')
                  setEntry('')
                  setPreflight(null)
                }}
              >
                <option value="">— выберите —</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name} · {p.stack}</option>
                ))}
              </Select>
            </Field>
            <Field
              label="Снимок"
              hint={project ? `Зафиксировано: ${project.snapshots.length}` : 'снимок появляется после фиксации через backend'}
              error={attempted ? errors.snapshot : undefined}
            >
              <Select value={snapshotId} onChange={(e) => { setSnapshotId(e.target.value); setPreflight(null) }} disabled={!project}>
                <option value="">— выберите —</option>
                {project?.snapshots.map((s) => (
                  <option key={s.id} value={s.id}>{s.id} · снимок {s.commit} · {fmtDateTime(s.createdAt)}</option>
                ))}
              </Select>
            </Field>
            <Field label="State-каталог ядра" hint="используется ядром SecurityLab при прогоне">
              <TextInput value={stateDir || (project ? '— не задан проектом —' : '— выберите проект —')} readOnly aria-label="State-каталог ядра" />
            </Field>
          </div>
        </Step>

        {/* 02 · сервис и точка входа — из набора проекта (#3) */}
        <Step no="02" title="Сервис и точка входа">
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Сервис" hint="из набора, принятого по снимку проекта" error={attempted ? errors.service : undefined}>
              <Select value={service} onChange={(e) => {
                setService(e.target.value)
                // точка входа подставляется из выбранного сервиса
                const svc = entries.find((x) => x.service === e.target.value)
                setEntry(svc ? svc.entryFile : '')
                setPreflight(null)
              }} disabled={!project}>
                <option value="">— выберите —</option>
                {[...new Set(entries.map((s) => s.service))].map((value) => <option key={value} value={value}>{value === '.' ? '. (корень репозитория)' : value}</option>)}
              </Select>
            </Field>
            <Field
              label="Точка входа"
              hint="путь файла (app/main.py) либо ASGI import string (app.main:app); преобразование выполняет backend"
              error={attempted ? errors.entry : undefined}
            >
              <Select value={entry} onChange={(e) => { setEntry(e.target.value); setPreflight(null) }} disabled={entries.length === 0}>
                <option value="">— выберите —</option>
                {entries.flatMap((s) => [s.entryFile, s.entryImport !== s.entryFile ? s.entryImport : null]
                  .filter((v): v is string => !!v)
                  .map((v) => <option key={v} value={v}>{v}</option>))}
              </Select>
            </Field>
          </div>
          {entries.length === 0 && project && (
            <p className="mt-3 text-[12.5px] text-ink3">
              Набор сервисов/точек входа для проекта пуст — его заполняет backend по принятому снимку.
            </p>
          )}
        </Step>

        {/* 03 · профиль и политика (только чтение) */}
        <Step no="03" title="Профиль и политика · только чтение">
          <div className="grid gap-5 sm:grid-cols-[1fr_1.6fr]">
            <Field label="Профиль проверки" hint="определяется стеком проекта">
              <TextInput value={project ? project.profile : '— выберите проект —'} readOnly aria-label="Профиль проверки" />
            </Field>
            <Field label="Политика" hint="редактируется оператором вне UI" error={attempted ? errors.policy : undefined}>
              <Select value={policyId} onChange={(e) => { setPolicyId(e.target.value); setPreflight(null) }}>
                <option value="">— выберите —</option>
                {policies.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </Select>
            </Field>
          </div>
          {policy && (
            <div className="mt-5 rounded-field bg-dim px-4 py-4">
              <dl className="grid gap-x-10 gap-y-1.5 text-[13.5px] sm:grid-cols-2">
                <div><dt className="text-ink3">Область</dt><dd className="font-semibold">{policy.scope}</dd></div>
                <div><dt className="text-ink3">Контрольных случаев</dt><dd className="font-semibold">{policy.casesCount}</dd></div>
              </dl>
              <p className="mt-2.5 max-w-2xl text-[13px] leading-relaxed text-ink2">{policy.subjects}</p>
              <ul className="mt-3 max-w-2xl list-none space-y-1.5 text-[13px] text-ink2">
                {policy.restrictions.map((r) => (
                  <li key={r} className="flex gap-2.5"><span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true" />{r}</li>
                ))}
              </ul>
            </div>
          )}
        </Step>

        {/* 04 · AI-конфигурация (#4): выбор сохраняется и применяется к новым запускам */}
        <Step no="04" title="AI-конфигурация">
          <div className="grid gap-5 sm:grid-cols-[1fr_1.6fr]">
            <Field label="Конфигурация" hint="выбор сохраняется и действует на новые запуски; текущий прогон сохраняет свою" error={attempted ? errors.ai : undefined}>
              <Select value={aiConfigId} onChange={(e) => { setAiConfigId(e.target.value); setSelectedAiConfigId(e.target.value); setPreflight(null) }}>
                <option value="">— выберите —</option>
                {configs.map((c) => (
                  <option key={c.id} value={c.id}>{c.name} · {c.model}{c.present === null ? ' (наличие не проверено)' : c.present ? '' : ' (нет на сервере)'}</option>
                ))}
              </Select>
            </Field>
            {aiConfig && (
              <div className="rounded-field bg-dim px-4 py-3">
                <NumRow k="Модель" v={aiConfig.model} mono />
                <NumRow k="digest (фиксируется, полный 64 hex)" v={aiConfig.digest} mono />
                <NumRow k="Сервер" v={aiConfig.server} mono />
                <NumRow k="Сеть" v={aiConfig.network} mono />
                <NumRow k="Контекст" v={`${aiConfig.contextTokens.toLocaleString('ru-RU')} токенов (минимум Hermes — 64 000)`} />
                <NumRow k="Лимит ответа" v={`${aiConfig.maxOutputTokens.toLocaleString('ru-RU')} токенов`} />
                <NumRow k="Тайм-аут вызова" v={`${aiConfig.timeoutSeconds} с`} />
              </div>
            )}
          </div>
        </Step>

        {/* 05 · предпроверка */}
        <Step
          no="05"
          title="Предпроверка готовности"
          aside={
            <Button variant="secondary" onClick={runPreflight} disabled={!formOk || preflightBusy} title={formOk ? '' : 'заполните разделы выше'}>
              {preflightBusy ? 'Проверяем…' : preflight ? 'Повторить предпроверку' : 'Выполнить предпроверку'}
            </Button>
          }
        >
          <div className="overflow-hidden rounded-field">
            {PREFLIGHT_KEYS.map((k) => {
              const row = preflight ? preflight[k] : 'untested'
              const detail = preflight ? preflight[`${k}Detail` as 'dockerDetail' | 'imagesDetail' | 'modelDetail'] : undefined
              const label = k === 'docker' ? 'Docker на хосте' : k === 'images' ? 'Образы профиля' : 'Адрес модели'
              return (
                <div key={k} className="flex flex-wrap items-center justify-between gap-x-6 gap-y-1.5 border-b border-line bg-dim px-4 py-3 last:border-b-0">
                  <span className="text-[14px] font-semibold">{label}</span>
                  <span className="flex items-center gap-3">
                    {detail && <span className="max-w-xl text-[12.5px] leading-snug text-ink3">{detail}</span>}
                    <PreflightChip v={row} />
                  </span>
                </div>
              )
            })}
          </div>
          {preflightErr && (
            <div className="mt-4 max-w-2xl">
              <Note tone="warn" title="Предпроверка не выполнена — ошибка связи:">{preflightErr}</Note>
            </div>
          )}
          {preflight && (
            <p className="mt-3 font-mono text-[11px] text-ink3">
              проверено: {fmtDateTime(preflight.checkedAt ?? '')}
              {preflightStale && ' · параметры формы изменились — предпроверка недействительна, повторите'}
            </p>
          )}
          {attempted && !formOk && (
            <p className="mt-3 text-[12.5px] font-semibold text-dangerink">Предпроверка станет доступна после заполнения разделов 01–04.</p>
          )}
        </Step>

        {/* 06 · сводка и запуск */}
        <Step no="06" title="Сводка и запуск">
          <div className="grid gap-x-12 sm:grid-cols-2">
            <div className="divide-y divide-line">
              <NumRow k="Проект" v={project?.name ?? '—'} />
              <NumRow k="Снимок" v={snapshotId || '—'} mono />
              <NumRow k="Сервис / entry" v={service && entry ? `${service} · ${entry}` : '—'} mono />
              <NumRow k="State-каталог" v={stateDir || '—'} mono />
            </div>
            <div className="divide-y divide-line">
              <NumRow k="Политика" v={policy ? `${policy.name} · ${policy.casesCount} случаев` : '—'} />
              <NumRow k="AI-конфигурация" v={aiConfig ? `${aiConfig.model}` : '—'} mono />
              <NumRow k="Предпроверка" v={preflight ? (preflightStale ? 'устарела — повторите' : preflightReady(preflight) ? 'все проверки пройдены' : 'есть ошибки — запуск невозможен') : 'не выполнена'} />
            </div>
          </div>

          {launchRefusal && (
            <div className="mt-5 max-w-3xl">
              <Note tone="warn" title="Запуск отклонён сервером:">{launchRefusal}</Note>
            </div>
          )}

          <div className="mt-7 flex flex-wrap items-center gap-4">
            <Button variant="primary" icon="play" onClick={launch} disabled={!canLaunchReal || launching} title={canLaunchReal ? '' : 'нужна предпроверка со всеми проверками «проверен»'}>
              {launching ? 'Создаём…' : 'Запустить проверку'}
            </Button>
            {showSimulate && (
              <SimulateButton
                formInput={formInput}
                onDone={(runId, where) => {
                  bumpData()
                  pushToast(
                    where === 'browser'
                      ? `Симуляция ${runId} запущена в браузере без реального стенда (предпроверка выявила неготовность).`
                      : `Прогон ${runId} принят сервером симуляции без реального стенда (demo: true).`,
                    'ok',
                  )
                  navigate(`/runs/${runId}`)
                }}
              />
            )}
            <span className="max-w-md text-[12.5px] leading-snug text-ink3">
              параметры выше фиксируются в отчёте прогона
              {mode === 'demo' ? '; деморежим создаёт симуляцию с пометкой «демо»' : '; сервер симуляции помечает прогоны demo: true'}
            </span>
          </div>
        </Step>
      </div>
    </>
  )
}

/** Отдельное действие «Запустить симуляцию» (#6): разрешено при неготовности
    стенда, но не выдаёт готовность. Симуляция создаётся там же, где читаются
    данные: в деморежиме — в браузере, в HTTP-режиме — на сервере симуляции
    (demo: true), чтобы прогон был виден и отменяем, а не «в невидимом кармане». */
function SimulateButton({ formInput, onDone }: { formInput: NewRunInput; onDone: (runId: string, where: 'browser' | 'server') => void }) {
  const [busy, setBusy] = useState(false)
  const { adapter, mode, pushToast } = useStore()
  const run = async () => {
    setBusy(true)
    try {
      const res = await adapter.createRun(formInput)
      if ('ok' in res) {
        pushToast(res.reason, 'error')
        return
      }
      onDone(res.runId, mode === 'demo' ? 'browser' : 'server')
    } finally {
      setBusy(false)
    }
  }
  return (
    <Button variant="secondary" onClick={run} disabled={busy}>
      {busy ? 'Создаём…' : mode === 'demo' ? 'Запустить симуляцию в браузере' : 'Запустить симуляцию (без реального стенда)'}
    </Button>
  )
}
