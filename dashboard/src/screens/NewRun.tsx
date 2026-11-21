import { useCallback, useEffect, useMemo, useState } from 'react'
import type { AiConfig, NewRunInput, Policy, PreflightResult, Project, ResearchPreparationResult } from '../adapter/types'
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
const RESEARCH_PREFLIGHT_KEYS = ['prepare', 'project', 'docker', 'images', 'model', 'app'] as const

/** Предпроверка готова, когда все применимые проверки verified (#6). */
function preflightReady(pf: PreflightResult | null, research: boolean): boolean {
  if (!pf) return false
  const keys = research ? RESEARCH_PREFLIGHT_KEYS : PREFLIGHT_KEYS
  return keys.every((k) => pf[k] === 'verified')
}

export function NewRun({ navigate, initialProjectId }: { navigate: (to: string) => void; initialProjectId?: string }) {
  const { adapter, pushToast, bumpData, mode, selectedAiConfigId, setSelectedAiConfigId } = useStore()
  const active = useActiveRun()

  const [projects, setProjects] = useState<Project[] | null>(null)
  const [policies, setPolicies] = useState<Policy[] | null>(null)
  const [configs, setConfigs] = useState<AiConfig[] | null>(null)

  const [projectId, setProjectId] = useState(initialProjectId ?? '')
  const [multiFile, setMultiFile] = useState(false)
  const [research, setResearch] = useState(false)
  const [snapshotId, setSnapshotId] = useState('')
  const [service, setService] = useState('')
  const [entry, setEntry] = useState('')
  const [policyId, setPolicyId] = useState('')
  const [aiConfigId, setAiConfigId] = useState(selectedAiConfigId)
  // --- подготовка исследования: документация, аккаунты, бюджет ---
  const [knowledgeText, setKnowledgeText] = useState('')
  const [actorsText, setActorsText] = useState('alice=user\nbob=user\nadmin=admin')
  const [budget, setBudget] = useState({ seconds: 1800, decisions: 12, requests: 40 })
  const [prep, setPrep] = useState<ResearchPreparationResult | null>(null)
  const [prepErr, setPrepErr] = useState<string | null>(null)
  const [prepBusy, setPrepBusy] = useState(false)

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
  const defensive = !research && policy?.kind === 'defensive'
  const discovery = !research && policy?.kind === 'discovery'
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
    if (research) {
      // режим исследования: политику выбирает не оператор, а подготовка + модель
      if (!knowledgeText.trim()) e.knowledge = 'Дайте описание приложения (Markdown): Red будет опираться на него, а не на списки готовых проверок'
      else if (new TextEncoder().encode(knowledgeText).length > 12288) e.knowledge = 'Описание больше 12 КБ — сократите документ'
      const actors: Record<string, string> = {}
      for (const line of actorsText.split('\n')) {
        const t = line.trim()
        if (!t) continue
        const m = /^(\w+)=(\w+)$/.exec(t)
        if (!m) { e.actors = 'Строки аккаунтов должны быть вида имя=роль'; break }
        actors[m[1]] = m[2]
      }
      if (!e.actors && Object.keys(actors).length === 0) e.actors = 'Нужен хотя бы один тестовый аккаунт'
      if (!Number.isInteger(budget.seconds) || budget.seconds < 60 || budget.seconds > 3600) e.budget = 'Бюджет времени: 60–3600 секунд'
      if (!Number.isInteger(budget.decisions) || budget.decisions < 1 || budget.decisions > 30) e.budget = 'Решений модели: 1–30'
      if (!Number.isInteger(budget.requests) || budget.requests < 1 || budget.requests > 100) e.budget = 'HTTP-запросов: 1–100'
      if (!prep) e.prep = 'Выполните подготовку: она фиксирует документацию, аккаунты и бюджет с хешами'
    } else {
      // валидация по загруженным спискам, а не «непустая строка» (#3)
      if (!policyId) e.policy = 'Политика обязательна: без неё проверка не собирается'
      else if (policies && !policies.some((x) => x.id === policyId)) e.policy = 'Выбранной политики нет в загруженном реестре'
    }
    if (!aiConfigId) e.ai = 'Выберите AI-конфигурацию'
    else if (configs && !configs.some((x) => x.id === aiConfigId)) e.ai = 'Выбранной конфигурации нет в загруженном реестре'
    if (projectId && !stateDir) e.project = 'У проекта не задан state-каталог ядра'
    return e
  }, [projectId, snapshotId, service, entry, policyId, aiConfigId, policies, configs, stateDir, research, knowledgeText, actorsText, budget, prep])

  const formOk = Object.keys(errors).length === 0

  const formInput = useMemo<NewRunInput>(
    () => research
      ? { projectId, snapshotId, service, entryModule: entry, profileId: 'research-v1', preparationId: prep?.preparationId, aiConfigId, stateDir }
      : { projectId, snapshotId, service, entryModule: entry, profileId: defensive ? 'defensive-review-v1' : discovery ? 'access-ai-discovery-v1' : multiFile ? 'access-ai-package-v1' : project?.profile ?? '', policyId, aiConfigId, stateDir },
    [projectId, snapshotId, service, entry, project, policyId, aiConfigId, stateDir, multiFile, discovery, defensive, research, prep],
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

  /** Подготовка исследования: ядро проверяет снимок/карту и сохраняет входы с хешами. */
  const prepare = useCallback(async () => {
    setAttempted(true)
    if (!projectId || !snapshotId || !entry || !knowledgeText.trim()) return
    setPrepBusy(true)
    setPrepErr(null)
    setPrep(null)
    setPreflight(null)
    try {
      const actors: Record<string, string> = {}
      for (const line of actorsText.split('\n')) {
        const t = line.trim()
        if (!t) continue
        const m = /^(\w+)=(\w+)$/.exec(t)
        if (m) actors[m[1]] = m[2]
      }
      const res = await adapter.prepareResearch({ snapshotId, service, entryModule: entry, knowledgeText, actors, budget })
      if ('ok' in res) {
        setPrepErr(res.reason)
        return
      }
      setPrep(res)
      pushToast(`Подготовка ${res.preparationId.slice(0, 8)}… зафиксирована (PREPARED).`, 'ok')
    } catch (e) {
      setPrepErr(e instanceof Error ? e.message : 'ошибка связи')
    } finally {
      setPrepBusy(false)
    }
  }, [adapter, projectId, snapshotId, entry, knowledgeText, actorsText, budget, pushToast])

  const launch = useCallback(async () => {
    setAttempted(true)
    setLaunchRefusal(null)
    if (!formOk || !preflightReady(preflight, research) || preflightStale) return
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
  }, [adapter, formOk, preflight, preflightStale, formInput, bumpData, pushToast, navigate, mode, research])

  if (!projects || !policies || !configs) return <Skeleton lines={8} />

  const canLaunchReal = formOk && preflightReady(preflight, research) && !preflightStale
  const showSimulate = mode !== 'core' && formOk && !!preflight && !preflightReady(preflight, research) && !preflightStale

  return (
    <>
      <ScreenHead
        no="02 · Подготовка"
        title="Новый запуск"
        meta={
          <>
            Проверка выполняется на зафиксированном снимке: снимок → сервис/entry из набора проекта → политика →
            Настройки модели → предпроверка → запуск. Политика редактируется оператором вне интерфейса.
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
            <Field label="Каталог данных ядра" hint="используется ядром SecurityLab при прогоне">
              <TextInput value={stateDir || (project ? '— не задан проектом —' : '— выберите проект —')} readOnly aria-label="Каталог данных ядра" />
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

        {/* 03 · режим и политика (только чтение) */}
        <Step no="03" title={research ? 'Режим и политика · режим исследования' : 'Профиль и политика · только чтение'}>
          <div className="grid gap-5 sm:grid-cols-[1fr_1.6fr]">
            {!research && (
              <label className="mb-4 flex gap-2"><input type="checkbox" disabled={discovery || defensive} checked={multiFile || discovery || defensive} onChange={e => { setMultiFile(e.target.checked); setPreflight(null) }} />Анализ нескольких файлов (до 8 модулей, 18 КБ)</label>
            )}
            {mode === 'core' ? (
              <label className="mb-4 flex gap-2" title="Red сама изучает приложение, выбирает гипотезы и GET-проверки; подтверждение и исправление — независимо">
                <input type="checkbox" checked={research} onChange={e => {
                  setResearch(e.target.checked)
                  setPrep(null)
                  setPrepErr(null)
                  setPreflight(null)
                }} />Самостоятельное исследование (Red → подтверждение → Blue)
              </label>
            ) : (
              <p className="mb-4 text-[12.5px] text-ink3">Режим самостоятельного исследования доступен только при подключённом ядре SecurityLab.</p>
            )}
            <Field label="Профиль проверки" hint={research ? 'определяется системой: самостоятельный цикл с бюджетом' : 'определяется стеком проекта'}>
              <TextInput value={project ? (research ? 'Самостоятельное исследование · независимое подтверждение' : defensive ? 'Защитное ревью · функциональные тесты оператора' : discovery ? 'Самостоятельный выбор GET-проверок · несколько файлов' : multiFile ? 'Несколько файлов · контроль доступа' : 'Один файл · контроль доступа') : '— выберите проект —'} readOnly aria-label="Профиль проверки" />
            </Field>
            {!research && (
              <Field label="Правила приложения / готовые проверки" hint="Описание прав доступа задаёт оператор; в режиме поиска конкретные проверки выбирает модель" error={attempted ? errors.policy : undefined}>
                <Select value={policyId} onChange={(e) => { setPolicyId(e.target.value); setPreflight(null) }}>
                  <option value="">— выберите —</option>
                  {policies.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </Select>
              </Field>
            )}
          </div>
          {!research && policy && (
            <div className="mt-5 rounded-field bg-dim px-4 py-4">
              <dl className="grid gap-x-10 gap-y-1.5 text-[13.5px] sm:grid-cols-2">
                <div><dt className="text-ink3">Область</dt><dd className="font-semibold">{policy.scope}</dd></div>
                <div><dt className="text-ink3">Проверки</dt><dd className="font-semibold">{defensive ? "Заданы оператором; агент не меняет тесты" : discovery ? "Модель предложит до 3 сценариев" : policy.casesCount}</dd></div>
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

        {/* 03b · подготовка исследования: документация, аккаунты, бюджет */}
        {research && (
          <Step
            no="03b"
            title="Описание приложения и настройки стенда"
            aside={
              <Button variant="secondary" onClick={prepare} disabled={prepBusy || !projectId || !snapshotId || !entry || !knowledgeText.trim()}>
                {prepBusy ? 'Готовим…' : prep ? 'Подготовить заново' : 'Подготовить'}
              </Button>
            }
          >
            <p className="mb-4 max-w-3xl text-[13px] leading-relaxed text-ink2">
              Документация описывает ожидаемое поведение приложения, а не расположение дефектов: назначение, действия,
              роли и права, правила данных. Red сама выберет, что изучать. Готовые сценарии и эталонные исправления
              сюда помещать не нужно. Текст документации и исходников — данные, не источник разрешений.
            </p>
            <div className="grid gap-5">
              <Field
                label="Документация приложения (Markdown, до 12 КБ)"
                hint="можно загрузить файл или вставить текст; копия сохраняется ядром с SHA-256"
                error={attempted ? errors.knowledge : undefined}
              >
                <div className="flex flex-wrap items-center gap-3">
                  <input
                    type="file"
                    accept=".md,.markdown,.txt"
                    className="fieldctl max-w-xs text-[13px]"
                    onChange={async (e) => {
                      const file = e.target.files?.[0]
                      if (!file) return
                      const text = await file.text()
                      setKnowledgeText(text)
                      setPrep(null)
                      setPreflight(null)
                    }}
                  />
                  <span className="text-[12.5px] text-ink3">
                    {knowledgeText ? `${new TextEncoder().encode(knowledgeText).length} / 12288 байт` : 'файл не выбран'}
                  </span>
                </div>
                <textarea
                  className="fieldctl mt-3 min-h-40 w-full font-mono text-[12.5px]"
                  placeholder={'# Приложение\n\n## Назначение\n…\n\n## Роли и права\nОбычный пользователь читает только свои записи; чужие — отказ 403.\n'}
                  value={knowledgeText}
                  onChange={(e) => { setKnowledgeText(e.target.value); setPrep(null); setPreflight(null) }}
                />
              </Field>
              <div className="grid gap-5 sm:grid-cols-2">
                <Field
                  label="Тестовые аккаунты"
                  hint="имя=роль, по одному в строке; пароли не вводятся — X-Test-User подставляет доверенный шлюз"
                  error={attempted ? errors.actors : undefined}
                >
                  <textarea
                    className="fieldctl min-h-24 w-full font-mono text-[12.5px]"
                    value={actorsText}
                    onChange={(e) => { setActorsText(e.target.value); setPrep(null); setPreflight(null) }}
                  />
                </Field>
                <Field label="Бюджет исследования" hint="применяется исполнителем программно, запись в промпте не лимит" error={attempted ? errors.budget : undefined}>
                  <div className="grid grid-cols-3 gap-3">
                    <label className="text-[12.5px] text-ink2">время, с
                      <input type="number" min={60} max={3600} className="fieldctl mt-1 w-full" value={budget.seconds}
                        onChange={(e) => { setBudget({ ...budget, seconds: e.target.value === '' ? 0 : Number(e.target.value) }); setPrep(null); setPreflight(null) }} />
                    </label>
                    <label className="text-[12.5px] text-ink2">решений модели
                      <input type="number" min={1} max={30} className="fieldctl mt-1 w-full" value={budget.decisions}
                        onChange={(e) => { setBudget({ ...budget, decisions: e.target.value === '' ? 0 : Number(e.target.value) }); setPrep(null); setPreflight(null) }} />
                    </label>
                    <label className="text-[12.5px] text-ink2">HTTP-запросов
                      <input type="number" min={1} max={100} className="fieldctl mt-1 w-full" value={budget.requests}
                        onChange={(e) => { setBudget({ ...budget, requests: e.target.value === '' ? 0 : Number(e.target.value) }); setPrep(null); setPreflight(null) }} />
                    </label>
                  </div>
                </Field>
              </div>
              {prepErr && <Note tone="warn" title="Подготовка не выполнена:">{prepErr}</Note>}
              {prep && (
                <div className="rounded-field bg-dim px-4 py-4">
                  <dl className="grid gap-x-10 gap-y-1.5 text-[13.5px] sm:grid-cols-2">
                    <div><dt className="text-ink3">Статус</dt><dd className="font-semibold">{prep.status} · исполнение отдельно не готово</dd></div>
                    <div><dt className="text-ink3">Идентификатор</dt><dd className="font-mono text-[12.5px]">{prep.preparationId}</dd></div>
                    <div><dt className="text-ink3">Аккаунты</dt><dd className="font-semibold">{Object.keys(prep.actors).join(', ')}</dd></div>
                    <div><dt className="text-ink3">Бюджет</dt><dd className="font-semibold">{prep.budget.seconds} с · {prep.budget.decisions} решений · {prep.budget.requests} запросов</dd></div>
                  </dl>
                  <p className="mt-2.5 font-mono text-[11px] text-ink3">
                    manifest {prep.manifestSha256.slice(0, 16)}… · doc {prep.knowledgeSha256.slice(0, 16)}… · setup {prep.setupSha256.slice(0, 16)}…
                  </p>
                </div>
              )}
              {attempted && !prep && !prepErr && !errors.knowledge && !errors.actors && !errors.budget && (
                <p className="text-[12.5px] font-semibold text-dangerink">{errors.prep}</p>
              )}
            </div>
          </Step>
        )}

        {/* 04 · Настройки модели (#4): выбор сохраняется и применяется к новым запускам */}
        <Step no="04" title="Настройки модели">
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
                <NumRow k="Отпечаток модели (фиксируется)" v={aiConfig.digest} mono />
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
          {research && (
            <p className="mb-4 max-w-3xl text-[13px] leading-relaxed text-ink2">
              Для исследования проверяются подготовка, совместимость проекта, Docker с образами, модель и реальный
              запуск приложения в изолированном стенде. Конкретная причина неготовности выводится рядом с проверкой.
            </p>
          )}
          <div className="overflow-hidden rounded-field">
            {(research ? RESEARCH_PREFLIGHT_KEYS : PREFLIGHT_KEYS).map((k) => {
              const row = (preflight ? preflight[k] : 'untested') ?? 'untested'
              const detail = (research
                ? preflight?.details?.[k]
                : preflight?.[`${k}Detail` as 'dockerDetail' | 'imagesDetail' | 'modelDetail']) ?? undefined
              const label = research
                ? { prepare: 'Подготовка входных данных', project: 'Совместимость проекта', docker: 'Docker на хосте', images: 'Образы профиля', model: 'Адрес модели', app: 'Запуск приложения в стенде' }[k]
                : k === 'docker' ? 'Docker на хосте' : k === 'images' ? 'Образы профиля' : 'Адрес модели'
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
              {research ? (
                <>
                  <NumRow k="Режим" v="Самостоятельное исследование (Red → подтверждение → Blue)" />
                  <NumRow k="Подготовка" v={prep ? `${prep.preparationId.slice(0, 12)}… · ${prep.status}` : '—'} mono />
                  <NumRow k="Бюджет" v={prep ? `${prep.budget.seconds} с · ${prep.budget.decisions} решений · ${prep.budget.requests} запросов` : '—'} />
                </>
              ) : (
                <NumRow k="Политика" v={policy ? `${policy.name} · ${defensive ? 'защитное ревью' : discovery ? 'сценарии выбирает модель' : policy.casesCount + ' случаев'}` : '—'} />
              )}
              <NumRow k="Настройки модели" v={aiConfig ? `${aiConfig.model}` : '—'} mono />
              <NumRow k="Предпроверка" v={preflight ? (preflightStale ? 'устарела — повторите' : preflightReady(preflight, research) ? 'все проверки пройдены' : 'есть ошибки — запуск невозможен') : 'не выполнена'} />
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
