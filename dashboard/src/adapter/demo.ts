import type {
  Artifact,
  BackendRefusal,
  Diagnostics,
  Policy,
  PreflightResult,
  Project,
  ResearchPreparationInput,
  ResearchPreparationResult,
  Run,
  SecurityLabAdapter,
  AiConfig,
  NewRunInput,
  Snapshot,
  RunFilters,
} from './types'
import { aiConfigs, demoRuns, FIX_DIFF, newRunScript, policies, projects } from './demoData'

const STORE_KEY = 'slb.demoRuns.v1'
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms))

/* ---------- симуляция активного демо-прогона ---------- */

export function runElapsedSec(run: Run, nowMs: number): number {
  return Math.max(0, (nowMs - Date.parse(run.startedAt)) / 1000)
}

/** Прогон активен, пока сценарий симуляции не дошёл до финала. */
export function isRunActive(run: Run, nowMs: number): number {
  if (!run.script) return false
  return runElapsedSec(run, nowMs) < run.script.finishAt
}

/** Чистая функция: разворачивает сценарий симуляции на момент nowMs.
    Перезагрузка страницы продолжает прогон, а не запускает его заново. */
export function resolveLiveRun(run: Run, nowMs: number): Run {
  if (!run.script) return run
  const elapsed = runElapsedSec(run, nowMs)
  const s = run.script
  const finished = elapsed >= s.finishAt
  const stages = s.stages.map((st) => {
    if (elapsed >= (st.to ?? s.finishAt)) {
      return { id: st.id, label: st.label, role: st.role, state: st.state === 'wait_model' ? 'done' : st.state, startedAt: st.from, finishedAt: st.to, detail: st.detail }
    }
    if (elapsed >= st.from) {
      const waiting = st.waitModelFrom !== undefined && elapsed >= st.waitModelFrom
      return { id: st.id, label: st.label, role: st.role, state: waiting ? ('wait_model' as const) : ('running' as const), startedAt: st.from, detail: waiting ? 'ожидаем ответ — событий нет; процент готовности не показывается' : undefined }
    }
    return { id: st.id, label: st.label, role: st.role, state: 'pending' as const }
  })
  return {
    ...run,
    exec: finished ? s.final.exec : 'running',
    verdict: finished ? s.final.verdict : 'NOT_EVALUATED',
    finding: finished ? s.final.finding : 'NOT_EVALUATED',
    finishedAt: finished ? new Date(Date.parse(run.startedAt) + s.finishAt * 1000).toISOString() : undefined,
    stages,
    events: s.events.filter((e) => e.t <= elapsed),
    checks: finished ? run.checks : [],
    attempts: finished ? run.attempts : [],
    redProposal: finished ? run.redProposal : undefined,
    commit: finished ? run.commit : undefined,
  }
}

/* ---------- хранилище созданных пользователем демо-прогонов ---------- */

function loadCreated(): Run[] {
  try {
    const raw = localStorage.getItem(STORE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as Run[]
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function saveCreated(runs: Run[]) {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(runs))
  } catch {
    /* без localStorage демо-прогоны живут только до перезагрузки */
  }
}

function buildDemoRun(input: NewRunInput): Run {
  const id = `run-dem-${Math.random().toString(16).slice(2, 6)}`
  const diff = FIX_DIFF
  return {
    id,
    demo: true,
    projectId: input.projectId,
    snapshotId: input.snapshotId,
    service: input.service,
    entryModule: input.entryModule,
    profileId: input.profileId,
    policyId: input.policyId ?? "",
    aiConfigId: input.aiConfigId,
    stateDir: input.stateDir,
    mode: 'ai_red_blue',
    startedAt: new Date().toISOString(),
    timeLimitMin: 20,
    exec: 'running',
    verdict: 'NOT_EVALUATED',
    finding: 'NOT_EVALUATED',
    stages: [],
    events: [],
    checks: [
      { id: 'c-1', scenario: 'Просмотр своего заказа', group: 'owner', actor: 'владелец (user-a)', method: 'GET', path: '/api/v1/orders/1037', expectStatus: 200, baseline: { http: 200, outcome: 'pass', bodyHashOk: true }, candidate: { http: 200, outcome: 'pass', bodyHashOk: true }, recheck: { http: 200, outcome: 'pass', bodyHashOk: true }, final: 'pass' },
      { id: 'c-2', scenario: 'Чужой заказ по возрастающему ID (S-2)', group: 'foreign', actor: 'авторизованный user-b', method: 'GET', path: '/api/v1/orders/1042', expectStatus: 403, baseline: { http: 200, outcome: 'fail', bodyHashOk: false, note: 'нарушение воспроизведено' }, candidate: { http: 403, outcome: 'pass', bodyHashOk: true }, recheck: { http: 403, outcome: 'pass', bodyHashOk: true }, final: 'pass' },
      { id: 'c-3', scenario: 'Анонимный доступ к списку', group: 'anon', actor: 'аноним', method: 'GET', path: '/api/v1/orders', expectStatus: 401, baseline: { http: 401, outcome: 'pass', bodyHashOk: true }, candidate: { http: 401, outcome: 'pass', bodyHashOk: true }, final: 'pass' },
      { id: 'c-4', scenario: 'Регрессия: владелец не потерял доступ', group: 'regress', actor: 'владелец (user-a)', method: 'GET', path: '/api/v1/orders/1037', expectStatus: 200, baseline: { http: 200, outcome: 'pass', bodyHashOk: true }, candidate: { http: 200, outcome: 'pass', bodyHashOk: true }, recheck: { http: 200, outcome: 'pass', bodyHashOk: true }, final: 'pass' },
    ],
    redProposal: {
      scenarioNo: 'S-2',
      summary: 'Чужой заказ по возрастающему ID: сервер отдаёт объект без проверки владельца.',
      method: 'GET',
      path: '/api/v1/orders/{id}',
      entry: 'app/orders.py · get_order',
      aiGenerated: true,
    },
    attempts: [{ n: 1, role: 'candidate', status: 'accepted', diff, rejectionReasons: [], checkSummary: 'независимая проверка: 4/4, совпадение тела/хеша подтверждено' }],
    commit: { ref: 'fix/slb-demo-s2', sha: '8e2f41c', isolated: true },
    artifacts: [
      { id: 'art-sum', name: 'summary.json', kind: 'json', present: true, content: `{\n  "run_id": "${id}",\n  "demo": true,\n  "security_verdict": "FIXED",\n  "finding_status": "FIXED"\n}` },
      { id: 'art-p1', name: 'candidate-1.patch', kind: 'patch', present: true, content: diff },
      { id: 'art-log', name: 'container.log', kind: 'log', present: false, absentReason: 'файл удалён при очистке контейнера после прогона — ожидаемое поведение очистки' },
    ],
    tech: {
      image: 'securitylab-demo:local',
      imageDigest: 'sha256:ab12f0…9c33',
      network: 'slb-internal (изолированная, без выхода в интернет)',
      configHash: 'sha256:1d44aa…b802',
      snapshotPin: `${input.snapshotId}`,
      cleanup: 'контейнеры и тома удалены по завершении прогона',
      hashDisclaimer: 'хеши — журнал целостности и привязки, не криптографическая подпись и не гарантия отсутствия всех уязвимостей.',
    },
    script: { ...newRunScript },
  }
}

/* ---------- DemoAdapter ---------- */

export class DemoAdapter implements SecurityLabAdapter {
  private created: Run[] = loadCreated()

  private allRuns(): Run[] {
    return [...this.created, ...demoRuns]
  }

  async listProjects(): Promise<Project[]> {
    await delay(350) // состояние загрузки показывается честно
    return projects
  }

  async getProject(id: string): Promise<Project | null> {
    await delay(150)
    return projects.find((p) => p.id === id) ?? null
  }

  async registerProject(_path: string): Promise<Project | BackendRefusal> {
    await delay(300)
    return {
      ok: false,
      reason:
        'Деморежим: регистрация проекта выполняет локальный backend (предлагаемый POST /api/projects) — только он может проверить путь на сервере. Выбор папки в браузере не выдаётся за серверный абсолютный путь, поэтому кнопка не имитирует добавление.',
    }
  }

  async createSnapshot(projectId: string): Promise<Snapshot | BackendRefusal> {
    await delay(300)
    return {
      ok: false,
      reason: `Деморежим: снимок создаёт backend (предлагаемый POST /api/projects/${projectId}/snapshots) через Git в изолированной копии. Создание снимка силами браузера было бы подделкой — операция отклонена.`,
    }
  }

  async deleteProject(_id: string): Promise<BackendRefusal> {
    await delay(250)
    return {
      ok: false,
      reason:
        'Деморежим: реестром проектов управляет локальный backend (DELETE /api/projects/{id}) — он удаляет запись, снимки проекта и их копии в state-каталоге. Браузер не стирает серверные данные, поэтому операция отклонена.',
    }
  }

  async listPolicies(): Promise<Policy[]> {
    await delay(200)
    return policies
  }

  async listAiConfigs(): Promise<AiConfig[]> {
    await delay(200)
    return aiConfigs
  }

  async validateAiConfig(id: string) {
    await delay(600)
    const cfg = aiConfigs.find((c) => c.id === id)
    return cfg
      ? { valid: true, detail: 'Структурная проверка записи конфигурации пройдена: модель, полный digest (64 hex), контекст, сеть и лимиты. Файл TOML в деморежиме не разбирается; валидность записи не означает, что модель доступна.' }
      : { valid: false, detail: 'конфигурация не найдена' }
  }

  async pingModel(id: string) {
    await delay(700)
    const cfg = aiConfigs.find((c) => c.id === id)
    if (!cfg) return { ok: false, detail: 'конфигурация не найдена' }
    // в демо-данных проверка не выполнялась — модельPing: null, ответ честный
    if (cfg.modelPing === 'ok') return { ok: true, detail: 'модель отвечает (проверка выполняется через Hermes в локальной сети)' }
    return { ok: false, detail: cfg.pingError ?? 'проверка доступности модели в деморежиме не выполнялась: TCP-пробой адреса hermes:11434 из браузера не подтверждает ни модель, ни digest' }
  }

  async preflight(input: NewRunInput): Promise<PreflightResult> {
    await delay(900)
    const cfg = aiConfigs.find((c) => c.id === input.aiConfigId)
    return {
      docker: 'verified',
      images: 'verified',
      model: cfg?.present ? 'verified' : 'error',
      dockerDetail: 'Демоданные: в браузере docker не проверяется; в референсном сервере выполняется docker version.',
      imagesDetail: 'образы профиля (securitylab-demo:local, securitylab-hermes:s4, securitylab-fastapi:local) отмечены присутствующими — демоданные',
      modelDetail: cfg?.present
        ? 'конфигурация присутствует в демо-наборе; доступность модели не проверялась из браузера'
        : (cfg?.pingError ?? 'модель недоступна'),
      checkedAt: new Date().toISOString(),
    }
  }

  async prepareResearch(_input: ResearchPreparationInput): Promise<ResearchPreparationResult | BackendRefusal> {
    await delay(300)
    return {
      ok: false,
      reason:
        'Деморежим: подготовка исследования выполняет ядро SecurityLab (POST /api/research/prepare) — оно проверяет снимок, статическую карту и сохраняет копии входных данных с хешами. Браузер не может этого выполнить, поэтому операция отклонена.',
    }
  }

  async listRuns(filters?: RunFilters): Promise<Run[]> {
    await delay(250)
    let runs = this.allRuns()
    const f = filters ?? {}
    if (f.projectId) runs = runs.filter((r) => r.projectId === f.projectId)
    if (f.status && f.status !== 'all') runs = runs.filter((r) => r.exec === f.status)
    if (f.mode && f.mode !== 'all') runs = runs.filter((r) => r.mode === f.mode)
    if (f.dateRange && f.dateRange !== 'all') {
      const cutoff = Date.now() - (f.dateRange === '24h' ? 864e5 : 7 * 864e5)
      runs = runs.filter((r) => Date.parse(r.startedAt) >= cutoff)
    }
    return runs.sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt))
  }

  async getRun(id: string): Promise<Run | null> {
    await delay(150)
    return this.allRuns().find((r) => r.id === id) ?? null
  }

  async createRun(input: NewRunInput): Promise<{ runId: string } | BackendRefusal> {
    await delay(400)
    const now = Date.now()
    const active = [...this.created].find((r) => isRunActive(r, now))
    if (active) {
      return {
        ok: false,
        reason: `Активный прогон уже выполняется (${active.id}). Очередь фоновых заданий не реализована — до её реализации разрешён один активный запуск, второй отклоняется честным отказом, а не ставится в невидимую очередь.`,
      }
    }
    const run = buildDemoRun(input)
    this.created = [run, ...this.created]
    saveCreated(this.created)
    return { runId: run.id }
  }

  async cancelRun(_id: string): Promise<BackendRefusal> {
    await delay(250)
    return {
      ok: false,
      reason:
        'Отмена в деморежиме не выполняется: браузер не запускал прогон. Подключите референсный сервер (npm run serve:api) — там отмена подтверждается состоянием; в ядре SecurityLab операция отмены требует реализации.',
    }
  }

  async exportPatch(runId: string): Promise<{ fileName: string; content: string } | BackendRefusal> {
    await delay(300)
    const run = this.allRuns().find((r) => r.id === runId)
    if (!run) return { ok: false, reason: 'прогон не найден' }
    if (!run.commit) {
      return {
        ok: false,
        reason: 'Подтверждённый отдельный коммит у прогона отсутствует — экспортировать нечего. Экспорт возможен только после независимой проверки патча и создания коммита.',
      }
    }
    const diff = run.attempts.find((a) => a.status === 'accepted')?.diff ?? ''
    return { fileName: `${run.id}-patch.patch`, content: diff }
  }

  async getArtifact(runId: string, artifactId: string): Promise<Artifact | BackendRefusal> {
    await delay(200)
    // traversal-защита: артефакты отдаются только по идентификаторам
    if (!/^[a-z0-9][a-z0-9-]*$/i.test(artifactId) || artifactId.includes('..') || artifactId.includes('/')) {
      return {
        ok: false,
        reason: 'Идентификатор артефакта отклонён (проверка traversal): пути не принимаются, артефакты отдаются по идентификаторам из контролируемых каталогов.',
      }
    }
    const run = this.allRuns().find((r) => r.id === runId)
    const art = run?.artifacts.find((a) => a.id === artifactId)
    if (!art) return { ok: false, reason: 'артефакт не найден в этом прогоне' }
    if (!art.present) return { ok: false, reason: art.absentReason ?? 'артефакт отсутствует' }
    return art
  }

  async diagnostics(): Promise<Diagnostics> {
    await delay(200)
    return {
      available: false,
      note: 'Метрики GPU/CPU/памяти появятся только из реально полученных данных backend-агента. Пока сбор не реализован, показывается «нет данных» вместо выдуманных значений.',
    }
  }

  async health(baseUrl: string) {
    const url = baseUrl.replace(/\/+$/, '') + '/api/health'
    try {
      const ctrl = new AbortController()
      const timer = setTimeout(() => ctrl.abort(), 4000)
      const res = await fetch(url, { signal: ctrl.signal, headers: { Accept: 'application/json' } })
      clearTimeout(timer)
      if (!res.ok) return { ok: false, detail: `backend ответил HTTP ${res.status}; остаёмся в текущем режиме`, httpStatus: res.status }
      return { ok: true, detail: 'backend отвечает; подключение выполнит HttpAdapter (см. экран «Интеграция»)', httpStatus: res.status }
    } catch (e) {
      return { ok: false, detail: `соединение не установлено (${e instanceof Error ? e.message : 'сетевая ошибка'}) — остаёмся в деморежиме, интерфейс не изображает серверные действия` }
    }
  }
}

/* ---------- HttpAdapter: заготовка под предложенные endpoint ---------- */

/**
 * Фактическая карта Python API S8.2. Не является обещанием универсального сканирования.
 */
export const ENDPOINTS = [
  { action: 'Список проектов и снимков', module: 'dashboard.py / projects.py / snapshots.py', endpoint: 'GET /api/projects', status: 'Работает', detail: 'Снимки входят в ответ; отдельного GET snapshots нет.' },
  { action: 'Регистрация проекта', module: 'projects.py', endpoint: 'POST /api/projects', status: 'Работает', detail: 'Регистрация локального пути без исполнения кода.' },
  { action: 'Создание снимка', module: 'snapshots.py', endpoint: 'POST /api/projects/{id}/snapshots', status: 'Работает', detail: 'Копирование допустимых файлов с фиксацией хешей.' },
  { action: 'Удаление проекта', module: 'dashboard.py / projects.py', endpoint: 'DELETE /api/projects/{id}', status: 'Работает', detail: 'Запись реестра, снимки проекта и их копии в state-каталоге удаляются; исходный код на диске и история прогонов не трогаются. Во время активного прогона отклоняется.' },
  { action: 'Политики', module: 'dashboard.py', endpoint: 'GET /api/policies', status: 'Работает', detail: 'Чтение внешних политик оператора.' },
  { action: 'AI-профили и выбор модели', module: 'dashboard_profiles.py / ai_config.py', endpoint: 'GET /api/ai-configs', status: 'Работает', detail: 'Выбранный профиль передаётся при создании запуска.' },
  { action: 'Валидация конфигурации', module: 'ai_config.py', endpoint: 'POST /api/ai-configs/{id}/validate', status: 'Работает', detail: 'Проверка параметров, без обращения к модели.' },
  { action: 'Наличие модели', module: 'dashboard.py / hermes_adapter.py', endpoint: 'POST /api/ai-configs/{id}/ping-model', status: 'Работает', detail: 'Проверяются имя и digest через /api/tags; генерация не проверяется.' },
  { action: 'Предпроверка', module: 'dashboard.py / http_runner.py', endpoint: 'POST /api/preflight', status: 'Работает', detail: 'Снимок, пакет, политика, Docker, образы, сеть и модель.' },
  { action: 'Создание запуска', module: 'dashboard.py / access_ai.py', endpoint: 'POST /api/runs → 202 + runId', status: 'Работает', detail: 'Один access-ai запуск; ограниченный FastAPI-профиль S7.2.' },
  { action: 'История запусков', module: 'dashboard.py / dashboard_dto.py', endpoint: 'GET /api/runs', status: 'Частично', detail: 'Подключена история access_ai; старые demo/candidate-check доступны через CLI.' },
  { action: 'Ход выполнения и события', module: 'dashboard.py / dashboard_dto.py', endpoint: 'GET /api/runs/{id}', status: 'Работает', detail: 'Опрос статуса и ключевых этапов; последние 200 событий, ожидание модели без фиктивного процента.' },
  { action: 'Отмена', module: 'dashboard.py', endpoint: 'POST /api/runs/{id}/cancel', status: 'Работает', detail: 'Только активный запуск текущего сервера. Сначала CANCEL_REQUESTED, затем STOPPED после проверки очистки; ошибка очистки → BLOCKED.' },
  { action: 'Diff каждой попытки Blue', module: '—', endpoint: 'GET /api/runs/{id}/attempts/{n}/diff', status: 'Работает', detail: 'Для кандидатов, созданных с S8.2: отдельный diff относительно исходного снимка, включая отклонённые предложения.' },
  { action: 'Артефакты', module: 'dashboard.py', endpoint: 'GET /api/runs/{id}/artifacts/{aid}', status: 'Работает', detail: 'Сохранённые файлы выбранного запуска, только текстовый просмотр.' },
  { action: 'Экспорт подтверждённого патча', module: 'dashboard.py / access_ai.py', endpoint: 'GET /api/runs/{id}/patch', status: 'Работает', detail: 'Только PASS с сохранённым Git diff; merge/push не выполняются.' },
  { action: 'Метрики CPU/RAM/GPU', module: 'dashboard.py', endpoint: 'GET /api/diagnostics', status: 'Заглушка', detail: 'Возвращает available:false; метрики не собираются.' },
  { action: 'Подключение и CSRF', module: 'dashboard.py', endpoint: 'GET /api/health; GET /api/csrf', status: 'Работает', detail: 'Loopback, проверка Host/Origin, CSRF-токен для POST.' },
] as const
