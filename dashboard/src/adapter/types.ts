/**
 * Типизированный контракт «UI ↔ SecurityLab backend».
 *
 * DemoAdapter обслуживает явный деморежим (браузер), HttpAdapter — референсный
 * сервер endpoint'ов (server/server.mjs, симуляция). Боевой backend заменяет
 * референсный сервер без изменения UI. Ничего из этого не выдаётся за ядро.
 */

/**
 * Статус выполнения. STOP-причины (blocked/timeout) живут здесь,
 * а не в security_verdict — по контракту ядра S7.4.
 */
export type ExecStatus = 'queued' | 'running' | 'completed' | 'failed' | 'blocked' | 'timeout' | 'cancelled'

/**
 * security_verdict ядра: было ли нарушение воспроизведено на baseline.
 * Неизвестные значения (после обновления ядра) DTO-слой переводит в 'UNKNOWN'
 * с сохранением исходной строки в verdictRaw — UI показывает нейтрально.
 */
export type Verdict = 'POLICY_VIOLATION_OBSERVED' | 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX' | 'REPRODUCED' | 'NOT_EVALUATED' | 'UNKNOWN'

/**
 * finding_status ядра: наблюдается ли нарушение политики на проверенном
 * исправлении. null — оценка не выполнялась (например, smoke или прогон,
 * остановленный до baseline). NEEDS_REVIEW — решение оператора. Неизвестные
 * значения → 'UNKNOWN' + findingRaw.
 */
export type Finding =
  | 'FIXED'
  | 'REPRODUCED'
  | 'POLICY_VIOLATION_OBSERVED'
  | 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX'
  | 'NEEDS_REVIEW'
  | 'NOT_EVALUATED'
  | 'UNKNOWN'
  | null

/** Состояние предпроверки: строго четыре значения, без частичных процентов. */
export type PreflightState = 'detected' | 'verified' | 'error' | 'untested'

export interface Snapshot {
  id: string
  commit: string
  createdAt: string // ISO
  note?: string
}

/** Точка входа сервиса проекта: путь файла и ASGI import string разделены. */
export interface ServiceEntry {
  service: string
  entryFile: string
  entryImport: string
}

export interface Project {
  id: string
  name: string
  /** Локальный путь на машине оператора; UI получает только строку от backend. */
  path: string
  stack: string
  profile: string
  supported: boolean
  unsupportedReason?: string
  snapshots: Snapshot[]
  lastRunId?: string
  /** Доступные сервисы/точки входа, известные backend по снимку/профилю. */
  services?: ServiceEntry[]
  /** state-каталог ядра (например, TEMP/SecurityLab_S72_DemoState). */
  stateDir?: string
}

/** Политика оператора — только чтение. Редактирование вне UI. */
export interface Policy {
  kind?: 'fixed' | 'discovery' | 'defensive'
  id: string
  name: string
  version: string
  scope: string
  casesCount: number
  subjects: string
  restrictions: string[]
}

export interface AiConfig {
  id: string
  name: string
  model: string
  digest: string
  server: string // внутренний адрес Ollama-совместимого сервера
  network: string
  contextTokens: number // минимум для текущего Hermes — 64000
  maxOutputTokens: number
  timeoutSeconds: number
  /** Результаты проверок живут отдельно: null — «не проверялся». */
  configValid: boolean | null
  modelPing: 'ok' | 'fail' | null
  pingError?: string
  present: boolean | null // null = наличие не проверялось
}

export interface PreflightResult {
  docker: PreflightState
  images: PreflightState
  model: PreflightState
  dockerDetail?: string
  imagesDetail?: string
  modelDetail?: string
  checkedAt?: string
  /** Расширенная предпроверка исследования: подготовка/совместимость/запуск приложения. */
  prepare?: PreflightState
  project?: PreflightState
  app?: PreflightState
  details?: Record<string, string>
  params?: unknown
}

/** Входные данные подготовки исследования (этап 1). */
export interface ResearchPreparationInput {
  snapshotId: string
  service: string
  entryModule: string
  knowledgeText: string
  actors: Record<string, string>
  budget: { seconds: number; decisions: number; requests: number }
}

export interface ResearchPreparationResult {
  preparationId: string
  status: 'PREPARED' | 'SUPERSEDED'
  budget: { seconds: number; decisions: number; requests: number }
  actors: Record<string, string>
  manifestSha256: string
  knowledgeSha256: string
  setupSha256: string
}

/** Одно событие журнала. text — недоверенная строка: рендер только текстом. */
export interface RunEvent {
  t: number // секунды от старта
  source: 'securitylab' | 'hermes' | 'verifier' | 'docker'
  text: string
}

export type StageState =
  | 'pending'
  | 'running'
  | 'wait_model' // длительная генерация без событий — честно, без псевдопроцентов
  | 'done'
  | 'failed'
  | 'skipped'

export interface Stage {
  id: string
  label: string
  role?: string // Red / baseline / Blue / verifier
  attempt?: number
  state: StageState
  startedAt?: number
  finishedAt?: number
  detail?: string
}

export type CheckGroup = 'owner' | 'foreign' | 'anon' | 'regress'
export type StageOutcome = 'pass' | 'fail' | 'not_run'

export interface CheckProbe {
  http: number | null
  outcome: StageOutcome
  bodyHashOk?: boolean | null // совпадение тела/хеша; null — не сравнивалось
  note?: string
}

export interface Check {
  id: string
  scenario: string
  group: CheckGroup
  actor: string
  method: string
  path: string
  expectStatus: number
  baseline: CheckProbe
  candidate: CheckProbe
  candidateRetry?: CheckProbe
  recheck?: CheckProbe
  final: StageOutcome
  note?: string
}

export interface RedProposal {
  scenarioNo: string
  summary: string
  method: string
  path: string
  entry: string
  /** Пометка «предложение AI» обязательна: Red не внедряет уязвимость сам. */
  aiGenerated: true
}

export interface BlueAttempt {
  n: number
  role: 'candidate' | 'candidate_retry'
  status: 'accepted' | 'rejected' | 'not_produced'
  diff: string // недоверенный контент
  rejectionReasons: string[]
  checkSummary?: string
}

export interface Artifact {
  id: string
  name: string
  kind: 'json' | 'text' | 'patch' | 'html' | 'log'
  present: boolean
  absentReason?: string
  /** Содержимое только для демонстрации; рендер текстом, html не исполняется. */
  content?: string
}

export interface RunTech {
  image: string
  imageDigest: string
  network: string
  configHash: string
  snapshotPin: string
  cleanup: string
  /** Хеш — журнал целостности, не криптографическая подпись и не гарантия. */
  hashDisclaimer: string
}

export interface Run {
  id: string
  cancelSupported?: boolean
  cancelRequested?: boolean
  demo: boolean // прогон сервера симуляции/демо помечается всегда
  projectId: string
  snapshotId: string
  service: string
  entryModule: string
  profileId: string
  policyId: string
  aiConfigId: string
  /** Идентификатор подготовки исследования (только для режима research-v1). */
  preparationId?: string | null
  mode: string // ai_red_blue / smoke_only / S11_RESEARCH_CYCLE
  /** state-каталог ядра, с которым выполнялся прогон. */
  stateDir?: string
  timingKnown?: boolean // false for imported summaries without execution timestamps
  startedAt: string // ISO
  finishedAt?: string
  aiConfiguration?: { model?: string; model_digest?: string; context_tokens?: number; timeout_seconds?: number }
  timeLimitMin: number
  exec: ExecStatus
  /** Причина остановки из ядра (например, «BLOCKED: лимит попыток исчерпан»). */
  error?: string
  verdict: Verdict
  /** Исходная строка security_verdict из summary, если значение вне известного набора. */
  verdictRaw?: string
  finding: Finding
  /** Исходная строка finding_status из summary, если значение вне известного набора. */
  findingRaw?: string
  stages: Stage[]
  events: RunEvent[]
  checks: Check[]
  redProposal?: RedProposal
  attempts: BlueAttempt[]
  commit?: { ref: string; sha: string; isolated: boolean }
  artifacts: Artifact[]
  tech: RunTech
  /** Режим исследования: гипотезы Red с независимыми статусами подтверждения. */
  hypotheses?: ResearchHypothesisView[]
  /** Режим исследования: использованный и оставшийся бюджет (без процентов). */
  coverage?: { decisions_used: number; requests_used: number; verification_requests: number; seconds_used: number; budget: { seconds: number; decisions: number; requests: number } }
  /** Режим исследования: пояснения цикла (ограничения, остановки по бюджету). */
  notes?: string[]
  /** Для активного демо-прогона: сценарий симуляции по секундам. */
  script?: DemoScript
}

export interface DemoScript {
  limitSeconds: number
  stages: Array<{ id: string; label: string; role?: string; state: StageState; from: number; to?: number; waitModelFrom?: number; detail?: string }>
  events: RunEvent[]
  finishAt: number
  final: { exec: ExecStatus; verdict: Verdict; finding: Finding }
}

export interface RunFilters {
  projectId?: string
  status?: ExecStatus | 'all'
  mode?: string | 'all'
  dateRange?: 'all' | '24h' | '7d'
}

/** Гипотеза Red и её независимая проверка; статусы считаются ядром, не моделью. */
export interface ResearchHypothesisView {
  n: number
  file: string
  path: string
  actor: string
  description: string
  basis: string
  expectedStatus: number
  observedStatus: number | null
  /** Стадия, где ядро зафиксировало наблюдение Red (http_01, http_assist_02…). */
  observedStage?: string | null
  confirmStatus: number | null
  /** Стадия свежего стенда воспроизведения; null — свежий стенд не запускался. */
  confirmStage?: string | null
  state: 'confirmed' | 'refuted' | 'consistent' | 'unconfirmed' | 'insufficient'
  patch?: string
}

export interface NewRunInput {
  projectId: string
  snapshotId: string
  service: string
  /** Путь файла точки входа (app/main.py); import string выводит backend. */
  entryModule: string
  profileId: string
  /** Обязателен для штатных режимов; в режиме исследования не передаётся. */
  policyId?: string
  /** Обязателен для режима исследования (results of POST /api/research/prepare). */
  preparationId?: string
  aiConfigId: string
  /** state-каталог ядра. */
  stateDir: string
}

/** Результат действия, которое требует реального backend. */
export type BackendRefusal = { ok: false; reason: string }

/** Диагностика: значения появляются только из реально полученных данных. */
export interface Diagnostics {
  available: boolean
  note: string
  cpu?: string
  memory?: string
  /** null — метрика не реализована; показывается «нет данных». */
  gpu?: string | null
  uptime?: string
}

export interface SecurityLabAdapter {
  /** Реестр проектов и снимков (ожидаемая зона ответственности: storage.py / cli.py). */
  listProjects(): Promise<Project[]>
  getProject(id: string): Promise<Project | null>
  createSnapshot(projectId: string): Promise<Snapshot | BackendRefusal>
  registerProject(path: string): Promise<Project | BackendRefusal>
  /** Удаление проекта из реестра: снимки проекта удаляются, исходный код на диске и история прогонов не трогаются. */
  deleteProject(id: string): Promise<{ ok: true; removedSnapshots: number; removedFolders: number } | BackendRefusal>

  listPolicies(): Promise<Policy[]>
  listAiConfigs(): Promise<AiConfig[]>
  validateAiConfig(id: string): Promise<{ valid: boolean; detail: string }>
  pingModel(id: string): Promise<{ ok: boolean; detail: string }>

  preflight(input: NewRunInput): Promise<PreflightResult>
  /** Подготовка входа исследования: документация + аккаунты + бюджет. Только ядро. */
  prepareResearch(input: ResearchPreparationInput): Promise<ResearchPreparationResult | BackendRefusal>

  listRuns(filters?: RunFilters): Promise<Run[]>
  /** null — только «не найдено» (404); сетевая ошибка выбрасывается, чтобы не маскироваться под отсутствие данных. */
  getRun(id: string): Promise<Run | null>
  /** 202 + run_id; длинные задания — только через backend-исполнитель. */
  createRun(input: NewRunInput): Promise<{ runId: string } | BackendRefusal>
  /** Референсный сервер подтверждает отмену; деморежим возвращает честный отказ. */
  cancelRun(id: string): Promise<BackendRefusal | { ok: true; state: string; runId: string }>

  exportPatch(runId: string): Promise<{ fileName: string; content: string } | BackendRefusal>
  getArtifact(runId: string, artifactId: string): Promise<Artifact | BackendRefusal>

  diagnostics(): Promise<Diagnostics>
  /** GET /api/health на указанном адресе; ошибка сети возвращается, не глотается. */
  health(baseUrl: string): Promise<{ ok: boolean; detail: string; httpStatus?: number; mode?: string }>
}
