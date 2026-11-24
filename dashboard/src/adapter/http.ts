/**
 * HttpAdapter — клиент референсного сервера (server/server.mjs).
 *
 * Контракт:
 *  — чтение — GET (patch/артефакты в том числе), изменение — POST с CSRF (#1);
 *  — getRun/getProject: null только для «не найдено» (404); сетевая ошибка,
 *    тайм-аут и 5xx выбрасываются — чтобы UI показал «связь потеряна», а не
 *    пустой реестр (#8);
 *  — CSRF-токен обновляется по TTL и один раз переиспрашивается при 403/CSRF
 *    (сервер отклоняет запрос до обработки, повтор безопасен);
 *  — прогоны прогоняются через DTO-мэппинг (adapter/dto.ts): raw-статусы ядра
 *    переводятся в типы UI, неизвестные значения — нейтрально с raw-строкой.
 */
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
  RunFilters,
  SecurityLabAdapter,
  AiConfig,
  NewRunInput,
  Snapshot,
} from './types'
import { mapCoreRun } from './dto'

const ABORT_MS = 60000

export class HttpError extends Error {
  readonly status?: number
  constructor(message: string, status?: number) {
    super(message)
    this.name = 'HttpError'
    this.status = status
  }
}

interface RunLikeRaw {
  security_verdict?: string
  finding_status?: string | null
  status?: string
  error?: string
  [k: string]: unknown
}

/** DTO: raw-поля ядра → типы UI, с сохранением raw для неизвестных значений. */
function applyDto(run: RunLikeRaw): Run {
  const mapped = mapCoreRun(run)
  return { ...run, ...mapped } as unknown as Run
}

export class HttpAdapter implements SecurityLabAdapter {
  private csrf: string | null = null
  private csrfIssuedAt = 0
  private csrfTtlMs = Infinity
  private baseUrl: string

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl
  }

  /** Нормализованный базовый адрес: без хвостового слеша. */
  static normalize(url: string): string {
    return url.trim().replace(/\/+$/, '')
  }

  private async raw<T>(path: string, init?: { method?: 'GET' | 'POST' | 'DELETE'; body?: unknown; csrf?: boolean; retry?: boolean }): Promise<T> {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), ABORT_MS)
    try {
      const headers: Record<string, string> = { Accept: 'application/json' }
      if (init?.body !== undefined) headers['Content-Type'] = 'application/json'
      if (init?.csrf) {
        await this.ensureCsrf()
        headers['X-CSRF-Token'] = this.csrf!
      }
      const res = await fetch(this.baseUrl + path, {
        method: init?.method ?? 'GET',
        headers,
        body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
        signal: ctrl.signal,
      })
      const data = (await res.json().catch(() => null)) as (T & { ok?: boolean; reason?: string }) | null
      if (!res.ok) {
        const reason = data?.reason ?? `сервер ответил HTTP ${res.status}`
        // CSRF-токен протух на сервере (TTL 1 ч): обновляем и повторяем один раз
        if (res.status === 403 && /CSRF/i.test(reason) && !init?.retry) {
          this.csrf = null
          return await this.raw<T>(path, { ...init, retry: true })
        }
        throw new HttpError(reason, res.status)
      }
      return data as T
    } catch (e) {
      if (e instanceof HttpError) throw e
      // AbortError и сетевые ошибки — наружу как понятная ошибка связи
      throw new HttpError(e instanceof DOMException && e.name === 'AbortError' ? `тайм-аут ${ABORT_MS / 1000} с — сервер не ответил` : 'нет соединения с сервером')
    } finally {
      clearTimeout(timer)
    }
  }

  private async ensureCsrf(): Promise<void> {
    const fresh = this.csrf && Date.now() - this.csrfIssuedAt < this.csrfTtlMs * 0.8
    if (fresh) return
    const data = await this.raw<{ token: string; expiresInMs: number }>('/api/csrf')
    this.csrf = data.token
    this.csrfIssuedAt = Date.now()
    this.csrfTtlMs = data.expiresInMs ?? Infinity
  }

  /** Изменяющий вызов: HTTP-отказ превращается в BackendRefusal для экрана. */
  private async action<T>(path: string, body?: unknown, method: 'POST' | 'DELETE' = 'POST'): Promise<T | BackendRefusal> {
    try {
      return await this.raw<T & { ok?: true }>(path, { method, body, csrf: true })
    } catch (e) {
      return { ok: false, reason: e instanceof Error ? e.message : 'сетевая ошибка' }
    }
  }

  /** Читающий вызов с отказом вместо исключения (экспорт/артефакты). */
  private async read<T>(path: string): Promise<T | BackendRefusal> {
    try {
      return await this.raw<T>(path)
    } catch (e) {
      return { ok: false, reason: e instanceof Error ? e.message : 'сетевая ошибка' }
    }
  }

  /* ---------- реестр ---------- */

  async listProjects(): Promise<Project[]> {
    return this.raw<Project[]>('/api/projects')
  }
  /** null — только 404; ошибка связи выбрасывается (#8). */
  async getProject(id: string): Promise<Project | null> {
    try {
      const all = await this.listProjects()
      return all.find((p) => p.id === id) ?? null
    } catch (e) {
      if (e instanceof HttpError && e.status === 404) return null
      throw e
    }
  }
  registerProject(path: string) {
    return this.action<Project>('/api/projects', { path })
  }
  createSnapshot(projectId: string) {
    return this.action<Snapshot>(`/api/projects/${encodeURIComponent(projectId)}/snapshots`)
  }
  /** Реестр: удаление проекта. Снимки проекта удаляются, исходный код и прогоны не трогаются. */
  deleteProject(id: string) {
    return this.action<{ ok: true; removedSnapshots: number; removedFolders: number }>(`/api/projects/${encodeURIComponent(id)}`, undefined, 'DELETE')
  }

  /* ---------- справочники ---------- */

  listPolicies(): Promise<Policy[]> {
    return this.raw<Policy[]>('/api/policies')
  }
  listAiConfigs(): Promise<AiConfig[]> {
    return this.raw<AiConfig[]>('/api/ai-configs')
  }
  async validateAiConfig(id: string) {
    try {
      return await this.raw<{ valid: boolean; detail: string }>(`/api/ai-configs/${encodeURIComponent(id)}/validate`, { method: 'POST', csrf: true })
    } catch (e) {
      return { valid: false, detail: e instanceof Error ? e.message : 'сетевая ошибка' }
    }
  }
  async pingModel(id: string) {
    try {
      return await this.raw<{ ok: boolean; detail: string }>(`/api/ai-configs/${encodeURIComponent(id)}/ping-model`, { method: 'POST', csrf: true })
    } catch (e) {
      return { ok: false, detail: e instanceof Error ? e.message : 'сетевая ошибка' }
    }
  }

  /* ---------- запуск ---------- */

  async preflight(input: NewRunInput): Promise<PreflightResult> {
    return this.raw<PreflightResult>('/api/preflight', { method: 'POST', body: input, csrf: true })
  }

  prepareResearch(input: ResearchPreparationInput) {
    return this.action<ResearchPreparationResult>('/api/research/prepare', input)
  }

  async listRuns(filters?: RunFilters): Promise<Run[]> {
    const q = new URLSearchParams()
    if (filters?.projectId) q.set('projectId', filters.projectId)
    if (filters?.status) q.set('status', filters.status)
    if (filters?.mode) q.set('mode', filters.mode)
    if (filters?.dateRange) q.set('dateRange', filters.dateRange)
    const qs = q.toString()
    const runs = await this.raw<RunLikeRaw[]>(`/api/runs${qs ? `?${qs}` : ''}`)
    return runs.map(applyDto)
  }
  /** null — только «прогон не найден» (404); ошибка связи выбрасывается (#8). */
  async getRun(id: string): Promise<Run | null> {
    try {
      const run = await this.raw<RunLikeRaw>(`/api/runs/${encodeURIComponent(id)}`)
      return applyDto(run)
    } catch (e) {
      if (e instanceof HttpError && e.status === 404) return null
      throw e
    }
  }
  createRun(input: NewRunInput) {
    return this.action<{ runId: string }>('/api/runs', input)
  }
  cancelRun(id: string) {
    return this.action<{ ok: true; state: string; runId: string }>(`/api/runs/${encodeURIComponent(id)}/cancel`)
  }

  /* ---------- доказательства: чтение — GET (#1) ---------- */

  exportPatch(runId: string) {
    return this.read<{ fileName: string; content: string }>(`/api/runs/${encodeURIComponent(runId)}/patch`)
  }
  getArtifact(runId: string, artifactId: string) {
    return this.read<Artifact>(`/api/runs/${encodeURIComponent(runId)}/artifacts/${encodeURIComponent(artifactId)}`)
  }

  async diagnostics(): Promise<Diagnostics> {
    try {
      return await this.raw<Diagnostics>('/api/diagnostics')
    } catch (e) {
      return {
        available: false,
        note: `диагностика недоступна (${e instanceof Error ? e.message : 'сетевая ошибка'}) — показывается «нет данных» вместо выдуманных значений`,
      }
    }
  }

  async health(baseUrl: string) {
    const url = HttpAdapter.normalize(baseUrl) + '/api/health'
    try {
      const ctrl = new AbortController()
      const timer = setTimeout(() => ctrl.abort(), 4000)
      const res = await fetch(url, { signal: ctrl.signal, headers: { Accept: 'application/json' } })
      clearTimeout(timer)
      const data = (await res.json().catch(() => null)) as { ok?: boolean; mode?: string } | null
      if (!res.ok || !data?.ok) {
        return { ok: false, detail: `backend ответил HTTP ${res.status} без признака health; остаёмся в текущем режиме`, httpStatus: res.status, mode: data?.mode }
      }
      const label =
        data.mode === 'securitylab-core'
          ? 'ядро SecurityLab отвечает — режим «SecurityLab подключён»'
          : 'референсный сервер отвечает: операции выполняются реально, прогоны — сценарии симуляции (demo: true)'
      return { ok: true, detail: label, httpStatus: res.status, mode: data.mode }
    } catch (e) {
      return { ok: false, detail: `соединение не установлено (${e instanceof Error ? e.message : 'сетевая ошибка'}) — остаёмся в текущем режиме` }
    }
  }
}
