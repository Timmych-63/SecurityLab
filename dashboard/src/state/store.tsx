import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { DemoAdapter, isRunActive, resolveLiveRun } from '../adapter/demo'
import { HttpAdapter } from '../adapter/http'
import type { Run, SecurityLabAdapter } from '../adapter/types'

/* ---------- тема ---------- */

export type Theme = 'light' | 'dark'

/**
 * Режим интерфейса (#11): всё видно и на мобильном.
 *  demo       — демо-данные в браузере;
 *  sim-server — подключён референсный сервер симуляции;
 *  core       — подключено ядро SecurityLab (боевой backend).
 * Отдельно connectionLost: «Связь потеряна» поверх текущего режима.
 */
export type AdapterMode = 'demo' | 'sim-server' | 'core'

/* ---------- тосты ---------- */

export interface Toast {
  id: number
  text: string
  tone: 'info' | 'error' | 'ok'
}

/* ---------- контекст ---------- */

interface StoreValue {
  theme: Theme
  toggleTheme: () => void
  /** Активный адаптер: демо или подключённый backend. */
  adapter: SecurityLabAdapter
  mode: AdapterMode
  /** Адрес подключённого backend, если есть. */
  backendUrl: string | null
  /** Переключение на HttpAdapter по адресу backend; живёт до перезагрузки страницы. */
  connectBackend: (url: string, backendMode: 'sim-server' | 'core') => void
  disconnectBackend: () => void
  /** Экраны сообщают об успешных/неудачных опросах backend; отображается как «Связь потеряна». */
  connectionLost: boolean
  reportConnection: (ok: boolean) => void
  /** Выбранная AI-конфигурация (#4): реально используется новыми запусками. */
  selectedAiConfigId: string
  setSelectedAiConfigId: (id: string) => void
  toasts: Toast[]
  pushToast: (text: string, tone?: Toast['tone']) => void
  dismissToast: (id: number) => void
  /** Тикающие «сейчас»: обновляются, пока есть активный прогон (демо или HTTP). */
  nowMs: number
  /** Прогон с развёрнутой симуляцией (или статический). */
  liveRun: (run: Run) => Run
  /** Увеличивается после создания прогона — списки перечитывают данные. */
  dataVersion: number
  bumpData: () => void
}

const StoreCtx = createContext<StoreValue | null>(null)

const AI_CFG_KEY = 'slb.aiConfig.v1'

export function StoreProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(() =>
    document.documentElement.classList.contains('dark') ? 'dark' : 'light',
  )
  const [toasts, setToasts] = useState<Toast[]>([])
  const [dataVersion, setDataVersion] = useState(0)
  const [nowMs, setNowMs] = useState(() => Date.now())
  const [backend, setBackend] = useState<{ url: string; adapter: SecurityLabAdapter; mode: 'sim-server' | 'core' } | null>(() => document.querySelector('meta[name=securitylab-core]') ? { url: location.origin, adapter: new HttpAdapter(location.origin), mode: 'core' } : null)
  const [connectionLost, setConnectionLost] = useState(false)
  const [selectedAiConfigId, setSelectedAiConfigIdState] = useState<string>(() => {
    try {
      return localStorage.getItem(AI_CFG_KEY) ?? (document.querySelector('meta[name=securitylab-core]') ? 'default' : 'aicfg-qwen7b')
    } catch {
      return 'aicfg-qwen7b'
    }
  })
  const adapterRef = useRef<DemoAdapter | null>(null)
  if (!adapterRef.current) adapterRef.current = new DemoAdapter()
  const demoAdapter = adapterRef.current
  // переключение демо ↔ backend: экраны продолжают читать один и тот же контракт
  const adapter: SecurityLabAdapter = backend ? backend.adapter : demoAdapter

  const setSelectedAiConfigId = useCallback((id: string) => {
    setSelectedAiConfigIdState(id)
    try {
      localStorage.setItem(AI_CFG_KEY, id)
    } catch { /* приватный режим — выбор живёт до перезагрузки */ }
  }, [])

  const toggleTheme = useCallback(() => {
    setTheme((t) => {
      const next = t === 'light' ? 'dark' : 'light'
      document.documentElement.classList.toggle('dark', next === 'dark')
      try {
        localStorage.setItem('slb.theme', next)
      } catch { /* приватный режим — тема не сохраняется */ }
      return next
    })
  }, [])

  const toastSeq = useRef(1)
  const pushToast = useCallback((text: string, tone: Toast['tone'] = 'info') => {
    const id = toastSeq.current++
    setToasts((ts) => [...ts.slice(-3), { id, text, tone }])
    setTimeout(() => setToasts((ts) => ts.filter((t) => t.id !== id)), 7000)
  }, [])
  const dismissToast = useCallback((id: number) => {
    setToasts((ts) => ts.filter((t) => t.id !== id))
  }, [])

  const reportConnection = useCallback((ok: boolean) => setConnectionLost(!ok), [])

  const bumpData = useCallback(() => setDataVersion((v) => v + 1), [])

  // переключение на backend живёт до перезагрузки страницы — после
  // перезагрузки экран «Интеграция» заново проверит соединение (честный вход)
  const connectBackend = useCallback(
    (url: string, backendMode: 'sim-server' | 'core') => {
      setBackend({ url: HttpAdapter.normalize(url), adapter: new HttpAdapter(url), mode: backendMode })
      setConnectionLost(false)
      bumpData()
    },
    [bumpData],
  )

  const disconnectBackend = useCallback(() => {
    setBackend(null)
    setConnectionLost(false)
    bumpData()
  }, [bumpData])

  // глобальный опрос: тикает «сейчас» и следит за активным прогоном.
  // Активность определяется по exec сервера (для HTTP-прогонов script нет) (#2),
  // а ошибка опроса при подключённом backend помечает «Связь потеряна» (#8).
  useEffect(() => {
    let stopped = false
    let timer: ReturnType<typeof setInterval> | undefined
    const scan = async () => {
      try {
        const runs = await adapter.listRuns()
        if (stopped) return
        setConnectionLost(false)
        const hasActive = runs.some((r) => r.exec === 'running' || r.exec === 'queued' || isRunActive(r, Date.now()))
        if (hasActive && !timer) timer = setInterval(() => setNowMs(Date.now()), 1000)
        if (!hasActive && timer) {
          clearInterval(timer)
          timer = undefined
          setNowMs(Date.now())
        }
      } catch {
        if (!stopped && backend) setConnectionLost(true)
      }
    }
    scan()
    const scanTimer = setInterval(scan, 4000)
    return () => {
      stopped = true
      if (timer) clearInterval(timer)
      clearInterval(scanTimer)
    }
  }, [adapter, dataVersion, backend])

  const liveRun = useCallback(
    (run: Run) => resolveLiveRun(run, nowMs),
    [nowMs],
  )

  const value: StoreValue = {
    theme,
    toggleTheme,
    adapter,
    mode: backend ? backend.mode : 'demo',
    backendUrl: backend?.url ?? null,
    connectBackend,
    disconnectBackend,
    connectionLost,
    reportConnection,
    selectedAiConfigId,
    setSelectedAiConfigId,
    toasts,
    pushToast,
    dismissToast,
    nowMs,
    liveRun,
    dataVersion,
    bumpData,
  }
  return <StoreCtx.Provider value={value}>{children}</StoreCtx.Provider>
}

export function useStore(): StoreValue {
  const v = useContext(StoreCtx)
  if (!v) throw new Error('useStore вне StoreProvider')
  return v
}

/**
 * Активный (ещё не завершённый) прогон, если есть. Активность — по серверному
 * exec (running/queued), а не только по сценарию симуляции (#2): HTTP-прогон
 * без script тоже виден. Ошибка связи не считается «активных нет»: возвращается
 * предыдущее состояние + error.
 */
export function useActiveRun(): { run: Run | null; ready: boolean; error: boolean } {
  const { adapter, dataVersion } = useStore()
  const [state, setState] = useState<{ run: Run | null; ready: boolean; error: boolean }>({ run: null, ready: false, error: false })
  useEffect(() => {
    let alive = true
    adapter.listRuns().then((runs) => {
      if (!alive) return
      const active = runs.find((r) => r.exec === 'running' || r.exec === 'queued' || isRunActive(r, Date.now())) ?? null
      setState({ run: active, ready: true, error: false })
    }).catch(() => {
      // сохраняем предыдущий прогон; error=true — экран не заявляет «активных нет»
      if (alive) setState((s) => ({ ...s, ready: true, error: true }))
    })
    return () => { alive = false }
  }, [adapter, dataVersion])
  return state
}
