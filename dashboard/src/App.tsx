import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useRoute } from './router'
import { useStore } from './state/store'
import { Icon } from './components/ui'
import { Page } from './components/layout'
import { Projects } from './screens/Projects'
import { NewRun } from './screens/NewRun'
import { Runs } from './screens/Runs'
import { RunDetail } from './screens/RunDetail'
import { Settings } from './screens/Settings'
import { Integration } from './screens/Integration'

const NAV = [
  { to: '/projects', label: 'Проекты', no: '01' },
  { to: '/new', label: 'Новый запуск', no: '02' },
  { to: '/runs', label: 'Запуски', no: '03' },
  { to: '/settings', label: 'Настройки', no: '04' },
  { to: '/integration', label: 'Интеграция', no: '05' },
]

/* ---------- логотип: градиентная плитка lucian ---------- */

function Wordmark() {
  return (
    <a href="#/projects" className="flex shrink-0 items-center gap-2.5" aria-label="SecurityLab — на главную">
      <span
        className="grid h-9 w-9 place-items-center rounded-field text-[15px] font-black text-white shadow-[0_10px_18px_-8px_var(--shadow-strong)]"
        style={{ background: 'var(--grad)' }}
        aria-hidden="true"
      >
        S
      </span>
      <span className="leading-none">
        <span className="block text-[16px] font-extrabold tracking-[-0.03em]">
          Security<span className="text-accent">Lab</span>
        </span>
        <span className="mt-1 block font-mono text-[9px] font-bold uppercase tracking-[0.18em] text-ink3">
          стенд проверки
        </span>
      </span>
    </a>
  )
}

/* ---------- навигация: скользящая чернильная пилюля (lucian #039) ---------- */

function NavPills({ path, navigate }: { path: string; navigate: (to: string) => void }) {
  const boxRef = useRef<HTMLDivElement>(null)
  const [pill, setPill] = useState<{ x: number; w: number; ready: boolean }>({ x: 0, w: 0, ready: false })
  const active = NAV.find((n) => path === n.to || path.startsWith(n.to + '/'))?.to ?? '/projects'

  const measure = useCallback(() => {
    const el = boxRef.current?.querySelector<HTMLElement>(`[data-to="${active}"]`)
    if (el) setPill({ x: el.offsetLeft, w: el.offsetWidth, ready: true })
  }, [active])

  useLayoutEffect(() => {
    measure()
    // шрифты грузятся асинхронно — ширина ссылок меняется, перемеряем
    document.fonts?.ready.then(measure).catch(() => {})
  }, [measure])

  useEffect(() => {
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [measure])

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return
    e.preventDefault()
    const idx = NAV.findIndex((n) => n.to === active)
    const next = e.key === 'ArrowRight' ? (idx + 1) % NAV.length : (idx - 1 + NAV.length) % NAV.length
    navigate(NAV[next].to)
    boxRef.current?.querySelector<HTMLElement>(`[data-to="${NAV[next].to}"]`)?.focus()
  }

  return (
    <div ref={boxRef} className="navrail max-w-full" role="navigation" aria-label="Основная навигация" onKeyDown={onKeyDown}>
      {pill.ready && <span className="navpill" aria-hidden="true" style={{ width: pill.w, transform: `translateX(${pill.x}px)` }} />}
      {NAV.map((item) => {
        const isActive = active === item.to
        return (
          <a
            key={item.to}
            data-to={item.to}
            href={`#${item.to}`}
            aria-current={isActive ? 'page' : undefined}
            tabIndex={isActive ? 0 : -1}
            className="navlink"
            onClick={(e) => {
              e.preventDefault()
              navigate(item.to)
            }}
          >
            <span className="navno">{item.no}</span>
            {item.label}
          </a>
        )
      })}
    </div>
  )
}

/* ---------- переключатель темы: мини-пилюля ---------- */

function ThemeToggle() {
  const { theme, toggleTheme } = useStore()
  return (
    <button
      type="button"
      role="switch"
      aria-checked={theme === 'dark'}
      onClick={toggleTheme}
      aria-label={theme === 'light' ? 'Включить тёмную тему' : 'Включить светлую тему'}
      title={theme === 'light' ? 'Тёмная тема' : 'Светлая тема'}
      className="themetoggle pressable"
    >
      <span className="themetoggle-knob">
        <Icon name={theme === 'light' ? 'moon' : 'sun'} size={13} />
      </span>
    </button>
  )
}

function ModeStamp() {
  const { mode, backendUrl, connectionLost } = useStore()
  const base = 'inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[11px] font-bold uppercase tracking-[0.08em]'
  // короткая подпись на узких экранах, полная — от sm (#11: режим виден и на телефоне)
  const Short = ({ children }: { children: ReactNode }) => <span className="sm:hidden">{children}</span>
  const Long = ({ children }: { children: ReactNode }) => <span className="hidden sm:inline">{children}</span>
  // связь потеряна поверх текущего режима — видна и на мобильном (#11, #8)
  if (connectionLost) {
    return (
      <span className={`${base} bg-dangersoft text-dangerink`} title="последний опрос backend завершился ошибкой; показанные данные могут быть устаревшими">
        <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
        <Short>нет связи</Short>
        <Long>связь потеряна</Long>
      </span>
    )
  }
  if (mode === 'core') {
    return (
      <span className={`${base} bg-mintsoft text-mintink`} title={`ядро SecurityLab подключено (${backendUrl}); данные из state ядра`}>
        <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
        <Short>ядро</Short>
        <Long>securitylab подключён</Long>
      </span>
    )
  }
  if (mode === 'sim-server') {
    return (
      <span className={`${base} bg-accentsoft text-accent`} title={`подключён референсный сервер симуляции (${backendUrl}); операции над реестром реальные, прогоны — сценарии (demo: true)`}>
        <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
        <Short>симуляция</Short>
        <Long>сервер симуляции</Long>
      </span>
    )
  }
  return (
    <span className={`${base} bg-warnsoft text-warnink`} title="демо-данные в браузере; серверные действия не изображаются">
      <span className="breathing h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
      <Short>демо</Short>
      <Long>демо в браузере</Long>
    </span>
  )
}

/* ---------- тосты ---------- */

function Toasts() {
  const { toasts, dismissToast } = useStore()
  if (toasts.length === 0) return null
  return (
    <div className="pointer-events-none fixed bottom-4 left-4 z-[60] flex w-[min(440px,calc(100vw-2rem))] flex-col gap-2.5" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`anim-in pointer-events-auto flex items-start gap-2.5 rounded-card bg-surface px-4 py-3.5 text-[13.5px] leading-snug shadow-[0_0_0_1px_var(--line),0_20px_36px_-20px_var(--shadow-strong)] ${
            t.tone === 'error' ? 'text-dangerink' : t.tone === 'ok' ? 'text-mintink' : 'text-ink2'
          }`}
        >
          <span className="mt-0.5 shrink-0">
            <Icon name={t.tone === 'error' ? 'alert' : t.tone === 'ok' ? 'check' : 'eye'} size={15} />
          </span>
          <span>{t.text}</span>
          <button
            type="button"
            onClick={() => dismissToast(t.id)}
            aria-label="Скрыть"
            className="ml-auto shrink-0 rounded-full p-1 text-ink3 transition-colors hover:text-ink"
          >
            <Icon name="cross" size={13} />
          </button>
        </div>
      ))}
    </div>
  )
}

/* ---------- маршруты и оболочка ---------- */

function Routes({ path, navigate }: { path: string; navigate: (to: string) => void }) {
  const [base, query = ''] = path.split('?')
  const params = new URLSearchParams(query)
  if (base === '/new') return <NewRun navigate={navigate} initialProjectId={params.get('project') ?? undefined} />
  if (base === '/runs') return <Runs navigate={navigate} />
  if (base.startsWith('/runs/')) return <RunDetail runId={decodeURIComponent(base.slice('/runs/'.length))} navigate={navigate} />
  if (base === '/settings') return <Settings />
  if (base === '/integration') return <Integration />
  return <Projects navigate={navigate} />
}

function Shell() {
  const { path, navigate } = useRoute()
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-40 border-b border-line bg-page/85 backdrop-blur-md">
        <div className="mx-auto flex h-[72px] w-full max-w-[1400px] items-center gap-4 px-4 sm:gap-6 sm:px-6">
          <Wordmark />
          <div className="mx-auto min-w-0 max-w-full flex-1 sm:mx-0">
            <NavPills path={path} navigate={navigate} />
          </div>
          <div className="ml-auto flex min-w-0 items-center gap-2.5 sm:ml-0 sm:gap-3">
            <ModeStamp />
            <ThemeToggle />
          </div>
        </div>
      </header>
      <main key={path} className="anim-in">
        <Page>
          <Routes path={path} navigate={navigate} />
        </Page>
        <footer className="border-t border-line px-5 py-6 sm:px-8 lg:px-12">
          <p className="mx-auto max-w-[1080px] font-mono text-[10.5px] leading-relaxed text-ink3">
            SecurityLab UI · демо-сборка · интерфейс не исполняет код проектов и не подключается к Docker напрямую;
            длинные задания выполняет backend-исполнитель
          </p>
        </footer>
      </main>
      <Toasts />
    </div>
  )
}

export default function App() {
  return <Shell />
}
