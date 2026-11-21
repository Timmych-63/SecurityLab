import { useEffect, useMemo, useState } from 'react'
import type { AiConfig, Project } from '../adapter/types'
import { HttpAdapter } from '../adapter/http'
import type { ResearchPreparation, ResearchPreflight, ResearchPreparationRow } from '../adapter/http'
import { useStore } from '../state/store'
import { ScreenHead } from '../components/layout'
import { Button, Card, Field, Note, Select, Skeleton, TextInput } from '../components/ui'

const MAX_DOC_BYTES = 12288

function parseActors(value: string): Record<string, string> {
  const actors: Record<string, string> = Object.create(null)
  const lines = value.split(/\r?\n/).map(x => x.trim()).filter(Boolean)
  if (lines.length < 1 || lines.length > 16) throw new Error('Укажите от 1 до 16 тестовых аккаунтов')
  for (const line of lines) {
    const match = /^([A-Za-z][A-Za-z0-9_-]{0,31})\s*:\s*([A-Za-z][A-Za-z0-9_-]{0,31})$/.exec(line)
    if (!match || Object.hasOwn(actors, match[1])) throw new Error('Аккаунты: каждая строка в формате alice:user, без повторений')
    actors[match[1]] = match[2]
  }
  return actors
}

const fieldCss = 'fieldctl w-full min-h-[130px] resize-y font-mono text-[12px] leading-5'

export function Research({ navigate, initialProjectId }: { navigate: (to: string) => void; initialProjectId?: string }) {
  const { adapter, mode, selectedAiConfigId } = useStore()
  const core = mode === 'core' && adapter instanceof HttpAdapter ? adapter : null
  const [projects, setProjects] = useState<Project[] | null>(null)
  const [configs, setConfigs] = useState<AiConfig[] | null>(null)
  const [history, setHistory] = useState<ResearchPreparationRow[]>([])
  const [projectId, setProjectId] = useState(initialProjectId ?? '')
  const [snapshotId, setSnapshotId] = useState('')
  const [entry, setEntry] = useState('')
  const [knowledge, setKnowledge] = useState('')
  const [actors, setActors] = useState('alice:user\nbob:user')
  const [seconds, setSeconds] = useState(1800)
  const [decisions, setDecisions] = useState(12)
  const [requests, setRequests] = useState(40)
  const [aiConfigId, setAiConfigId] = useState(selectedAiConfigId)
  const [prepared, setPrepared] = useState<ResearchPreparation | null>(null)
  const [preflight, setPreflight] = useState<ResearchPreflight | null>(null)
  const [busy, setBusy] = useState<'prepare' | 'preflight' | null>(null)
  const [error, setError] = useState('')
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    let live = true
    Promise.all([adapter.listProjects(), adapter.listAiConfigs()]).then(([p, c]) => {
      if (live) { setProjects(p); setConfigs(c) }
    }).catch(e => { if (live) { setProjects([]); setConfigs([]); setError(String(e)) } })
    if (core) core.listResearchPreparations().then(h => { if (live) setHistory(h) }).catch(() => {})
    return () => { live = false }
  }, [adapter, core])
  useEffect(() => {
    if (busy !== 'preflight') return
    const started = Date.now()
    const handle = window.setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000)
    return () => window.clearInterval(handle)
  }, [busy])

  const project = projects?.find(x => x.id === projectId)
  const entries = useMemo(() => [...new Set((project?.services ?? []).map(s => `${s.service}|${s.entryFile}`))], [project])
  const clear = () => { setPrepared(null); setPreflight(null); setError('') }

  async function prepare() {
    if (!core) return
    setError('')
    setBusy('prepare')
    try {
      const selected = entry.split('|')
      if (!project || !snapshotId || selected.length !== 2 || !aiConfigId) throw new Error('Выберите проект, снимок, точку входа и модель')
      if (new TextEncoder().encode(knowledge).length < 1 || new TextEncoder().encode(knowledge).length > MAX_DOC_BYTES) {
        throw new Error('Документация должна содержать от 1 до 12288 байт UTF-8')
      }
      const setupText = JSON.stringify({ schema_version: 1, runtime: 'fastapi-local-v1',
        identity: 'trusted-test-user-header', actors: parseActors(actors),
        budget: { seconds, decisions, requests } })
      const result = await core.createResearchPreparation({
        projectId, snapshotId, service: selected[0], entry: selected[1],
        knowledge, setupText, aiConfigId,
      })
      setPrepared(result)
      setPreflight(null)
      core.listResearchPreparations().then(setHistory).catch(() => {})
    } catch (e) { setError(e instanceof Error ? e.message : 'Ошибка подготовки') }
    finally { setBusy(null) }
  }

  async function checkStand() {
    if (!core || !prepared) return
    setBusy('preflight')
    setPreflight(null)
    setError('')
    setElapsed(0)
    try {
      setPreflight(await core.preflightResearch(prepared.id))
      core.listResearchPreparations().then(setHistory).catch(() => {})
    } catch (e) { setError(e instanceof Error ? e.message : 'Ошибка предпроверки') }
    finally { setBusy(null) }
  }

  return <>
    <ScreenHead no="02 · Подготовка" title="Исследование безопасности"
      meta="Новый путь SecurityLab: проект → описание приложения → стенд → проверка готовности. Автономный запуск Red будет подключён на следующем этапе." />
    {!core && <div className="mb-5"><Note tone="warn" title="Требуется локальное ядро">
      Подготовка исследования работает только в подключённом SecurityLab. Демо-режим не создаёт настоящие исследования.
    </Note></div>}
    {error && <div className="mb-5"><Note tone="warn" title="Не удалось выполнить действие">{error}</Note></div>}
    {!projects || !configs ? <Skeleton lines={5} /> : <div className="space-y-5">
      <Card>
        <h2 className="mb-4 text-[16px] font-extrabold">01. Проект и снимок</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Проект"><Select value={projectId} onChange={e => {
            setProjectId(e.target.value); setSnapshotId(''); setEntry(''); clear()
          }}><option value="">Выберите проект</option>{projects.filter(x => x.supported).map(p =>
            <option key={p.id} value={p.id}>{p.name}</option>)}</Select></Field>
          <Field label="Зафиксированный снимок"><Select value={snapshotId} onChange={e => { setSnapshotId(e.target.value); clear() }}>
            <option value="">Выберите снимок</option>{project?.snapshots.map(s => <option key={s.id} value={s.id}>{s.commit} · {s.id.slice(0, 12)}</option>)}
          </Select></Field>
          <Field label="Сервис и точка входа" hint="Выбирается из обнаруженных сервером файлов; совместимость проверит ядро">
            <Select value={entry} onChange={e => { setEntry(e.target.value); clear() }}>
              <option value="">Выберите точку входа</option>{entries.map(v =>
                <option key={v} value={v}>{v.replace('|', ' · ')}</option>)}
            </Select>
          </Field>
          <Field label="Модель" hint="Проверяется точная конфигурация и digest; модель не получает новых разрешений">
            <Select value={aiConfigId} onChange={e => { setAiConfigId(e.target.value); clear() }}>
              <option value="">Выберите модель</option>{configs.map(c => <option key={c.id} value={c.id}>{c.name} · {c.model}</option>)}
            </Select>
          </Field>
        </div>
      </Card>
      <Card>
        <h2 className="mb-4 text-[16px] font-extrabold">02. Документация приложения</h2>
        <Field label="Markdown: назначение, роли, бизнес-правила, запуск" hint="Без расположения искусственно созданных уязвимостей и готовых сценариев атак. До 12 КБ.">
          <textarea className={fieldCss} rows={9} value={knowledge} onChange={e => { setKnowledge(e.target.value); clear() }} placeholder="# Описание приложения&#10;## Роли и права&#10;## Правила работы с данными" />
        </Field>
        <label className="mt-3 block text-[13px] text-ink2">
          Загрузить .md/.txt с компьютера
          <input type="file" accept=".md,.txt,text/markdown,text/plain" className="mt-2 block max-w-full text-[12px]"
            onChange={async e => { const file = e.target.files?.[0]; if (!file) return
              try { if (file.size > MAX_DOC_BYTES) throw new Error('Файл превышает 12 КБ')
                setKnowledge(await file.text()); clear()
              } catch (err) { setError(err instanceof Error ? err.message : 'Не удалось прочитать файл') }
            }} />
        </label>
      </Card>
      <Card>
        <h2 className="mb-4 text-[16px] font-extrabold">03. Тестовые аккаунты и бюджет</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Аккаунты и роли" hint="Один аккаунт на строку: alice:user. Пароли сюда не вводятся.">
            <textarea className={fieldCss} rows={4} value={actors} onChange={e => { setActors(e.target.value); clear() }} />
          </Field>
          <div className="grid grid-cols-3 gap-3">
            <Field label="Секунды"><TextInput type="number" min={60} max={3600} value={seconds} onChange={e => { setSeconds(Number(e.target.value)); clear() }} /></Field>
            <Field label="Шаги Red"><TextInput type="number" min={1} max={30} value={decisions} onChange={e => { setDecisions(Number(e.target.value)); clear() }} /></Field>
            <Field label="GET-запросы"><TextInput type="number" min={1} max={100} value={requests} onChange={e => { setRequests(Number(e.target.value)); clear() }} /></Field>
          </div>
        </div>
        <p className="mt-4 text-[12px] leading-relaxed text-ink3">
          Профиль MVP: Python/FastAPI, локальная тестовая идентификация, изолированный Docker. Ограничения записываются сейчас,
          но их применение к решениям Red будет реализовано на этапе 2.
        </p>
        <div className="mt-5 flex flex-wrap items-center gap-3">
          <Button variant="primary" disabled={!core || !!busy} onClick={prepare}>{busy === 'prepare' ? 'Подготовка…' : 'Сохранить подготовку'}</Button>
          {prepared && <span className="font-mono text-[12px] text-ink3">PREPARED · {prepared.id}</span>}
        </div>
      </Card>
      <Card>
        <h2 className="mb-4 text-[16px] font-extrabold">04. Проверка готовности</h2>
        <Note tone="info">Проверяются точные копии входных данных, совместимость снимка, Docker, образ, Hermes,
          модель и запуск FastAPI на свежем стенде. Успешная предпроверка не означает безопасность приложения.
        </Note>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <Button disabled={!prepared || !!busy || !core} onClick={checkStand}>
            {busy === 'preflight' ? `Предпроверка · ${elapsed} с` : 'Проверить стенд'}
          </Button>
          {busy === 'preflight' && <span className="text-[12px] text-ink3">Ожидание реального ответа Docker/модели. Процент не рассчитывается.</span>}
        </div>
        {preflight && <div className="mt-5 space-y-2">
          <Note tone={preflight.environment_ready ? 'ok' : 'warn'} title={preflight.environment_ready ? 'Стенд готов' : 'Стенд не готов'}>
            {preflight.reason ?? 'Подтверждён запуск на свежем Docker-стенде; исследование ещё не запущено.'}
          </Note>
          {preflight.checks.map((check, i) => <div key={i} className="rounded-field bg-dim px-3 py-3 text-[13px]">
            <strong>{check.status === 'PASS' ? '✓' : '!' } {check.name}</strong><div className="text-ink3">{check.detail}</div>
          </div>)}
        </div>}
        <div className="mt-6 flex flex-wrap items-center gap-3">
          <Button variant="primary" disabled>Начать автономное исследование</Button>
          <span className="text-[12px] text-ink3">Недоступно до подключения цикла Red (этап 2)</span>
        </div>
      </Card>
      {history.length > 0 && <Card>
        <h2 className="mb-3 text-[15px] font-bold">Последние подготовки</h2>
        <div className="space-y-2">{history.slice(0, 10).map(h => <p key={h.id} className="font-mono text-[11.5px] text-ink3">
          {h.id.slice(0, 12)} · {h.entry} · {h.preflight}
        </p>)}</div>
      </Card>}
      <p className="text-[12px] text-ink3">Предыдущие сценарии сохранены: <button type="button" className="underline" onClick={() => navigate('/new')}>старый интерфейс проверок</button>.</p>
    </div>}
  </>
}
