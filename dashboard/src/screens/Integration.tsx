import { useState } from 'react'
import { ENDPOINTS } from '../adapter/demo'
import { useStore } from '../state/store'
import { ScreenHead } from '../components/layout'
import { Button, Chip, Note, TextInput, Card, Overline } from '../components/ui'

export function Integration() {
  const { adapter, mode, backendUrl, connectionLost, reportConnection, connectBackend, disconnectBackend, pushToast } = useStore()
  const [url, setUrl] = useState('http://127.0.0.1:8765')
  const [busy, setBusy] = useState(false)
  const [recheckBusy, setRecheckBusy] = useState(false)
  const [result, setResult] = useState<{ ok: boolean; detail: string } | null>(null)

  const check = async () => {
    setBusy(true)
    setResult(null)
    const res = await adapter.health(url.trim())
    setBusy(false)
    setResult(res)
    // успех — реальное переключение на HttpAdapter (живёт до перезагрузки страницы);
    // режим берём из ответа: simulated-data → «сервер симуляции», securitylab-core → «ядро»
    if (res.ok) {
      connectBackend(url.trim(), res.mode === 'securitylab-core' ? 'core' : 'sim-server')
    }
  }

  // перепроверка текущего backend: при отказе — «связь потеряна», данные не подменяются демо (#8)
  const recheck = async () => {
    if (!backendUrl) return
    setRecheckBusy(true)
    try {
      const res = await adapter.health(backendUrl)
      if (res.ok) {
        reportConnection(true)
        pushToast(`Соединение с ${backendUrl} восстановлено/подтверждено.`, 'ok')
      } else {
        reportConnection(false)
        pushToast(`Соединение с ${backendUrl} не подтвердилось: ${res.detail}`, 'error')
      }
    } finally {
      setRecheckBusy(false)
    }
  }

  return (
    <>
      <ScreenHead
        no="05 · Стык"
        title="Интеграция и инструкция"
        meta={<>Интерфейс подключается к Python-ядру автоматически при запуске через securitylab.dashboard. DemoAdapter и Node-сервер остаются отдельной демонстрацией. Изменяющие операции защищены CSRF-токеном и проверкой Origin.</>}
      />

      <div className="space-y-5">
        {/* 01 · режим подключения */}
        <Card>
          <Overline>01 · Режим подключения</Overline>
          <div className="mt-3.5 flex flex-wrap items-center gap-2.5">
            {mode === 'sim-server' && (
              <Chip tone="accent">сервер симуляции · {backendUrl?.replace(/^https?:\/\//, '')}</Chip>
            )}
            {mode === 'core' && (
              <Chip tone="mint">securitylab подключён · {backendUrl?.replace(/^https?:\/\//, '')}</Chip>
            )}
            {mode === 'demo' && <Chip tone="warn">демо в браузере</Chip>}
            {connectionLost && <Chip tone="danger">связь потеряна</Chip>}
            {mode !== 'demo' && (
              <Button variant="secondary" onClick={recheck} disabled={recheckBusy}>
                {recheckBusy ? 'Проверяем…' : 'Перепроверить соединение'}
              </Button>
            )}
            {mode !== 'demo' && (
              <Button variant="ghost" onClick={() => { disconnectBackend(); setResult(null) }}>
                Вернуться в деморежим
              </Button>
            )}
          </div>
          <div className="mt-5 flex flex-wrap items-end gap-3">
            <label className="w-full max-w-md">
              <span className="mb-1.5 block text-[13px] font-bold">Адрес backend (loopback)</span>
              <TextInput value={url} onChange={(e) => setUrl(e.target.value)} aria-label="Адрес backend" />
            </label>
            <Button variant="primary" onClick={check} disabled={busy}>{busy ? 'Проверяем…' : 'Проверить соединение'}</Button>
          </div>
          {result && (
            <div className="mt-4 max-w-2xl">
              <Note tone={result.ok ? 'ok' : 'warn'} title={result.ok ? 'Backend отвечает — переключено' : 'Соединение не установлено'}>
                {result.detail}
              </Note>
            </div>
          )}
          <p className="mt-4 max-w-2xl text-[13px] leading-relaxed text-ink3">
            Сервер слушает только loopback и требует GET /api/csrf + заголовок X-CSRF-Token для изменяющих операций;
            Origin должен быть loopback-адресом. Docker-сокет браузеру не открывается.
          </p>
        </Card>

        <Card>
          <Overline>02 · Запуск с Python-ядром</Overline>
          <p className="mt-4 font-mono text-[12.5px]">py -3 -m securitylab.dashboard --state ПУТЬ_К_STATE</p>
          <p className="mt-4 text-[14px] leading-relaxed text-ink2">
            Откройте http://127.0.0.1:8765. Сервер раздаёт интерфейс и API.
            AI-профили читаются из ai-profiles/*.toml. Выбор применяется к новым запускам.
            Предпроверка проверяет Docker, образы, приватную сеть, имя и digest модели; генерацию не запускает.
          </p>
          <div className="mt-4"><Note tone="warn" title="Границы текущей интеграции">
            Поддержан access-ai для одного FastAPI-модуля и внешней политики. История показывает access_ai.
            Старые demo/candidate-check доступны через CLI. Очередь, безопасная отмена access-ai и метрики CPU/GPU пока не подключены.
            npx serve dist и Node-сервер симуляции не запускают Python-ядро.
          </Note></div>
        </Card>

        {/* 03 · карта API */}
        <Card className="overflow-hidden p-0!">
          <div className="p-5 sm:p-6">
            <Overline>03 · Карта «действие UI → модуль → endpoint»</Overline>
            <p className="mt-3 max-w-2xl text-[13.5px] leading-relaxed text-ink2">
              API реализован в securitylab/dashboard.py и вызывает модули ядра. Отмена access-ai возвращает явный отказ до реализации безопасной остановки.
            </p>
          </div>
          <div className="overflow-x-auto border-t border-line">
            <table className="tbl min-w-[680px]">
              <thead>
                <tr>
                  <th>Действие в UI</th>
                  <th>Ожидаемый модуль</th>
                  <th>Предлагаемый endpoint</th>
                </tr>
              </thead>
              <tbody>
                {ENDPOINTS.map((e) => (
                  <tr key={e.endpoint}>
                    <td className="text-ink2">{e.action}</td>
                    <td className="font-mono text-[12px] text-ink3">{e.module}</td>
                    <td className="font-mono text-[12px] font-semibold">{e.endpoint}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {/* 04 · контракт адаптера */}
        <section>
          <Overline>04 · Контракт адаптера</Overline>
          <div className="mt-3.5 grid gap-5 lg:grid-cols-2">
            <Card className="bg-dim! shadow-none!">
              <div className="font-mono text-[13px] font-bold">adapter/types.ts</div>
              <p className="mt-2.5 text-[13.5px] leading-relaxed text-ink2">
                Типы Run, Check, Attempt, Artifact, PreflightResult и интерфейс SecurityLabAdapter: listProjects,
                listRuns, getRun, createRun (202 + run_id), cancelRun, preflight, pingModel, exportPatch,
                getArtifact, diagnostics, health.
              </p>
            </Card>
            <Card className="bg-dim! shadow-none!">
              <div className="font-mono text-[13px] font-bold">adapter/demo.ts · adapter/http.ts</div>
              <p className="mt-2.5 text-[13.5px] leading-relaxed text-ink2">
                DemoAdapter — демо-данные в браузере и честные отказы без backend. HttpAdapter — клиент
                референсного сервера: запросы к loopback, GET /api/csrf + заголовок X-CSRF-Token для изменяющих
                операций, abort по тайм-ауту, JSON; человекочитаемый stdout CLI как API не парсится.
              </p>
            </Card>
          </div>
        </section>

        {/* 05 · безопасность отображения */}
        <Card>
          <Overline>05 · Безопасность отображения</Overline>
          <ul className="mt-4 max-w-3xl list-none space-y-2.5 text-[14px] leading-relaxed text-ink2">
            {[
              'логи, diff, JSON и HTML-отчёты — недоверенный контент: выводятся как текст, innerHTML не используется; строки со <script> и onerror в демо-логах не исполняются',
              'артефакты отдаются только по идентификаторам: запрос ../../etc/passwd отклоняется (проверка traversal)',
              'нет кнопок «принять как безопасное», merge/push; политика не редактируется и не ослабляется из UI',
              'хеш — журнал целостности и привязки, не криптографическая подпись и не гарантия отсутствия всех уязвимостей',
              'код проектов не загружается во внешние сервисы из браузера',
            ].map((t) => (
              <li key={t} className="flex gap-3">
                <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true" />
                <span>{t}</span>
              </li>
            ))}
          </ul>
        </Card>

        {/* 06 · работает / отложено */}
        <Card>
          <Overline>06 · Что работает и что отложено</Overline>
          <div className="mt-4 grid gap-8 lg:grid-cols-2">
            <div>
              <div className="mb-3.5 flex items-center gap-2"><Chip tone="mint">работает (демо + референсный сервер)</Chip></div>
              <ul className="list-none space-y-2 text-[13.5px] leading-relaxed text-ink2">
                {[
                  'чтение всех разделов на демо-данных с явной пометкой «демо»',
                  'раздельные статусы: выполнение / security_verdict / finding_status',
                  'все попытки Blue с diff, причинами отклонения и независимыми проверками',
                  'BLOCKED / TIMEOUT / NEEDS_REVIEW / NOT_EVALUATED не показываются зелёным',
                  'предпроверка с четырьмя состояниями, честный отказ второго запуска',
                  'симуляция прогона, переживает перезагрузку страницы (localStorage)',
                  'экспорт подтверждённого патча, absent-артефакт с причиной',
                  'подключение к референсному серверу: регистрация проекта (fs.stat), снимки, отмена прогона, реальные CPU/память в диагностике',
                  'светлая и тёмная темы, клавиатура, мобильные таблицы «поле — значение»',
                ].map((t) => <li key={t} className="flex gap-3"><span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-mint" aria-hidden="true" />{t}</li>)}
              </ul>
            </div>
            <div>
              <div className="mb-3.5 flex items-center gap-2"><Chip tone="warn">отложено до боевого backend</Chip></div>
              <ul className="list-none space-y-2 text-[13.5px] leading-relaxed text-ink2">
                {[
                  'реальные Docker-прогоны с воспроизведением нарушения и Git-коммитом патча',
                  'очередь фоновых заданий; восстановление после рестарта не обещается',
                  'WebSocket/SSE-события — документом не подтверждены, сервер отдаёт состояние по GET',
                  'GPU-метрики — os.* не знает о GPU, показывается «нет данных»',
                  'редактирование политик и профилей, поддержка стеков помимо FastAPI',
                ].map((t) => <li key={t} className="flex gap-3"><span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-warn" aria-hidden="true" />{t}</li>)}
              </ul>
            </div>
          </div>
        </Card>

        {/* 07 · инструкция */}
        <Card>
          <Overline>07 · Инструкция</Overline>
          <ol className="mt-4 max-w-3xl list-none space-y-4 text-[14px] leading-relaxed text-ink2">
            {[
              ['Сборка и запуск', 'npm install → npm run dev (dev-сервер) или npm run build → npm run preview (статика из dist/). Прямое открытие file:// браузеры блокируют для ES-модулей.'],
              ['Референсный сервер', 'node server/server.mjs → http://127.0.0.1:8765. Данные — server/seed.json (перегенерация: node scripts/dump-seed.mjs). Затем на этом экране нажмите «Проверить соединение» — режим в шапке сменится на backend.'],
              ['Первый обход', 'Проекты → «orders-api»: снимки и история. «Новый запуск»: заполните 01–04, выполните предпроверку, запустите — прогон развивается в реальном времени и помечен как демо.'],
              ['Разбор результата', 'Деталь прогона: вкладки «Проверки», «Предложения и попытки» (все попытки, включая отклонённые), «Доказательства» (артефакты, привязки, очистка), длительности этапов на графике.'],
              ['Отказы', 'Второй запуск при активном, отмена, отсутствие модели, недоступный backend — все отказы показываются честно с причиной.'],
              ['Для боевой интеграции', 'Пришлите репозиторий (cli.py, access_ai.py, ai_workflow.py, storage.py, hermes_adapter.py, ai_config.py и примеры summary/receipts) — карта API сверяется с кодом, референсный сервер заменяется боевой реализацией.'],
            ].map(([h, t]) => (
              <li key={h} className="grid gap-x-6 gap-y-1 sm:grid-cols-[150px_1fr]">
                <span className="font-bold text-ink">{h}</span>
                <span>{t}</span>
              </li>
            ))}
          </ol>
        </Card>
      </div>
    </>
  )
}
