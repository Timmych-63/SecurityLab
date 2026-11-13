/**
 * SecurityLab reference server — реализация карты endpoint'ов из UI.
 *
 * Zero-dependency Node (>=18): http, fs, crypto, os, net, child_process.
 * Слушает ТОЛЬКО loopback (127.0.0.1). Изменяющие операции защищены
 * GET /api/csrf + заголовок X-CSRF-Token, список Origin/Host ограничен явно,
 * размер тела ограничен ДО накопления (64 КБ).
 *
 * Честность данных: операции над реестром (проекты, снимки, запуски, отмена,
 * артефакты) выполняются реально и переживают рестарт (state.json); прогоны —
 * сценарии симуляции (demo: true); предпроверка реально вызывает docker/model
 * на хосте и честно фиксирует отсутствие; это симулятор для разработки UI,
 * не параллельное ядро SecurityLab.
 *
 * Запуск: node server/server.mjs  (PORT=8765 по умолчанию,
 * SLB_ALLOWED_ORIGINS=http://a:1,http://b:2 — расширить список Origin)
 */
import http from 'node:http'
import fs from 'node:fs'
import os from 'node:os'
import net from 'node:net'
import path from 'node:path'
import crypto from 'node:crypto'
import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const PORT = Number(process.env.PORT ?? 8765)
const HOST = '127.0.0.1'
const CSRF_TTL_MS = 60 * 60 * 1000
const BODY_LIMIT = 64 * 1024
const STATE_FILE = path.join(HERE, 'state.json')

/* ---------- seed + персистентность ---------- */

const seed = JSON.parse(readFileSync(path.join(HERE, 'seed.json'), 'utf8'))

/** @type {Array} реестр проектов (mutable) */
let projects = seed.projects.map((p) => ({ ...p, snapshots: [...p.snapshots] }))
const policies = seed.policies
let aiConfigs = seed.aiConfigs.map((c) => ({ ...c }))
/** @type {Map<string, object>} все прогоны: seed + созданные */
const runs = new Map()
for (const r of seed.demoRuns) runs.set(r.id, { ...r, artifacts: r.artifacts.map((a) => ({ ...a })) })

/** Реестр переживает рестарт сервера (#11): изменения не исчезают молча. */
function persist() {
  try {
    writeFileSync(STATE_FILE, JSON.stringify({ savedAt: new Date().toISOString(), projects, aiConfigs, runs: [...runs.values()] }))
  } catch {
    /* отсутствие записи не ломает работу: реестр остаётся в памяти */
  }
}
function restore() {
  if (!existsSync(STATE_FILE)) return false
  try {
    const st = JSON.parse(readFileSync(STATE_FILE, 'utf8'))
    if (Array.isArray(st.projects)) projects = st.projects
    if (Array.isArray(st.aiConfigs)) aiConfigs = st.aiConfigs
    if (Array.isArray(st.runs)) for (const r of st.runs) runs.set(r.id, r)
    return true
  } catch {
    return false
  }
}
const restored = restore()

/* ---------- симуляция прогона (порт resolveLiveRun из адаптера) ---------- */

const runElapsedSec = (run, nowMs) => Math.max(0, (nowMs - Date.parse(run.startedAt)) / 1000)

function isRunActive(run, nowMs) {
  if (run.cancelledAt) return false
  if (!run.script) return false
  return runElapsedSec(run, nowMs) < run.script.finishAt
}

/** Разворачивает сценарий на момент now; у отменённого прогона состояние замораживается на момент отмены. */
function resolveRun(run, nowMs = Date.now()) {
  if (!run.script) return stripScript(run)
  const stopMs = run.cancelledAt ? Date.parse(run.cancelledAt) : nowMs
  const elapsed = runElapsedSec(run, stopMs)
  const s = run.script
  const finished = !run.cancelledAt && elapsed >= s.finishAt
  const stages = s.stages.map((st) => {
    if (run.cancelledAt && elapsed >= st.from && !(st.to !== undefined && elapsed >= st.to)) {
      return { id: st.id, label: st.label, role: st.role, state: 'skipped', startedAt: st.from, detail: 'остановлено отменой прогона' }
    }
    if (elapsed >= (st.to ?? s.finishAt)) {
      return { id: st.id, label: st.label, role: st.role, state: st.state === 'wait_model' ? 'done' : st.state, startedAt: st.from, finishedAt: st.to, detail: st.detail }
    }
    if (elapsed >= st.from) {
      const waiting = st.waitModelFrom !== undefined && elapsed >= st.waitModelFrom
      return { id: st.id, label: st.label, role: st.role, state: waiting ? 'wait_model' : 'running', startedAt: st.from, detail: waiting ? 'ожидаем ответ — событий нет; процент готовности не показывается' : undefined }
    }
    return { id: st.id, label: st.label, role: st.role, state: 'pending' }
  })
  const resolved = {
    ...run,
    exec: run.cancelledAt ? 'cancelled' : finished ? s.final.exec : 'running',
    verdict: finished ? s.final.verdict : 'NOT_EVALUATED',
    finding: finished ? s.final.finding : 'NOT_EVALUATED',
    finishedAt: run.cancelledAt ? run.cancelledAt : finished ? new Date(Date.parse(run.startedAt) + s.finishAt * 1000).toISOString() : undefined,
    stages,
    events: run.cancelledAt
      ? [...s.events.filter((e) => e.t <= elapsed), { t: Math.floor(elapsed), source: 'securitylab', text: 'отмена подтверждена сервером: прогон остановлен, контейнеры очищены (сценарий симуляции)' }]
      : s.events.filter((e) => e.t <= elapsed),
    checks: finished ? run.checks : [],
    attempts: finished ? run.attempts : [],
    redProposal: finished ? run.redProposal : undefined,
    commit: finished ? run.commit : undefined,
  }
  return stripScript(resolved)
}

function stripScript(run) {
  const { script: _s, ...rest } = run
  return rest
}

/* ---------- изменяющие операции ---------- */

const sha7 = (data) => crypto.createHash('sha256').update(data).digest('hex').slice(0, 7)

/**
 * Платформенная проверка абсолютного пути (#9): Windows drive/UNC — на Windows,
 * POSIX-путь — на POSIX. На POSIX windows-путь честно отклоняется с объяснением.
 */
function checkAbsolutePath(inputPath) {
  const p = String(inputPath ?? '').trim()
  if (!p) return { error: 'путь не указан' }
  if (/^[a-zA-Z]:[\\/]/.test(p) || p.startsWith('\\\\')) {
    if (process.platform === 'win32') return { p }
    return { error: 'путь в формате Windows (C:\\…), а сервер работает на POSIX-хосте: проверить существование такого пути невозможно. Референсный сервер нужно запускать на той же машине, где лежит репозиторий' }
  }
  if (!path.isAbsolute(p)) {
    return { error: 'сервер принимает только абсолютный локальный путь; относительный путь нельзя однозначно привязать к репозиторию' }
  }
  return { p }
}

function registerProject(inputPath) {
  const chk = checkAbsolutePath(inputPath)
  if (chk.error) return { status: 422, body: { ok: false, reason: chk.error } }
  const p = chk.p
  let stat
  try {
    stat = fs.statSync(p)
  } catch {
    return { status: 422, body: { ok: false, reason: `путь ${p} не найден на сервере: регистрация выполняется только для существующего локального каталога (проверка fs.stat — реальная серверная операция; приём репозитория ядром SecurityLab заменит её на штатный механизм)` } }
  }
  if (!stat.isDirectory()) {
    return { status: 422, body: { ok: false, reason: `${p} — не каталог; проект регистрируется от корня репозитория` } }
  }
  const base = path.basename(p)
  const existing = projects.find((x) => x.path === p)
  if (existing) {
    return { status: 409, body: { ok: false, reason: `проект по пути ${p} уже зарегистрирован (${existing.id})` } }
  }
  const id = `proj-${base.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24)}-${sha7(p).slice(0, 4)}`
  const project = {
    id,
    name: base,
    path: p,
    stack: 'не определён',
    profile: '—',
    supported: false,
    unsupportedReason: 'стек и профиль определяются ядром/оператором: референсный сервер не определяет стек автоматически и не выдаёт неподдерживаемый запуск за поддерживаемый',
    snapshots: [],
    services: [],
    stateDir: 'TEMP/SecurityLab_S72_DemoState',
  }
  projects.push(project)
  persist()
  return { status: 201, body: project }
}

function createSnapshot(projectId) {
  const p = projects.find((x) => x.id === projectId)
  if (!p) return { status: 404, body: { ok: false, reason: 'проект не найден' } }
  if (!p.supported) return { status: 422, body: { ok: false, reason: `стек проекта не поддерживается: ${p.unsupportedReason}` } }
  const now = new Date()
  const snap = {
    id: `snap-${sha7(p.id + now.toISOString()).slice(0, 7)}`,
    commit: sha7(`${p.id}:${p.snapshots.length}:${now.toISOString()}`),
    createdAt: now.toISOString(),
    note: 'запись в реестре сервера без содержимого и manifest — снимок с содержимым создаёт ядро SecurityLab; это симулятор, не ядро',
  }
  p.snapshots.push(snap)
  persist()
  return { status: 201, body: snap }
}

/* ---------- валидация создания прогона (#6) ---------- */

const ENTRY_RE = /^[\w][\w./:-]*$/

function validateRunInput(body) {
  const errs = []
  const projectId = body?.projectId
  const project = projects.find((x) => x.id === projectId)
  if (!project) errs.push(`projectId «${projectId ?? '—'}» отсутствует в реестре проектов`)
  else {
    if (!project.supported) errs.push(`стек проекта не поддерживается: ${project.unsupportedReason}`)
    if (body?.snapshotId && !project.snapshots.some((s) => s.id === body.snapshotId)) {
      errs.push(`snapshotId «${body.snapshotId}» не принадлежит проекту ${project.id}`)
    }
    if (project.profile && project.profile !== '—' && body?.profileId && body.profileId !== project.profile) {
      errs.push(`profileId «${body.profileId}» не совпадает с профилем проекта (${project.profile})`)
    }
    // сервис и точка входа — только из принятого набора проекта (#3)
    if (project.services?.length) {
      const svc = project.services.find((s) => s.service === body?.service)
      if (!svc) errs.push(`service «${body?.service ?? '—'}» не входит в набор сервиса проекта (${project.services.map((s) => s.service).join(', ')})`)
      else if (body?.entryModule !== svc.entryFile && body?.entryModule !== svc.entryImport) {
        errs.push(`entryModule «${body?.entryModule}» не соответствует точке входа проекта (${svc.entryFile} / ${svc.entryImport})`)
      }
    }
  }
  if (!body?.snapshotId) errs.push('snapshotId не указан')
  if (!body?.service) errs.push('service не указан')
  if (!body?.entryModule) errs.push('entryModule не указан')
  else if (!ENTRY_RE.test(body.entryModule) || body.entryModule.includes('..')) {
    errs.push(`entryModule «${body.entryModule}» отклонён: допустимы путь файла (app/main.py) или ASGI import string (app.main:app) из набора проекта; преобразование выполняет backend`)
  }
  if (!policies.some((x) => x.id === body?.policyId)) errs.push(`policyId «${body?.policyId ?? '—'}» отсутствует в реестре политик`)
  const cfg = aiConfigs.find((x) => x.id === body?.aiConfigId)
  if (!cfg) errs.push(`aiConfigId «${body?.aiConfigId ?? '—'}» отсутствует в реестре конфигураций`)
  else if (!/^sha256:[a-f0-9]{64}$/.test(cfg.digest ?? '')) {
    // приёмка аудита: конфигурация с сокращённым/невалидным digest не запускает выполнение
    errs.push(`у конфигурации ${cfg.id} некорректный digest (ожидается sha256 + 64 hex): запуск запрещён, исправьте конфигурацию`)
  }
  const sd = body?.stateDir
  if (!sd) errs.push('stateDir (state-каталог ядра) не указан')
  else if (typeof sd === 'string' && (sd.includes('..') || path.isAbsolute(sd))) {
    errs.push(`stateDir «${sd}» отклонён: ожидается относительный каталог состояния ядра (например, TEMP/SecurityLab_S72_DemoState)`)
  }
  return errs
}

function buildServerRun(input) {
  const id = `run-srv-${crypto.randomBytes(2).toString('hex')}`
  const diff = seed.fixDiff
  const run = {
    id,
    demo: true, // сценарий прогона — симуляция; сервер честно помечает это
    projectId: input.projectId,
    snapshotId: input.snapshotId,
    service: input.service,
    entryModule: input.entryModule,
    profileId: input.profileId,
    policyId: input.policyId,
    aiConfigId: input.aiConfigId,
    stateDir: input.stateDir,
    mode: 'ai_red_blue',
    startedAt: new Date().toISOString(),
    timeLimitMin: 20,
    exec: 'running',
    verdict: 'NOT_EVALUATED',
    finding: null,
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
    commit: { ref: 'fix/slb-s2', sha: sha7(`${id}${diff}`), isolated: true },
    artifacts: [
      { id: 'art-sum', name: 'summary.json', kind: 'json', present: true, content: `{\n  "run_id": "${id}",\n  "demo": true,\n  "security_verdict": "REPRODUCED",\n  "finding_status": "POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX"\n}` },
      { id: 'art-p1', name: 'candidate-1.patch', kind: 'patch', present: true, content: diff },
      { id: 'art-log', name: 'container.log', kind: 'log', present: false, absentReason: 'файл удалён при очистке контейнера после прогона — ожидаемое поведение очистки (сценарий симуляции)' },
    ],
    tech: {
      image: 'securitylab-demo:local',
      imageDigest: 'sha256:ab12f0…9c33',
      network: 'slb-internal (изолированная, без выхода в интернет)',
      configHash: `sha256:${sha7(JSON.stringify(input))}…`,
      snapshotPin: input.snapshotId,
      cleanup: 'контейнеры и тома удалены по завершении прогона (сценарий симуляции)',
      hashDisclaimer: 'хеши — журнал целостности и привязки, не криптографическая подпись и не гарантия. Прогон — сценарий симуляции, помечен demo: true; коммиты и события сценария — фиктивные.',
    },
    script: JSON.parse(JSON.stringify(seed.newRunScript)),
  }
  return run
}

/* ---------- реальные проверки хоста (#5: образы по профилю, честный ping) ---------- */

const PROFILE_IMAGES = ['securitylab-demo:local', 'securitylab-hermes:s4', 'securitylab-fastapi:local']

const execP = (cmd, args, timeoutMs = 3000) =>
  new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs }, (err, stdout) => resolve(err ? null : String(stdout)))
  })

async function tcpProbe(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port })
    const done = (ok) => { s.destroy(); resolve(ok) }
    s.setTimeout(timeoutMs, () => done(false))
    s.once('connect', () => done(true))
    s.once('error', () => done(false))
  })
}

function parseEndpoint(server) {
  try {
    const u = new URL(server)
    return { host: u.hostname, port: Number(u.port) || 80 }
  } catch {
    return null
  }
}

async function preflight(input) {
  const checkedAt = new Date().toISOString()
  // docker — реальный вызов CLI на хосте
  const dockerOk = (await execP('docker', ['version', '--format', '{{.Server.Version}}']))?.trim()
  const docker = dockerOk
    ? { docker: 'verified', dockerDetail: `docker engine ${dockerOk} отвечает на хосте` }
    : { docker: 'error', dockerDetail: 'docker CLI не найден или не отвечает на сервере — запуск контейнеров невозможен, предпроверка честно это фиксирует' }
  // образы — реальные inspect по образам профиля, только если docker есть
  let images
  if (dockerOk) {
    const found = []
    for (const img of PROFILE_IMAGES) {
      if (await execP('docker', ['image', 'inspect', img, '--format', '{{.Id}}'])) found.push(img)
    }
    images = found.length === PROFILE_IMAGES.length
      ? { images: 'verified', imagesDetail: `образы профиля найдены локально: ${found.join(', ')}` }
      : found.length > 0
        ? { images: 'error', imagesDetail: `из образов профиля найдены: ${found.join(', ')}; отсутствуют: ${PROFILE_IMAGES.filter((i) => !found.includes(i)).join(', ')} — проверьте профиль стенда` }
        : { images: 'error', imagesDetail: `образы профиля (${PROFILE_IMAGES.join(', ')}) не найдены локально — проверьте профиль стенда и способ доставки образов` }
  } else {
    images = { images: 'untested', imagesDetail: 'не проверялся: docker недоступен' }
  }
  // модель: TCP-пробой адреса из конфигурации — это «порт доступен», НЕ «модель отвечает»
  const cfg = aiConfigs.find((c) => c.id === input?.aiConfigId)
  const ep = cfg ? parseEndpoint(cfg.server) : null
  let model
  if (!ep) {
    model = { model: 'error', modelDetail: 'адрес сервера в конфигурации не разбирается' }
  } else {
    const up = await tcpProbe(ep.host, ep.port)
    model = up
      ? { model: 'verified', modelDetail: `TCP-пробой: порт ${ep.host}:${ep.port} доступен с хоста сервера. Это НЕ подтверждает выбранную модель, её digest и генерацию: модель живёт в приватной сети slb-internal, HTTP-вызов Hermes референсный сервер не выполняет (проверка из правильной сетевой среды — за ядром)` }
      : { model: 'error', modelDetail: `${ep.host}:${ep.port} не отвечает — порт недоступен с хоста сервера; модель в приватной сети не проверялась` }
  }
  return { ...docker, ...images, ...model, checkedAt, params: input ?? null }
}

function diagnostics() {
  const cpus = os.cpus()
  const total = os.totalmem()
  const free = os.freemem()
  const gb = (n) => `${(n / 2 ** 30).toFixed(1)} ГБ`
  return {
    available: true,
    note: 'значения собраны реальным сервером через os.* в момент запроса; GPU-метрик нет — модуль GPU не реализован',
    cpu: `${cpus.length} × ${cpus[0]?.model ?? 'неизвестно'} · load ${os.loadavg().map((x) => x.toFixed(2)).join(' / ')}`,
    memory: `свободно ${gb(free)} из ${gb(total)}`,
    gpu: null,
    uptime: `uptime сервера ${Math.floor(os.uptime() / 3600)} ч ${Math.floor((os.uptime() % 3600) / 60)} мин`,
  }
}

/**
 * Структурная проверка записи конфигурации (#5): полный digest — ровно
 * 64 lowercase hex после «sha256:». Правила валидатора ядра (ai_config.py)
 * остаются эталоном; здесь — совпадающий по смыслу референс.
 */
function validateConfig(id) {
  const c = aiConfigs.find((x) => x.id === id)
  if (!c) return { valid: false, detail: 'конфигурация не найдена' }
  const problems = []
  if (!c.model) problems.push('не указана модель')
  const m = /^sha256:([a-f0-9]{64})$/.exec(c.digest ?? '')
  if (!m) problems.push(`digest должен быть «sha256:» + ровно 64 символа [a-f0-9] (получено: «${c.digest}»); сокращённые визуальные формы не проходят валидацию`)
  if (!(Number.isFinite(c.contextTokens) && c.contextTokens >= 64000)) problems.push(`контекст ${c.contextTokens} ниже минимума текущего Hermes (64 000)`)
  if (!c.server || !parseEndpoint(c.server)) problems.push('внутренний адрес сервера не разбирается как URL')
  if (!(Number.isFinite(c.timeoutSeconds) && c.timeoutSeconds > 0)) problems.push('timeoutSeconds должен быть положительным числом')
  if (!(Number.isFinite(c.maxOutputTokens) && c.maxOutputTokens > 0)) problems.push('maxOutputTokens должен быть положительным числом')
  if (problems.length) return { valid: false, detail: `структурная проверка записи конфигурации не пройдена: ${problems.join('; ')}` }
  return { valid: true, detail: 'структурная проверка записи конфигурации пройдена (модель, полный digest 64 hex, контекст ≥ 64 000, сеть, лимиты). Это проверка записи, не TOML-файла: разбор TOML и полный валидатор ядра (ai_config.py) остаются эталоном. Доступность модели проверяется отдельно (ping-model).' }
}

async function pingModel(id) {
  const c = aiConfigs.find((x) => x.id === id)
  if (!c) return { ok: false, detail: 'конфигурация не найдена' }
  const ep = parseEndpoint(c.server)
  if (!ep) return { ok: false, detail: 'адрес сервера в конфигурации не разбирается' }
  const up = await tcpProbe(ep.host, ep.port, 2000)
  return up
    ? { ok: true, detail: `порт ${ep.host}:${ep.port} доступен с хоста сервера (TCP). Порт доступен ≠ модель отвечает: модель «${c.model}» не проверялась — HTTP-вызов Hermes референсный сервер не выполняет; проверка из приватной сети — за ядром` }
    : { ok: false, detail: `${ep.host}:${ep.port} не отвечает — порт недоступен с хоста сервера; модель «${c.model}» не проверялась` }
}

/* ---------- HTTP-обвязка: Origin/Host + CSRF ---------- */

/** Явный список разрешённых Origin для локального deployment (доп. правка аудита). */
const ALLOWED_ORIGINS = new Set(
  (process.env.SLB_ALLOWED_ORIGINS ?? 'http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:4173,http://localhost:4173,http://127.0.0.1:8765,http://localhost:8765')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
)

function originAllowed(origin) {
  if (!origin) return true // curl/same-origin без Origin
  return ALLOWED_ORIGINS.has(origin)
}

function hostAllowed(hostHeader) {
  if (!hostHeader) return false
  const h = hostHeader.toLowerCase()
  return h === `127.0.0.1:${PORT}` || h === `localhost:${PORT}` || h === HOST
}

let csrfToken = null
let csrfIssued = 0
function issueCsrf() {
  if (!csrfToken || Date.now() - csrfIssued > CSRF_TTL_MS) {
    csrfToken = crypto.randomUUID()
    csrfIssued = Date.now()
  }
  return csrfToken
}

function json(res, status, body, origin) {
  const payload = JSON.stringify(body)
  const headers = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers['Access-Control-Allow-Origin'] = origin
    headers['Vary'] = 'Origin'
  }
  res.writeHead(status, headers)
  res.end(payload)
}

/** путь из URL без декодирования %2F (идентификаторы — только [\w-]) */
function url_path(req) {
  try {
    const u = new URL(req.url, `http://${HOST}:${PORT}`)
    return u.pathname
  } catch {
    return '/'
  }
}

/* ---------- маршруты ---------- */

const routes = []
const route = (method, pattern, handler) => routes.push({ method, pattern, handler })

route('GET', /^\/api\/health$/, (m, q, body, req, res, origin) =>
  json(res, 200, {
    ok: true,
    service: 'securitylab-reference-server',
    mode: 'simulated-data', // боевой backend ответит mode: 'securitylab-core'
    demo: true,
    persisted: restored,
    note: 'операции над реестром выполняются реально и переживают рестарт (state.json); прогоны — сценарии симуляции, помечены demo: true; это симулятор, не ядро',
    time: new Date().toISOString(),
  }, origin))

route('GET', /^\/api\/csrf$/, (m, q, body, req, res, origin) =>
  json(res, 200, { token: issueCsrf(), expiresInMs: CSRF_TTL_MS }, origin))

route('GET', /^\/api\/projects$/, (m, q, body, req, res, origin) =>
  json(res, 200, projects, origin))

route('GET', /^\/api\/projects\/([\w-]+)\/snapshots$/, (m, q, body, req, res, origin) => {
  const p = projects.find((x) => x.id === m[1])
  return p ? json(res, 200, p.snapshots, origin) : json(res, 404, { ok: false, reason: 'проект не найден' }, origin)
})

route('POST', /^\/api\/projects$/, (m, q, body, req, res, origin) => {
  const out = registerProject(body?.path)
  return json(res, out.status, out.body, origin)
})

route('POST', /^\/api\/projects\/([\w-]+)\/snapshots$/, (m, q, body, req, res, origin) => {
  const out = createSnapshot(m[1])
  return json(res, out.status, out.body, origin)
})

route('GET', /^\/api\/policies$/, (m, q, body, req, res, origin) =>
  json(res, 200, policies, origin))

route('GET', /^\/api\/ai-configs$/, (m, q, body, req, res, origin) =>
  json(res, 200, aiConfigs, origin))

route('POST', /^\/api\/ai-configs\/([\w-]+)\/validate$/, (m, q, body, req, res, origin) =>
  json(res, 200, validateConfig(m[1]), origin))

route('POST', /^\/api\/ai-configs\/([\w-]+)\/ping-model$/, async (m, q, body, req, res, origin) =>
  json(res, 200, await pingModel(m[1]), origin))

route('POST', /^\/api\/preflight$/, async (m, q, body, req, res, origin) =>
  json(res, 200, await preflight(body), origin))

route('GET', /^\/api\/runs$/, (m, q, body, req, res, origin) => {
  const now = Date.now()
  let out = [...runs.values()].map((r) => resolveRun(r, now))
  if (q.get('projectId')) out = out.filter((r) => r.projectId === q.get('projectId'))
  if (q.get('status') && q.get('status') !== 'all') out = out.filter((r) => r.exec === q.get('status'))
  if (q.get('mode') && q.get('mode') !== 'all') out = out.filter((r) => r.mode === q.get('mode'))
  if (q.get('dateRange') && q.get('dateRange') !== 'all') {
    const cutoff = now - (q.get('dateRange') === '24h' ? 864e5 : 7 * 864e5)
    out = out.filter((r) => Date.parse(r.startedAt) >= cutoff)
  }
  out.sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt))
  return json(res, 200, out, origin)
})

route('GET', /^\/api\/runs\/([\w-]+)$/, (m, q, body, req, res, origin) => {
  const run = runs.get(m[1])
  return run ? json(res, 200, resolveRun(run), origin) : json(res, 404, { ok: false, reason: 'прогон не найден' }, origin)
})

route('POST', /^\/api\/runs$/, (m, q, body, req, res, origin) => {
  const now = Date.now()
  const active = [...runs.values()].find((r) => isRunActive(r, now))
  if (active) {
    return json(res, 409, {
      ok: false,
      reason: `Активный прогон уже выполняется (${active.id}). Очередь фоновых заданий в референсном сервере не реализована — второй запуск отклоняется, а не ставится в невидимую очередь.`,
    }, origin)
  }
  // валидация ссылок и принадлежности (#6): unknown ID / плохой entry / чужой снимок не запускаются
  const errs = validateRunInput(body)
  if (errs.length) {
    return json(res, 422, { ok: false, reason: `запуск отклонён сервером: ${errs.join('; ')}` }, origin)
  }
  const run = buildServerRun(body)
  runs.set(run.id, run)
  persist()
  return json(res, 202, { runId: run.id, status: 'accepted', note: 'прогон принят; ход выполнения читается через GET /api/runs/{id}' }, origin)
})

route('POST', /^\/api\/runs\/([\w-]+)\/cancel$/, (m, q, body, req, res, origin) => {
  const run = runs.get(m[1])
  if (!run) return json(res, 404, { ok: false, reason: 'прогон не найден' }, origin)
  if (run.cancelledAt) return json(res, 200, { ok: true, state: 'cancelled', runId: run.id }, origin)
  if (!isRunActive(run, Date.now())) {
    return json(res, 409, { ok: false, reason: 'прогон уже завершён — отменять нечего' }, origin)
  }
  run.cancelledAt = new Date().toISOString()
  persist()
  return json(res, 200, { ok: true, state: 'cancelled', runId: run.id, note: 'отмена подтверждена сервером; состояние заморожено на момент отмены' }, origin)
})

route('GET', /^\/api\/runs\/([\w-]+)\/attempts\/(\d+)\/diff$/, (m, q, body, req, res, origin) => {
  const run = runs.get(m[1])
  const attempt = run?.attempts.find((a) => a.n === Number(m[2]))
  if (!attempt) return json(res, 404, { ok: false, reason: 'попытка не найдена' }, origin)
  return json(res, 200, { fileName: `${run.id}-attempt-${attempt.n}.patch`, content: attempt.diff }, origin)
})

route('GET', /^\/api\/runs\/([\w-]+)\/patch$/, (m, q, body, req, res, origin) => {
  const run = runs.get(m[1])
  if (!run) return json(res, 404, { ok: false, reason: 'прогон не найден' }, origin)
  const resolved = resolveRun(run)
  if (!resolved.commit) {
    return json(res, 409, { ok: false, reason: 'Подтверждённый отдельный коммит у прогона отсутствует — экспортировать нечего.' }, origin)
  }
  const diff = resolved.attempts.find((a) => a.status === 'accepted')?.diff ?? ''
  return json(res, 200, { fileName: `${run.id}-patch.patch`, content: diff }, origin)
})

route('GET', /^\/api\/runs\/([\w-]+)\/artifacts\/([\w-]+)$/, (m, q, body, req, res, origin) => {
  const [, runId, artId] = m
  // traversal-защита: идентификаторы строго [A-Za-z0-9-], пути не принимаются
  if (!/^[A-Za-z0-9][A-Za-z0-9-]*$/.test(artId) || artId.includes('..')) {
    return json(res, 400, { ok: false, reason: 'Идентификатор артефакта отклонён (проверка traversal): пути не принимаются.' }, origin)
  }
  const run = runs.get(runId)
  const art = run?.artifacts.find((a) => a.id === artId)
  if (!art) return json(res, 404, { ok: false, reason: 'артефакт не найден в этом прогоне' }, origin)
  if (!art.present) return json(res, 409, { ok: false, reason: art.absentReason ?? 'артефакт отсутствует' }, origin)
  return json(res, 200, art, origin)
})

route('GET', /^\/api\/diagnostics$/, (m, q, body, req, res, origin) =>
  json(res, 200, diagnostics(), origin))

/* ---------- сервер ---------- */

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin
  // Host-заголовок: защита от DNS-rebinding, даже при loopback-бинде
  if (!hostAllowed(req.headers.host)) {
    return json(res, 403, { ok: false, reason: `Host «${req.headers.host}» не входит в разрешённые (127.0.0.1:${PORT} / localhost:${PORT})` })
  }

  // preflight CORS
  if (req.method === 'OPTIONS') {
    if (origin && !originAllowed(origin)) return json(res, 403, { ok: false, reason: `Origin «${origin}» не входит в разрешённый список (SLB_ALLOWED_ORIGINS)` })
    res.writeHead(204, {
      'Access-Control-Allow-Origin': origin ?? '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token, Accept',
      'Access-Control-Max-Age': '600',
    })
    return res.end()
  }

  const pathname = url_path(req)
  const match = routes.find((r) => r.method === req.method && r.pattern.test(pathname))
  if (!match) return json(res, 404, { ok: false, reason: `нет маршрута ${req.method} ${pathname}` }, origin)

  // изменяющие операции: Origin + CSRF
  if (req.method === 'POST') {
    if (origin && !originAllowed(origin)) {
      return json(res, 403, { ok: false, reason: `отклонено: Origin «${origin}» не входит в разрешённый список` }, origin)
    }
    const token = req.headers['x-csrf-token']
    if (!token || token !== issueCsrf()) {
      return json(res, 403, { ok: false, reason: 'отклонено (CSRF): изменяющие операции требуют свежий токен из GET /api/csrf в заголовке X-CSRF-Token' }, origin)
    }
  }

  let body
  if (req.method === 'POST') {
    // лимит размера тела — ДО накопления (Content-Length) и при чтении потока
    const declared = Number(req.headers['content-length'] ?? 0)
    if (declared > BODY_LIMIT) {
      return json(res, 413, { ok: false, reason: `тело запроса ${declared} байт превышает лимит ${BODY_LIMIT} байт` }, origin)
    }
    const chunks = []
    let size = 0
    let tooBig = false
    for await (const ch of req) {
      size += ch.length
      if (size > BODY_LIMIT) { tooBig = true; break }
      chunks.push(ch)
    }
    if (tooBig) {
      return json(res, 413, { ok: false, reason: `тело запроса превышает лимит ${BODY_LIMIT} байт` }, origin)
    }
    const raw = Buffer.concat(chunks).toString('utf8')
    if (raw) {
      try {
        body = JSON.parse(raw)
      } catch {
        return json(res, 400, { ok: false, reason: 'тело запроса не является корректным JSON' }, origin)
      }
    }
  }

  try {
    await match.handler(pathname.match(match.pattern), new URL(req.url, `http://${HOST}:${PORT}`).searchParams, body, req, res, origin)
  } catch (e) {
    return json(res, 500, { ok: false, reason: `внутренняя ошибка: ${e instanceof Error ? e.message : 'неизвестно'}` }, origin)
  }
})

server.listen(PORT, HOST, () => {
  console.log(`securitylab-reference-server: http://${HOST}:${PORT} (только loopback)`)
  console.log(`данные: seed.json от ${seed.exportedAt} — ${projects.length} проектов, ${runs.size} прогонов`)
  console.log(`реестр: ${restored ? 'восстановлен из state.json' : 'чистый старт'}; прогоны — сценарии симуляции (demo: true)`)
  console.log(`Origin-список: ${[...ALLOWED_ORIGINS].join(', ')}`)
})
