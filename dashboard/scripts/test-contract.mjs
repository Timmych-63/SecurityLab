/**
 * Контрактные тесты «клиент-метод ↔ сервер-маршрут» (аудит, п.1 и приёмка).
 * Запуск: node scripts/test-contract.mjs
 * Поднимает референсный сервер на тестовом порту, проверяет каждую пару
 * метод/маршрут, включая 404/409/413/422, отсутствующий артефакт, CSRF,
 * Origin/Host, лимит тела, Windows-пути на POSIX, валидацию ссылок прогона
 * и персистентность реестра после рестарта. Код выхода != 0 при провале.
 */
import { spawn } from 'node:child_process'
import http from 'node:http'
import { writeFileSync, mkdirSync, copyFileSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = dirname(HERE)
const PORT = 8790
const BASE = `http://127.0.0.1:${PORT}`

let passed = 0
let failed = 0
const fails = []
function check(name, cond, extra = '') {
  if (cond) { passed++; console.log(`  ok  ${name}`) }
  else { failed++; fails.push(name); console.log(`FAIL  ${name}${extra ? ` — ${extra}` : ''}`) }
}

function startServer(dir, env = {}) {
  const child = spawn(process.execPath, [join(dir, 'server.mjs')], {
    env: { ...process.env, PORT: String(PORT), ...env },
    stdio: 'ignore',
  })
  return child
}

const waitHealthy = async () => {
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`${BASE}/api/health`)
      if (r.ok) return
    } catch { /* ещё не поднялся */ }
    await new Promise((r) => setTimeout(r, 250))
  }
  throw new Error('сервер не поднялся')
}

async function csrf() {
  const r = await fetch(`${BASE}/api/csrf`)
  return (await r.json()).token
}

async function post(path, body, { token = true, origin, headers = {} } = {}) {
  const h = { 'Content-Type': 'application/json', ...headers }
  if (token) h['X-CSRF-Token'] = await csrf()
  if (origin) h['Origin'] = origin
  return fetch(BASE + path, { method: 'POST', headers: h, body: JSON.stringify(body) })
}

const get = (path, headers = {}) => fetch(BASE + path, { headers })

const serverDir = join(ROOT, 'server')
// тест всегда стартует с чистого реестра: state.json от прошлого запуска не должен влиять
rmSync(join(serverDir, 'state.json'), { force: true })
let child = startServer(serverDir)
await waitHealthy()
console.log(`— сервер поднят на :${PORT} —`)

/* ---------- health / csrf / безопасность ---------- */
{
  const r = await get('/api/health')
  const d = await r.json()
  check('GET /api/health → 200, mode simulated-data', r.status === 200 && d.mode === 'simulated-data' && d.ok === true)

  const c = await get('/api/csrf')
  const cd = await c.json()
  check('GET /api/csrf → token + expiresInMs', c.status === 200 && typeof cd.token === 'string' && cd.expiresInMs > 0)

  const noCsrf = await fetch(`${BASE}/api/preflight`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
  check('POST без CSRF → 403', noCsrf.status === 403)

  const badOrigin = await post('/api/preflight', {}, { origin: 'http://evil.example:5173' })
  check('POST с чужим Origin → 403', badOrigin.status === 403)

  const badHost = await new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, path: '/api/health', headers: { Host: 'attacker.example' }, method: 'GET' }, resolve)
    req.on('error', () => resolve({ statusCode: 0 }))
    req.end()
  })
  check('чужой Host → 403 (DNS-rebinding)', badHost.statusCode === 403)

  const big = await post('/api/preflight', { blob: 'x'.repeat(70 * 1024) })
  check('тело > 64 КБ → 413', big.status === 413)

  const badJson = await fetch(`${BASE}/api/preflight`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': await csrf() }, body: '{oops' })
  check('битый JSON → 400', badJson.status === 400)
}

/* ---------- реестр: проекты, снимки (#9) ---------- */
let registeredId = ''
{
  const list = await get('/api/projects')
  const projects = await list.json()
  check('GET /api/projects → 200, массив', list.status === 200 && Array.isArray(projects) && projects.length >= 3)

  const rel = await post('/api/projects', { path: 'relative/path' })
  check('POST /api/projects относительный путь → 422', rel.status === 422)

  const win = await post('/api/projects', { path: 'C:\\Users\\User\\Downloads\\demo' })
  const winBody = await win.json()
  check('POST /api/projects Windows-путь на POSIX → 422 с понятной причиной', win.status === 422 && /Windows/.test(winBody.reason))

  const ok = await post('/api/projects', { path: join(ROOT, 'src') })
  const okBody = await ok.json()
  registeredId = okBody.id ?? ''
  check('POST /api/projects существующий каталог → 201', ok.status === 201 && typeof registeredId === 'string' && registeredId.startsWith('proj-'))

  const dup = await post('/api/projects', { path: join(ROOT, 'src') })
  check('POST /api/projects повтор → 409', dup.status === 409)

  const miss = await post('/api/projects', { path: '/definitely/not/here' })
  check('POST /api/projects несуществующий путь → 422', miss.status === 422)

  const snaps = await get(`/api/projects/proj-orders/snapshots`)
  check('GET /api/projects/{id}/snapshots → 200', snaps.status === 200 && Array.isArray(await snaps.json()))

  const snaps404 = await get('/api/projects/proj-unknown/snapshots')
  check('GET снимков неизвестного проекта → 404', snaps404.status === 404)

  const snap = await post('/api/projects/proj-orders/snapshots', {})
  check('POST снимок supported-проекта → 201', snap.status === 201)

  const snapBad = await post(`/api/projects/${registeredId || 'proj-unknown'}/snapshots`, {})
  check('POST снимок неподдерживаемого проекта → 422', snapBad.status === 422)
}

/* ---------- конфигурации: полный digest (#5) ---------- */
{
  const cfgs = await (await get('/api/ai-configs')).json()
  check('GET /api/ai-configs → 200, digest 64 hex', cfgs.every((c) => /^sha256:[a-f0-9]{64}$/.test(c.digest)))

  const v = await post('/api/ai-configs/aicfg-qwen7b/validate', {})
  const vd = await v.json()
  check('POST validate (полный digest) → valid:true', v.status === 200 && vd.valid === true)

  // сокращённый digest: поднимем второй сервер с правленым seed на соседнем порту
  const tmp = '/tmp/slb-contract-test'
  rmSync(tmp, { recursive: true, force: true })
  mkdirSync(tmp, { recursive: true })
  copyFileSync(join(serverDir, 'server.mjs'), join(tmp, 'server.mjs'))
  const seed = JSON.parse(await (await import('node:fs')).promises.readFile(join(serverDir, 'seed.json'), 'utf8'))
  seed.aiConfigs[0].digest = 'sha256:9f31b7c2…e8a4' // сокращённая визуальная форма
  writeFileSync(join(tmp, 'seed.json'), JSON.stringify(seed))
  const child2 = spawn(process.execPath, [join(tmp, 'server.mjs')], { env: { ...process.env, PORT: String(PORT + 1) }, stdio: 'ignore' })
  try {
    for (let i = 0; i < 30; i++) {
      try { if ((await fetch(`http://127.0.0.1:${PORT + 1}/api/health`)).ok) break } catch {}
      await new Promise((r) => setTimeout(r, 200))
    }
    const t = await csrfAt(PORT + 1)
    const v2 = await fetch(`http://127.0.0.1:${PORT + 1}/api/ai-configs/aicfg-qwen7b/validate`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': t }, body: '{}' })
    const vd2 = await v2.json()
    check('POST validate (сокращённый digest) → valid:false с причиной', v2.status === 200 && vd2.valid === false && /64/.test(vd2.detail))
  } finally {
    child2.kill()
  }
}

async function csrfAt(port) {
  const r = await fetch(`http://127.0.0.1:${port}/api/csrf`)
  return (await r.json()).token
}

/* ---------- прогон: валидация ссылок, 202, 409, отмена (#6, #2) ---------- */
const VALID_RUN = { projectId: 'proj-orders', snapshotId: 'snap-9f3c-a1', service: '.', entryModule: 'app/main.py', profileId: 'fastapi-auth', policyId: 'pol-op-v2', aiConfigId: 'aicfg-qwen7b', stateDir: 'TEMP/SecurityLab_S72_DemoState' }
{
  const bad1 = await post('/api/runs', { ...VALID_RUN, projectId: 'missing' })
  check('POST /api/runs unknown projectId → 422', bad1.status === 422)

  const bad2 = await post('/api/runs', { ...VALID_RUN, snapshotId: 'snap-foreign' })
  check('POST /api/runs чужой snapshotId → 422', bad2.status === 422)

  const bad3 = await post('/api/runs', { ...VALID_RUN, entryModule: '../../outside.py' })
  check('POST /api/runs traversal entry → 422', bad3.status === 422 && /entryModule/.test((await bad3.json()).reason))

  const bad4 = await post('/api/runs', { ...VALID_RUN, aiConfigId: 'aicfg-missing' })
  check('POST /api/runs unknown aiConfigId → 422', bad4.status === 422)

  const bad5 = await post('/api/runs', { ...VALID_RUN, stateDir: '' })
  check('POST /api/runs без stateDir → 422', bad5.status === 422)

  const ok1 = await post('/api/runs', VALID_RUN)
  const ok1d = await ok1.json()
  const runId = ok1d.runId
  check('POST /api/runs валидный → 202 + run_id', ok1.status === 202 && /^run-srv-/.test(runId))

  const dup = await post('/api/runs', VALID_RUN)
  check('второй активный запуск → 409 (сервер, ане UI)', dup.status === 409)

  const active = await (await get('/api/runs')).json()
  check('GET /api/runs: активный без script, exec=running', active.some((r) => r.id === runId && r.exec === 'running' && !('script' in r)))

  const one = await get(`/api/runs/${runId}`)
  const oneD = await one.json()
  check('GET /api/runs/{id} → 200, этапы развёрнуты', one.status === 200 && oneD.stages.length > 0 && oneD.exec === 'running')

  const patchActive = await get(`/api/runs/${runId}/patch`)
  check('GET patch до коммита → 409 с причиной', patchActive.status === 409)

  const artMiss = await get(`/api/runs/${runId}/artifacts/art-nope`)
  check('GET артефакт отсутствующий → 404', artMiss.status === 404)

  const artAbsent = await get(`/api/runs/${runId}/artifacts/art-log`)
  check('GET absent-артефакт → 409 с absentReason', artAbsent.status === 409 && !!(await artAbsent.json()).reason)

  const artTraversal = await get(`/api/runs/${runId}/artifacts/..%252Fetc%252Fpasswd`)
  check('GET артефакт traversal-подобный id → 400/404', artTraversal.status === 400 || artTraversal.status === 404)

  const patchPost = await post(`/api/runs/${runId}/patch`, {})
  check('POST patch (метод-микс) → 404, чтение только GET (#1)', patchPost.status === 404)

  const cancel = await post(`/api/runs/${runId}/cancel`, {})
  check('POST cancel активного → 200 state=cancelled', cancel.status === 200 && (await cancel.json()).state === 'cancelled')

  const frozen = await (await get(`/api/runs/${runId}`)).json()
  check('после отмены: exec cancelled, этап заморожен', frozen.exec === 'cancelled' && frozen.stages.some((st) => st.state === 'skipped'))

  const dup2 = await post('/api/runs', VALID_RUN)
  const dup2d = await dup2.json()
  const runId2 = dup2d.runId
  check('после отмены можно запустить снова → 202', dup2.status === 202)

  const c404 = await post('/api/runs/run-unknown/cancel', {})
  check('cancel неизвестного прогона → 404', c404.status === 404)

  // завершаем второй прогон, чтобы не мешал проверкам персистентности
  await post(`/api/runs/${runId2}/cancel`, {})
}

/* ---------- seed-прогоны: blocked/timeout, patch, diff, фильтры (#7) ---------- */
{
  const blocked = await get('/api/runs/run-8c1f-a2')
  const b = await blocked.json()
  check('seed blocked: exec=blocked, verdict REPRODUCED, finding POLICY_VIOLATION_OBSERVED', b.exec === 'blocked' && b.verdict === 'REPRODUCED' && b.finding === 'POLICY_VIOLATION_OBSERVED' && typeof b.error === 'string')

  const timeout = await get('/api/runs/run-6a9d-58')
  const t = await timeout.json()
  check('seed timeout: exec=timeout, finding null, error с причиной', t.exec === 'timeout' && t.finding === null && /TIMEOUT/.test(t.error ?? ''))

  const fixed = await get('/api/runs/run-7b2e-d4')
  const f = await fixed.json()
  check('seed fixed: finding POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX', f.finding === 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX')

  const diff = await get('/api/runs/run-7b2e-d4/attempts/1/diff')
  check('GET attempts/{n}/diff → 200', diff.status === 200)

  const diff404 = await get('/api/runs/run-7b2e-d4/attempts/9/diff')
  check('GET diff неизвестной попытки → 404', diff404.status === 404)

  const patch = await get('/api/runs/run-7b2e-d4/patch')
  check('GET patch завершённого с коммитом → 200', patch.status === 200 && (await patch.json()).content.includes('diff --git'))

  const art = await get('/api/runs/run-7b2e-d4/artifacts/art-sum')
  check('GET артефакт по id → 200 c содержимым', art.status === 200 && ((await art.json()).content ?? '').includes('run_id'))

  const filtered = await get('/api/runs?status=blocked')
  const fd = await filtered.json()
  check('GET /api/runs?status=blocked → только blocked', filtered.status === 200 && fd.length >= 1 && fd.every((r) => r.exec === 'blocked'))
}

/* ---------- preflight / diagnostics (#5) ---------- */
{
  const pf = await post('/api/preflight', { aiConfigId: 'aicfg-qwen7b' })
  const pfd = await pf.json()
  check('POST preflight → честные состояния + params echo', pf.status === 200 && pfd.docker === 'error' && pfd.images === 'untested' && typeof pfd.checkedAt === 'string' && !!pfd.params)

  const diag = await get('/api/diagnostics')
  const dd = await diag.json()
  check('GET diagnostics → реальный CPU, gpu null', diag.status === 200 && dd.available === true && typeof dd.cpu === 'string' && dd.cpu.includes('×') && dd.gpu === null)
}

/* ---------- персистентность реестра после рестарта (#11) ---------- */
{
  const before = await (await get('/api/runs')).json()
  const cancelledCount = before.filter((r) => r.exec === 'cancelled').length
  child.kill()
  await new Promise((r) => setTimeout(r, 400))
  child = startServer(serverDir)
  await waitHealthy()
  const after = await (await get('/api/runs')).json()
  check('после рестарта сервера реестр восстановлен из state.json', after.filter((r) => r.exec === 'cancelled').length === cancelledCount && after.length === before.length)
}

child.kill()
rmSync('/tmp/slb-contract-test', { recursive: true, force: true })

console.log(`\nитого: ${passed} ok, ${failed} fail`)
if (failed > 0) {
  console.log('провалены:', fails.join(', '))
  process.exit(1)
}
