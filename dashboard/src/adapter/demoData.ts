import type {
  AiConfig,
  Artifact,
  Check,
  Policy,
  Project,
  Run,
  RunEvent,
  Stage,
} from './types'

/* Демонстрационный набор данных. Все прогоны помечены demo: true.
   Сюжеты повторяют реальную историю проекта из ТЗ: успешный прогон узкой
   политики, BLOCKED из-за неверного первого патча и зацикливания второго
   ответа, TIMEOUT при долгой генерации без событий. */

const T = (day: number, h: number, m: number) =>
  `2026-11-${String(day).padStart(2, '0')}T${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:00+03:00`

export const projects: Project[] = [
  {
    id: 'proj-orders',
    name: 'orders-api',
    path: '/home/operator/lab/orders-api',
    stack: 'Python 3.12 · FastAPI 0.115',
    profile: 'fastapi-auth',
    supported: true,
    snapshots: [
      { id: 'snap-9f3c-a1', commit: '4f0c21e', createdAt: T(10, 10, 58), note: 'зафиксирован перед запуском run-7b2e-d4' },
      { id: 'snap-2e77-b4', commit: '9d3aa07', createdAt: T(8, 13, 55) },
      { id: 'snap-1c05-7f', commit: '2b6e4d1', createdAt: T(6, 9, 12) },
    ],
    lastRunId: 'run-8c1f-a2',
    services: [{ service: '.', entryFile: 'app/main.py', entryImport: 'app.main:app' }],
    stateDir: 'TEMP/SecurityLab_S72_DemoState',
  },
  {
    id: 'proj-docs',
    name: 'docs-portal',
    path: '/home/operator/lab/docs-portal',
    stack: 'Python 3.12 · FastAPI 0.115',
    profile: 'fastapi-auth',
    supported: true,
    snapshots: [{ id: 'snap-3d81-02', commit: '77ac910', createdAt: T(7, 17, 30) }],
    services: [{ service: '.', entryFile: 'app/main.py', entryImport: 'app.main:app' }],
    stateDir: 'TEMP/SecurityLab_S72_DemoState',
  },
  {
    id: 'proj-payments',
    name: 'payments-go',
    path: '/home/operator/lab/payments-go',
    stack: 'Go 1.22 · chi',
    profile: '—',
    supported: false,
    unsupportedReason:
      'Профиль fastapi-auth рассчитан на Python/FastAPI. Профиля для Go-стека пока нет — поддержка добавляется вместе с backend, UI не имитирует неподдерживаемые запуски.',
    snapshots: [],
  },
]

export const policies: Policy[] = [
  {
    id: 'pol-op-v3',
    name: 'Операторская политика v3 (расширенная)',
    version: 'v3',
    scope: 'один модуль: app/orders.py',
    casesCount: 8,
    subjects:
      'Red и Blue — сервисные роли внутри изолированной сети; HTTP-проверки выполняет верификатор от имени владельца, второго пользователя и анонима',
    restrictions: [
      'исполнение только в Docker-сети slb-internal, без доступа в интернет',
      'максимум 2 попытки Blue, включая корректирующие',
      'исходный репозиторий не изменяется автоматически',
      'успешный патч — отдельный коммит в изолированной копии, без merge/push',
    ],
  },
  {
    id: 'pol-op-v2',
    name: 'Операторская политика v2 (узкая)',
    version: 'v2',
    scope: 'один модуль: app/orders.py',
    casesCount: 4,
    subjects:
      'те же роли, что в v3; сокращённый набор контрольных случаев: владелец, чужой пользователь, аноним, одна регрессия',
    restrictions: [
      'исполнение только в Docker-сети slb-internal, без доступа в интернет',
      'максимум 2 попытки Blue, включая корректирующие',
      'исходный репозиторий не изменяется автоматически',
    ],
  },
]

export const aiConfigs: AiConfig[] = [
  {
    id: 'aicfg-qwen7b',
    name: 'hermes-main.toml',
    model: 'qwen2.5-coder:7b',
    digest: 'sha256:9f31b7c2a7d54f68a5b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1',
    server: 'http://hermes:11434',
    network: 'slb-internal',
    contextTokens: 64000,
    maxOutputTokens: 4096,
    timeoutSeconds: 900,
    configValid: true,
    // проверка доступности модели выполняется раздельно (ping-model); в демо не выполнялась
    modelPing: null,
    present: true,
  },
  {
    id: 'aicfg-mistral',
    name: 'hermes-experiment.toml',
    model: 'mistral-7b-instruct:latest',
    digest: 'sha256:c04d2ea9137b5c9f2a6d8e0c4b6a8d0f2c4e6a8b0d2f4c6e8a0b2d4f6c8e0a2b',
    server: 'http://hermes:11434',
    network: 'slb-internal',
    contextTokens: 64000,
    maxOutputTokens: 4096,
    timeoutSeconds: 900,
    configValid: true,
    modelPing: null,
    present: false,
  },
]

export const FIX_DIFF = `diff --git a/app/orders.py b/app/orders.py
index 4f0c21e..9a17c55 100644
--- a/app/orders.py
+++ b/app/orders.py
@@ -41,9 +41,14 @@ def get_order(order_id: int, user: User = Depends(current_user)):
-    order = db.get(Order, order_id)
-    if order is None:
-        raise HTTPException(status_code=404)
-    return order
+    order = db.get(Order, order_id)
+    if order is None:
+        raise HTTPException(status_code=404)
+    # проверка владельца объекта: чужие заказы недоступны
+    if order.user_id != user.id and not user.is_admin:
+        # logging note: <img src=x onerror=alert(1)> — строка из ответа модели,
+        # отображается как текст и не исполняется
+        raise HTTPException(status_code=403)
+    return order
`

const BAD_DIFF_1 = `diff --git a/app/orders.py b/app/orders.py
index 4f0c21e..c3b91f0 100644
--- a/app/orders.py
+++ b/app/orders.py
@@ -48,6 +48,8 @@ def get_order(order_id: int, user: User = Depends(current_user)):
+    if order.user_id != user.id:
+        raise HTTPException(status_code=403)
@@ -112,4 +114,6 @@ def get_stats(user: User = Depends(current_user)):
+    # удалён вызов authorize(user, "stats:read") — маршрут стал 404
+    rows = db.all(Stat)
`

const BAD_DIFF_2 = `# второй ответ модели повторял первый блок без изменений;
# Hermes зафиксировал совпадение хеша вывода с предыдущей попыткой
# и прервал генерацию: лимит двух попыток Blue исчерпан
`

const CSV_DIFF = `diff --git a/app/orders.py b/app/orders.py
index 9d3aa07..1f6e2b8 100644
--- a/app/orders.py
+++ b/app/orders.py
@@ -55,7 +55,12 @@ def get_order(order_id: int, user: User = Depends(current_user)):
+    if order.user_id != user.id and not user.is_admin:
+        raise HTTPException(status_code=403)
diff --git a/app/utils/audit.py b/app/utils/audit.py
--- a/app/utils/audit.py
+++ b/app/utils/audit.py
@@ -12,3 +12,6 @@
+    # правка вне согласованной области политики (модуль app/orders.py)
+    # <script>alert('xss')</script> — строка ответа модели, показывается текстом
`

const summaryJson = `{
  "run_id": "run-7b2e-d4",
  "snapshot": "snap-9f3c-a1",
  "security_verdict": "REPRODUCED",
  "finding_status": "POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX",
  "checks": { "total": 4, "passed": 4 },
  "attempts": { "candidate": 1, "accepted": 1 }
}`

const receipts = `{"call":"red.propose","model":"qwen2.5-coder:7b","prompt_hash":"sha256:51ab…","snapshot":"snap-9f3c-a1"}
{"call":"verifier.baseline","check":"S-2","expect":403,"got":200,"body_hash":"sha256:77c1…"}
{"call":"verifier.candidate","check":"S-2","expect":403,"got":403,"body_hash":"sha256:2e9d…"}
{"call":"verifier.recheck","check":"S-2","expect":403,"got":403,"body_hash":"sha256:2e9d…"}`

const reportHtml = `<!doctype html>
<html><body><h1>SLB report — run-7b2e-d4</h1>
<p>Отчёт отдаётся как текст: содержимое отчётов недоверенное,
рендеринг HTML в интерфейсе отключён.</p></body></html>`

const containerLog = `[0.412] container slb-baseline started (network slb-internal)
[0.908] uvicorn app.main:app listening on 127.0.0.1:8000
[1.204] GET /api/v1/orders/1042 -> 200 (user-b)
[2.117] container stopped, volumes removed`

export function makeCheck(id: string, o: Partial<Check> & Pick<Check, 'scenario' | 'group' | 'actor' | 'method' | 'path' | 'expectStatus'>): Check {
  return {
    id,
    baseline: { http: null, outcome: 'not_run' },
    candidate: { http: null, outcome: 'not_run' },
    final: 'not_run',
    ...o,
  } as Check
}

export const runFixed: Run = {
  id: 'run-7b2e-d4',
  demo: true,
  projectId: 'proj-orders',
  snapshotId: 'snap-9f3c-a1',
  service: '.',
  entryModule: 'app/main.py',
  profileId: 'fastapi-auth',
  policyId: 'pol-op-v2',
  aiConfigId: 'aicfg-qwen7b',
  stateDir: 'TEMP/SecurityLab_S72_DemoState',
  mode: 'ai_red_blue',
  startedAt: T(10, 11, 5),
  finishedAt: T(10, 11, 31),
  timeLimitMin: 20,
  exec: 'completed',
  verdict: 'REPRODUCED',
  finding: 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX',
  stages: [
    { id: 'snapshot_pin', label: 'Фиксация снимка', state: 'done', startedAt: 0, finishedAt: 2 },
    { id: 'policy_load', label: 'Загрузка политики v2 (узкая)', state: 'done', startedAt: 2, finishedAt: 3 },
    { id: 'docker_prepare', label: 'Подготовка Docker-окружения', role: 'securitylab', state: 'done', startedAt: 3, finishedAt: 18 },
    { id: 'red_generate', label: 'Red: разбор и сценарий', role: 'Red · предложение AI', state: 'wait_model', startedAt: 18, finishedAt: 96, detail: 'ожидание ответа модели: 78 с без событий' },
    { id: 'baseline_run', label: 'Baseline: воспроизведение нарушения', role: 'verifier', state: 'done', startedAt: 96, finishedAt: 214, detail: 'S-2: получено 200 вместо 403 — нарушение воспроизведено' },
    { id: 'blue_generate', label: 'Blue: предложение патча (попытка 1)', role: 'Blue', state: 'done', startedAt: 214, finishedAt: 268 },
    { id: 'candidate_check', label: 'Независимая проверка кандидата', role: 'verifier', state: 'done', startedAt: 268, finishedAt: 402, detail: '4 из 4 проверок пройдены' },
    { id: 'recheck_run', label: 'Recheck: повторная проверка', role: 'verifier', state: 'done', startedAt: 402, finishedAt: 496, detail: 'результат подтверждён' },
    { id: 'commit_stage', label: 'Отдельный коммит в изолированной копии', role: 'securitylab', state: 'done', startedAt: 496, finishedAt: 512 },
  ],
  events: [
    { t: 0, source: 'securitylab', text: 'запуск создан; снимок snap-9f3c-a1 (4f0c21e) зафиксирован' },
    { t: 3, source: 'docker', text: 'образ securitylab-demo:local (sha256:ab12…) готов, сеть slb-internal создана' },
    { t: 18, source: 'hermes', text: 'запрос red.propose → qwen2.5-coder:7b (context 64000, timeout 900 с)' },
    { t: 96, source: 'hermes', text: 'Red вернул сценарий S-2: "GET /api/v1/orders/1042 от user-b: <img src=x onerror=alert(1)> передан в лог-файл как текст" (строка сохранена дословно, исполнение отключено)' },
    { t: 214, source: 'verifier', text: 'baseline: ожидалось 403, получено 200 — нарушение воспроизведено (тело не совпало с ожидаемым, hash ok=false)' },
    { t: 268, source: 'hermes', text: 'Blue вернул патч попытки 1 (candidate)' },
    { t: 402, source: 'verifier', text: 'candidate: 4/4 проверок пройдено, совпадение тела/хеша подтверждено' },
    { t: 496, source: 'verifier', text: 'recheck: результат воспроизведён на повторном контейнере' },
    { t: 512, source: 'securitylab', text: 'создан отдельный коммит 5c1e9ab в изолированной копии fix/slb-snap-9f3c-s2; merge и push не выполнялись' },
  ],
  checks: [
    makeCheck('c-1', {
      scenario: 'Просмотр своего заказа', group: 'owner', actor: 'владелец (user-a)',
      method: 'GET', path: '/api/v1/orders/1037', expectStatus: 200,
      baseline: { http: 200, outcome: 'pass', bodyHashOk: true },
      candidate: { http: 200, outcome: 'pass', bodyHashOk: true },
      recheck: { http: 200, outcome: 'pass', bodyHashOk: true },
      final: 'pass',
    }),
    makeCheck('c-2', {
      scenario: 'Чужой заказ по возрастающему ID (S-2)', group: 'foreign', actor: 'авторизованный user-b',
      method: 'GET', path: '/api/v1/orders/1042', expectStatus: 403,
      baseline: { http: 200, outcome: 'fail', bodyHashOk: false, note: 'нарушение воспроизведено' },
      candidate: { http: 403, outcome: 'pass', bodyHashOk: true },
      recheck: { http: 403, outcome: 'pass', bodyHashOk: true },
      final: 'pass',
    }),
    makeCheck('c-3', {
      scenario: 'Анонимный доступ к списку заказов', group: 'anon', actor: 'аноним',
      method: 'GET', path: '/api/v1/orders', expectStatus: 401,
      baseline: { http: 401, outcome: 'pass', bodyHashOk: true, note: 'авторизация работала и до патча' },
      candidate: { http: 401, outcome: 'pass', bodyHashOk: true },
      final: 'pass',
    }),
    makeCheck('c-4', {
      scenario: 'Регрессия: владелец не потерял доступ', group: 'regress', actor: 'владелец (user-a)',
      method: 'GET', path: '/api/v1/orders/1037', expectStatus: 200,
      baseline: { http: 200, outcome: 'pass', bodyHashOk: true },
      candidate: { http: 200, outcome: 'pass', bodyHashOk: true },
      recheck: { http: 200, outcome: 'pass', bodyHashOk: true },
      final: 'pass',
    }),
  ],
  redProposal: {
    scenarioNo: 'S-2',
    summary:
      'Пользователь user-b получает заказ другого пользователя, перебирая возрастающие идентификаторы: сервер отдаёт объект без проверки владельца. Предлагается проверка GET /api/v1/orders/1042 под учётной записью user-b с ожиданием 403.',
    method: 'GET',
    path: '/api/v1/orders/{id}',
    entry: 'app/orders.py · get_order',
    aiGenerated: true,
  },
  attempts: [
    {
      n: 1,
      role: 'candidate',
      status: 'accepted',
      diff: FIX_DIFF,
      rejectionReasons: [],
      checkSummary: 'независимая проверка: 4/4, совпадение тела/хеша подтверждено',
    },
  ],
  commit: { ref: 'fix/slb-snap-9f3c-s2', sha: '5c1e9ab', isolated: true },
  artifacts: [
    { id: 'art-sum', name: 'summary.json', kind: 'json', present: true, content: summaryJson },
    { id: 'art-rec', name: 'receipts.jsonl', kind: 'text', present: true, content: receipts },
    { id: 'art-patch', name: 'candidate-1.patch', kind: 'patch', present: true, content: FIX_DIFF },
    { id: 'art-html', name: 'report.html', kind: 'html', present: true, content: reportHtml },
    { id: 'art-log', name: 'container.log', kind: 'log', present: false, absentReason: 'файл удалён при очистке контейнера после прогона — это ожидаемое поведение очистки, а не потеря артефакта' },
  ],
  tech: {
    image: 'securitylab-demo:local',
    imageDigest: 'sha256:ab12f0…9c33',
    network: 'slb-internal (изолированная, без выхода в интернет)',
    configHash: 'sha256:1d44aa…b802',
    snapshotPin: 'snap-9f3c-a1 · 4f0c21e',
    cleanup: 'контейнеры и тома удалены по завершении прогона',
    hashDisclaimer:
      'хеши фиксируют привязку артефактов к снимку, политике, образу и модели. Это журнал целостности, а не криптографическая подпись и не гарантия отсутствия всех уязвимостей.',
  },
}

export const runBlocked: Run = {
  id: 'run-8c1f-a2',
  demo: true,
  projectId: 'proj-orders',
  snapshotId: 'snap-9f3c-a1',
  service: '.',
  entryModule: 'app/main.py',
  profileId: 'fastapi-auth',
  policyId: 'pol-op-v3',
  aiConfigId: 'aicfg-qwen7b',
  stateDir: 'TEMP/SecurityLab_S72_DemoState',
  mode: 'ai_red_blue',
  startedAt: T(11, 18, 42),
  finishedAt: T(11, 19, 7),
  timeLimitMin: 25,
  exec: 'blocked',
  // STOP-причина — в exec/error; verdict — воспроизведение на baseline
  error: 'BLOCKED: лимит попыток Blue исчерпан, нарушения остались после отклонённых патчей',
  verdict: 'REPRODUCED',
  finding: 'POLICY_VIOLATION_OBSERVED',
  stages: [
    { id: 'snapshot_pin', label: 'Фиксация снимка', state: 'done', startedAt: 0, finishedAt: 2 },
    { id: 'policy_load', label: 'Загрузка политики v3 (расширенная)', state: 'done', startedAt: 2, finishedAt: 3 },
    { id: 'docker_prepare', label: 'Подготовка Docker-окружения', state: 'done', startedAt: 3, finishedAt: 17 },
    { id: 'red_generate', label: 'Red: разбор и сценарии', role: 'Red · предложение AI', state: 'done', startedAt: 17, finishedAt: 128 },
    { id: 'baseline_run', label: 'Baseline: воспроизведение нарушений', state: 'done', startedAt: 128, finishedAt: 391, detail: '3 из 3 целевых нарушений воспроизведены' },
    { id: 'blue_generate', label: 'Blue: предложение патча (попытка 1)', state: 'done', startedAt: 391, finishedAt: 469 },
    { id: 'candidate_check', label: 'Проверка кандидата 1', state: 'failed', startedAt: 469, finishedAt: 631, detail: 'регрессия: /api/v1/stats отвечает 404; поведение владельца изменилось (500)' },
    { id: 'blue_retry', label: 'Blue: корректирующая попытка 2', state: 'failed', startedAt: 631, finishedAt: 897, detail: 'ответ модели зациклился: вывод идентичен предыдущему' },
    { id: 'recheck_run', label: 'Recheck', state: 'skipped', detail: 'не выполнен: лимит попыток Blue исчерпан' },
  ],
  events: [
    { t: 0, source: 'securitylab', text: 'запуск создан; политика v3: 8 контрольных случаев' },
    { t: 17, source: 'hermes', text: 'red.propose → qwen2.5-coder:7b' },
    { t: 128, source: 'hermes', text: 'Red вернул 3 целевых сценария; в анализе встречались строки "<script>alert(\'xss\')</script>" — сохранены в журнал как текст' },
    { t: 391, source: 'verifier', text: 'baseline: S-1 200≠403, S-2 200≠403, S-3 200≠403 — нарушения воспроизведены' },
    { t: 631, source: 'verifier', text: 'candidate 1 отклонён: /api/v1/stats → 404 (регрессия), GET /orders/1037 → 500 (владелец)' },
    { t: 742, source: 'hermes', text: 'blue.retry: запрос повторён' },
    { t: 897, source: 'hermes', text: 'ответ попытки 2 идентичен попытке 1 (hash вывода совпал) — зацикливание; попыток больше нет (лимит 2)' },
    { t: 901, source: 'securitylab', text: 'итог: BLOCKED. Коммит не создавался, репозиторий не изменён. BLOCKED не означает, что проект безопасен' },
  ],
  checks: [
    makeCheck('c-1', {
      scenario: 'Просмотр своего заказа', group: 'owner', actor: 'владелец (user-a)',
      method: 'GET', path: '/api/v1/orders/1037', expectStatus: 200,
      baseline: { http: 200, outcome: 'pass', bodyHashOk: true },
      candidate: { http: 500, outcome: 'fail', bodyHashOk: false, note: 'патч сломал поведение владельца' },
      final: 'fail',
    }),
    makeCheck('c-2', {
      scenario: 'Список статистики пользователя', group: 'owner', actor: 'владелец (user-a)',
      method: 'GET', path: '/api/v1/stats', expectStatus: 200,
      baseline: { http: 200, outcome: 'pass', bodyHashOk: true },
      candidate: { http: 404, outcome: 'fail', bodyHashOk: null, note: 'регрессия: легитимный маршрут потерян' },
      final: 'fail',
    }),
    makeCheck('c-3', {
      scenario: 'Чужой заказ по возрастающему ID (S-1)', group: 'foreign', actor: 'авторизованный user-b',
      method: 'GET', path: '/api/v1/orders/1042', expectStatus: 403,
      baseline: { http: 200, outcome: 'fail', bodyHashOk: false, note: 'нарушение воспроизведено' },
      candidate: { http: 403, outcome: 'pass', bodyHashOk: true },
      final: 'pass',
    }),
    makeCheck('c-4', {
      scenario: 'Чужой заказ через фильтр (S-2)', group: 'foreign', actor: 'авторизованный user-b',
      method: 'GET', path: '/api/v1/orders?user=b', expectStatus: 403,
      baseline: { http: 200, outcome: 'fail', bodyHashOk: false },
      candidate: { http: 403, outcome: 'pass', bodyHashOk: true },
      final: 'pass',
    }),
    makeCheck('c-5', {
      scenario: 'Экспорт чужого заказа (S-3)', group: 'foreign', actor: 'авторизованный user-b',
      method: 'GET', path: '/api/v1/orders/1042/export', expectStatus: 403,
      baseline: { http: 200, outcome: 'fail', bodyHashOk: false },
      candidate: { http: 403, outcome: 'pass', bodyHashOk: true },
      final: 'pass',
    }),
    makeCheck('c-6', {
      scenario: 'Анонимный доступ к заказу', group: 'anon', actor: 'аноним',
      method: 'GET', path: '/api/v1/orders/1037', expectStatus: 401,
      baseline: { http: 401, outcome: 'pass', bodyHashOk: true },
      candidate: { http: 401, outcome: 'pass', bodyHashOk: true },
      final: 'pass',
    }),
    makeCheck('c-7', {
      scenario: 'Регрессия: свой заказ после патча', group: 'regress', actor: 'владелец (user-a)',
      method: 'GET', path: '/api/v1/orders/1037?format=csv', expectStatus: 200,
      baseline: { http: 200, outcome: 'pass', bodyHashOk: true },
      candidate: { http: 200, outcome: 'pass', bodyHashOk: true },
      final: 'pass',
    }),
    makeCheck('c-8', {
      scenario: 'Повторная проверка после попытки 2', group: 'regress', actor: '—',
      method: '—', path: '—', expectStatus: 200,
      baseline: { http: 200, outcome: 'pass', bodyHashOk: true },
      candidate: { http: null, outcome: 'not_run', note: 'не выполнен: лимит попыток исчерпан' },
      final: 'not_run',
    }),
  ],
  redProposal: {
    scenarioNo: 'S-1…S-3',
    summary:
      'Три канала доступа к чужим заказам: прямой переход по возрастающему ID, фильтр по имени пользователя и экспорт заказа. Проверки выполняются от имени user-b с ожиданием 403.',
    method: 'GET',
    path: '/api/v1/orders/…, /api/v1/orders?user=…, /api/v1/orders/{id}/export',
    entry: 'app/orders.py',
    aiGenerated: true,
  },
  attempts: [
    {
      n: 1,
      role: 'candidate',
      status: 'rejected',
      diff: BAD_DIFF_1,
      rejectionReasons: [
        'регрессия: легитимный маршрут /api/v1/stats отвечает 404',
        'поведение владельца изменилось: GET /api/v1/orders/1037 отвечает 500',
      ],
      checkSummary: 'независимая проверка: 5/8, 3 нарушения остались, 2 регрессии внесены',
    },
    {
      n: 2,
      role: 'candidate_retry',
      status: 'rejected',
      diff: BAD_DIFF_2,
      rejectionReasons: [
        'второй ответ зациклился: вывод идентичен попытке 1 (хеш совпал)',
        'лимит двух попыток Blue (включая корректирующие) исчерпан — политика не менялась',
      ],
      checkSummary: 'проверка не проводилась: содержимого патча нет',
    },
  ],
  artifacts: [
    { id: 'art-sum', name: 'summary.json', kind: 'json', present: true, content: '{\n  "run_id": "run-8c1f-a2",\n  "status": "BLOCKED",\n  "security_verdict": "REPRODUCED",\n  "finding_status": "POLICY_VIOLATION_OBSERVED",\n  "attempts": { "rejected": 2, "accepted": 0 },\n  "note": "blocked does not mean safe"\n}' },
    { id: 'art-rec', name: 'receipts.jsonl', kind: 'text', present: true, content: '{"call":"verifier.candidate","check":"S-1","expect":403,"got":403}\n{"call":"verifier.candidate","check":"regress.stats","expect":200,"got":404}\n{"call":"hermes.blue.retry","result":"cycle_detected","prompt_hash":"sha256:ae31…"}' },
    { id: 'art-p1', name: 'candidate-1.patch', kind: 'patch', present: true, content: BAD_DIFF_1 },
    { id: 'art-log', name: 'container.log', kind: 'log', present: true, content: containerLog },
    { id: 'art-p2', name: 'candidate-2.trace', kind: 'text', present: true, content: BAD_DIFF_2 },
  ],
  tech: {
    image: 'securitylab-demo:local',
    imageDigest: 'sha256:ab12f0…9c33',
    network: 'slb-internal (изолированная, без выхода в интернет)',
    configHash: 'sha256:1d44aa…b802',
    snapshotPin: 'snap-9f3c-a1 · 4f0c21e',
    cleanup: 'контейнеры и тома удалены по завершении прогона',
    hashDisclaimer:
      'хеши — журнал целостности и привязки, не криптографическая подпись и не гарантия отсутствия всех уязвимостей.',
  },
}

export const runTimeout: Run = {
  id: 'run-6a9d-58',
  demo: true,
  projectId: 'proj-orders',
  snapshotId: 'snap-2e77-b4',
  service: '.',
  entryModule: 'app/main.py',
  profileId: 'fastapi-auth',
  policyId: 'pol-op-v3',
  aiConfigId: 'aicfg-qwen7b',
  stateDir: 'TEMP/SecurityLab_S72_DemoState',
  mode: 'ai_red_blue',
  startedAt: T(9, 21, 10),
  finishedAt: T(9, 21, 30),
  timeLimitMin: 20,
  exec: 'timeout',
  error: 'TIMEOUT: превышен лимит времени прогона (20 мин) — события от модели отсутствовали 14 мин',
  // baseline не выполнялся: нарушение не воспроизводилось, оценка не проводилась
  verdict: 'NOT_EVALUATED',
  finding: null,
  stages: [
    { id: 'snapshot_pin', label: 'Фиксация снимка', state: 'done', startedAt: 0, finishedAt: 2 },
    { id: 'docker_prepare', label: 'Подготовка Docker-окружения', state: 'done', startedAt: 2, finishedAt: 15 },
    { id: 'red_generate', label: 'Red: разбор и сценарий', role: 'Red · предложение AI', state: 'wait_model', startedAt: 15, detail: '14 минут без событий — ожидаем ответ; процент готовности не показывается' },
    { id: 'baseline_run', label: 'Baseline', state: 'skipped', detail: 'не выполнен: лимит времени израсходован на генерацию' },
    { id: 'blue_generate', label: 'Blue', state: 'skipped', detail: 'не выполнен' },
  ],
  events: [
    { t: 0, source: 'securitylab', text: 'запуск создан; лимит времени 20 мин' },
    { t: 15, source: 'hermes', text: 'red.propose → qwen2.5-coder:7b' },
    { t: 900, source: 'securitylab', text: 'событий от модели нет 14 мин; истёк лимит времени прогона (20 мин) — TIMEOUT' },
  ],
  checks: [],
  attempts: [],
  artifacts: [
    { id: 'art-sum', name: 'summary.json', kind: 'json', present: true, content: '{\n  "run_id": "run-6a9d-58",\n  "status": "TIMEOUT",\n  "security_verdict": "NOT_EVALUATED",\n  "finding_status": null,\n  "stages_run": ["snapshot_pin", "docker_prepare", "red_generate"]\n}' },
  ],
  tech: {
    image: 'securitylab-demo:local',
    imageDigest: 'sha256:ab12f0…9c33',
    network: 'slb-internal',
    configHash: 'sha256:1d44aa…b802',
    snapshotPin: 'snap-2e77-b4 · 9d3aa07',
    cleanup: 'контейнеры удалены по прерывании прогона',
    hashDisclaimer: 'хеши — журнал целостности, не подпись и не гарантия.',
  },
}

export const runReview: Run = {
  id: 'run-5d3a-71',
  demo: true,
  projectId: 'proj-orders',
  snapshotId: 'snap-2e77-b4',
  service: '.',
  entryModule: 'app/main.py',
  profileId: 'fastapi-auth',
  policyId: 'pol-op-v2',
  aiConfigId: 'aicfg-qwen7b',
  stateDir: 'TEMP/SecurityLab_S72_DemoState',
  mode: 'ai_red_blue',
  startedAt: T(8, 14, 20),
  finishedAt: T(8, 14, 47),
  timeLimitMin: 20,
  exec: 'completed',
  // Патч прошёл все проверки, но затронул файл вне области политики —
  // решение за оператором (finding_status = NEEDS_REVIEW).
  error: 'NEEDS_REVIEW: diff вне области политики — требуется решение оператора',
  verdict: 'REPRODUCED',
  finding: 'NEEDS_REVIEW',
  stages: [],
  events: [],
  checks: [],
  attempts: [],
  artifacts: [],
  tech: {
    image: 'securitylab-demo:local',
    imageDigest: 'sha256:ab12f0…9c33',
    network: 'slb-internal',
    configHash: 'sha256:1d44aa…b802',
    snapshotPin: 'snap-2e77-b4 · 9d3aa07',
    cleanup: 'контейнеры удалены по завершении',
    hashDisclaimer: 'хеши — журнал целостности, не подпись и не гарантия.',
  },
}

// Патч прошёл проверки, но затронул файл вне области политики — оператор решает.
runReview.stages = [
  { id: 'snapshot_pin', label: 'Фиксация снимка', state: 'done', startedAt: 0, finishedAt: 2 },
  { id: 'docker_prepare', label: 'Подготовка Docker-окружения', state: 'done', startedAt: 2, finishedAt: 16 },
  { id: 'red_generate', label: 'Red: разбор и сценарий', role: 'Red · предложение AI', state: 'done', startedAt: 16, finishedAt: 88 },
  { id: 'baseline_run', label: 'Baseline: воспроизведение нарушения', state: 'done', startedAt: 88, finishedAt: 190 },
  { id: 'blue_generate', label: 'Blue: предложение патча (попытка 1)', state: 'done', startedAt: 190, finishedAt: 244 },
  { id: 'candidate_check', label: 'Независимая проверка кандидата', state: 'done', startedAt: 244, finishedAt: 388, detail: '4/4 проверок пройдено' },
  { id: 'scope_review', label: 'Проверка области изменений', state: 'failed', startedAt: 388, finishedAt: 401, detail: 'diff затрагивает app/utils/audit.py — вне области политики (app/orders.py)' },
  { id: 'commit_stage', label: 'Коммит', state: 'skipped', detail: 'не создан: ожидается решение оператора' },
]
runReview.events = [
  { t: 0, source: 'securitylab', text: 'запуск создан; политика v2 (узкая)' },
  { t: 190, source: 'verifier', text: 'baseline: S-2 воспроизведено (200 вместо 403)' },
  { t: 388, source: 'verifier', text: 'candidate: 4/4 проверок пройдено' },
  { t: 401, source: 'securitylab', text: 'diff затрагивает app/utils/audit.py — вне области политики; итог NEEDS_REVIEW, коммит не создавался. Решение — за оператором, UI кнопку «принять как безопасное» не показывает' },
]
runReview.checks = [
  makeCheck('c-1', {
    scenario: 'Просмотр своего заказа', group: 'owner', actor: 'владелец (user-a)',
    method: 'GET', path: '/api/v1/orders/1037', expectStatus: 200,
    baseline: { http: 200, outcome: 'pass', bodyHashOk: true },
    candidate: { http: 200, outcome: 'pass', bodyHashOk: true },
    final: 'pass',
  }),
  makeCheck('c-2', {
    scenario: 'Чужой заказ по возрастающему ID (S-2)', group: 'foreign', actor: 'авторизованный user-b',
    method: 'GET', path: '/api/v1/orders/1042', expectStatus: 403,
    baseline: { http: 200, outcome: 'fail', bodyHashOk: false },
    candidate: { http: 403, outcome: 'pass', bodyHashOk: true },
    final: 'pass',
  }),
  makeCheck('c-3', {
    scenario: 'Анонимный доступ к списку', group: 'anon', actor: 'аноним',
    method: 'GET', path: '/api/v1/orders', expectStatus: 401,
    baseline: { http: 401, outcome: 'pass', bodyHashOk: true },
    candidate: { http: 401, outcome: 'pass', bodyHashOk: true },
    final: 'pass',
  }),
  makeCheck('c-4', {
    scenario: 'Регрессия: владелец не потерял доступ', group: 'regress', actor: 'владелец (user-a)',
    method: 'GET', path: '/api/v1/orders/1037', expectStatus: 200,
    baseline: { http: 200, outcome: 'pass', bodyHashOk: true },
    candidate: { http: 200, outcome: 'pass', bodyHashOk: true },
    final: 'pass',
  }),
]
runReview.redProposal = {
  scenarioNo: 'S-2',
  summary: 'Чужой заказ по возрастающему ID: сервер не проверяет владельца объекта.',
  method: 'GET',
  path: '/api/v1/orders/{id}',
  entry: 'app/orders.py · get_order',
  aiGenerated: true,
}
runReview.attempts = [
  {
    n: 1,
    role: 'candidate',
    status: 'rejected',
    diff: CSV_DIFF,
    rejectionReasons: [
      'изменения затрагивают app/utils/audit.py — вне области политики (один модуль app/orders.py)',
      'автоматического «принятия вне области» нет: решение принимает оператор, после чего возможен повторный прогон',
    ],
    checkSummary: 'независимая проверка: 4/4 пройдено, но патч не принят из-за области изменений',
  },
]
runReview.artifacts = [
  { id: 'art-sum', name: 'summary.json', kind: 'json', present: true, content: '{\n  "run_id": "run-5d3a-71",\n  "security_verdict": "REPRODUCED",\n  "finding_status": "NEEDS_REVIEW",\n  "reason": "diff out of policy scope"\n}' },
  { id: 'art-p1', name: 'candidate-1.patch', kind: 'patch', present: true, content: CSV_DIFF },
]

export const runSmoke: Run = {
  id: 'run-3f5e-b2',
  demo: true,
  projectId: 'proj-docs',
  snapshotId: 'snap-3d81-02',
  service: '.',
  entryModule: 'app/main.py',
  profileId: 'fastapi-auth',
  policyId: 'pol-op-v2',
  aiConfigId: 'aicfg-qwen7b',
  stateDir: 'TEMP/SecurityLab_S72_DemoState',
  mode: 'smoke_only',
  startedAt: T(7, 17, 41),
  finishedAt: T(7, 17, 44),
  timeLimitMin: 10,
  exec: 'completed',
  verdict: 'NOT_EVALUATED',
  finding: null,
  stages: [
    { id: 'snapshot_pin', label: 'Фиксация снимка', state: 'done', startedAt: 0, finishedAt: 2 },
    { id: 'docker_prepare', label: 'Подготовка Docker-окружения', state: 'done', startedAt: 2, finishedAt: 14 },
    { id: 'smoke_run', label: 'Smoke: сборка и подъём сервиса', state: 'done', startedAt: 14, finishedAt: 118, detail: 'сервис отвечает 200 на /healthz' },
  ],
  events: [
    { t: 0, source: 'securitylab', text: 'smoke-прогон: проверка конфигурации стенда' },
    { t: 118, source: 'verifier', text: 'smoke: 200 на /healthz — стенд работоспособен. Это НЕ оценка безопасности' },
  ],
  checks: [
    makeCheck('c-1', {
      scenario: 'Smoke: сервис поднимается и отвечает', group: 'owner', actor: '—',
      method: 'GET', path: '/healthz', expectStatus: 200,
      baseline: { http: 200, outcome: 'pass', bodyHashOk: true },
      final: 'pass',
      note: 'PASS smoke подтверждает только работоспособность стенда, а не отсутствие уязвимостей',
    }),
  ],
  attempts: [],
  artifacts: [
    { id: 'art-sum', name: 'summary.json', kind: 'json', present: true, content: '{\n  "run_id": "run-3f5e-b2",\n  "mode": "smoke_only",\n  "security_verdict": "NOT_EVALUATED",\n  "finding_status": null\n}' },
  ],
  tech: {
    image: 'securitylab-demo:local',
    imageDigest: 'sha256:ab12f0…9c33',
    network: 'slb-internal',
    configHash: 'sha256:1d44aa…b802',
    snapshotPin: 'snap-3d81-02 · 77ac910',
    cleanup: 'контейнеры удалены по завершении',
    hashDisclaimer: 'хеши — журнал целостности, не подпись и не гарантия.',
  },
}

export const demoRuns: Run[] = [runBlocked, runFixed, runReview, runTimeout, runSmoke]

/** Сценарий симуляции демо-прогона, создаваемого пользователем из формы.
    Полностью детерминирован: перезагрузка страницы продолжает прогон,
    а не запускает задачу заново. */
export const newRunScript: DemoScriptLike = {
  limitSeconds: 900,
  stages: [
    { id: 'snapshot_pin', label: 'Фиксация снимка', state: 'done', from: 0, to: 2 },
    { id: 'policy_load', label: 'Загрузка политики (узкая v2)', state: 'done', from: 2, to: 3 },
    { id: 'docker_prepare', label: 'Подготовка Docker-окружения', state: 'done', from: 3, to: 16 },
    { id: 'red_generate', label: 'Red: разбор и сценарий', role: 'Red · предложение AI', state: 'wait_model', from: 16, to: 62, waitModelFrom: 22 },
    { id: 'baseline_run', label: 'Baseline: воспроизведение нарушения', state: 'done', from: 62, to: 118 },
    { id: 'blue_generate', label: 'Blue: предложение патча (попытка 1)', state: 'wait_model', from: 118, to: 152, waitModelFrom: 124 },
    { id: 'candidate_check', label: 'Независимая проверка кандидата', state: 'done', from: 152, to: 205 },
    { id: 'recheck_run', label: 'Recheck: повторная проверка', state: 'done', from: 205, to: 238 },
    { id: 'commit_stage', label: 'Отдельный коммит в изолированной копии', state: 'done', from: 238, to: 246 },
  ],
  events: [
    { t: 0, source: 'securitylab', text: 'демо-прогон создан (симуляция; backend не задействован)' },
    { t: 3, source: 'docker', text: 'образ slb-python:3.12-slim готов, сеть slb-internal создана' },
    { t: 16, source: 'hermes', text: 'запрос red.propose → qwen2.5-coder:7b (context 64000)' },
    { t: 62, source: 'hermes', text: 'Red вернул сценарий S-2: чужой заказ по возрастающему ID' },
    { t: 118, source: 'verifier', text: 'baseline: ожидалось 403, получено 200 — нарушение воспроизведено' },
    { t: 152, source: 'hermes', text: 'Blue вернул патч попытки 1' },
    { t: 205, source: 'verifier', text: 'candidate: 4/4 проверок пройдено' },
    { t: 238, source: 'verifier', text: 'recheck: результат подтверждён' },
    { t: 246, source: 'securitylab', text: 'создан отдельный коммит 8e2f41c в изолированной копии; merge и push не выполнялись' },
  ],
  finishAt: 246,
  final: { exec: 'completed', verdict: 'REPRODUCED', finding: 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX' },
}

interface DemoScriptLike {
  limitSeconds: number
  stages: Array<{ id: string; label: string; role?: string; state: Stage['state']; from: number; to?: number; waitModelFrom?: number }>
  events: RunEvent[]
  finishAt: number
  final: { exec: 'completed' | 'failed' | 'timeout'; verdict: Run['verdict']; finding: Run['finding'] }
}

export const defaultArtifactsForNewRun = (runId: string, diff: string): Artifact[] => [
  { id: 'art-sum', name: 'summary.json', kind: 'json', present: true, content: `{\n  "run_id": "${runId}",\n  "demo": true,\n  "security_verdict": "REPRODUCED",\n  "finding_status": "POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX"\n}` },
  { id: 'art-p1', name: 'candidate-1.patch', kind: 'patch', present: true, content: diff },
]
