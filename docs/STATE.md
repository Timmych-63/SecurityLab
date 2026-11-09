# Latest S6.3a checkpoint (2026-11-09)

S6.2.2 18 snapshot tests confirmed on user Windows. S6.3a adds opt-in single-file Python Docker probe; only mock-transport tests locally (12); live Windows S6.3a not yet confirmed. Not a security scan. See docs/S6_3a.md.

# АКТУАЛЬНАЯ ТОЧКА — S6.2.2 Windows test cleanup hotfix, 2026-11-09

- На Windows пользователя в S6.2.1 16 из 17 snapshot-тестов PASS;
  единственный ERROR — `WinError 32` на удалении `state.sqlite3` после
  повторного открытия SQLite в одном тесте.
- Исправлена регистрация unittest cleanup текущего `Store` **только в тесте**.
  Новый регрессионный тест ловит утечку и на Linux. Локально 18/18 S6.2.2
  и 22/22 S6.1 PASS; Windows S6.2.2 пока ожидает подтверждения.
- Код приложения, Hermes, Docker, модель, SQLite schema и оригинальная
  `.securitylab` не изменены. `scan`/исполнение произвольных репозиториев BLOCKED.
- Инструкция: `docs/S6_2_2.md`. Дальше реальное CLI snapshot/verify на Windows,
  затем S6.3 безопасный профильный executor.

---

# АКТУАЛЬНАЯ ТОЧКА — S6.2.1 Windows hotfix, 2026-11-09

- На ПК пользователя S6.2 оказался нерабочим: 15 тестов -> 2 FAIL, 9 ERROR.
  Причина: некорректное сравнение кэшированных Windows DirEntry st_dev/st_ino=0
  с идентификаторами реального открытого файла.
- S6.2.1 вносит исправление в `snapshots.py` и добавляет два теста.
  Linux: 17 S6.2 и 22 S6.1 теста PASS; Windows S6.2.1 ещё не проверен.
- Никаких новых разрешений исполнения: `scan` и команды из исходника BLOCKED.
- Команды и границы безопасности: `docs/S6_2_1.md`.
- Дальше: Windows PASS -> S6.3 доверенный профильный контейнерный executor.

---

# АКТУАЛЬНАЯ ТОЧКА — S6.2, 2026-11-09

- S6.1 пройден на Windows пользователя: 22 теста PASS, 1 ожидаемый SKIP
  (FIFO), оба `repo inspect` завершились успешно; проверена общая регистрация
  и инвентаризация разных структур, не запуск проектов.
- S6.2: локальные bounded content-hashed copies; manifest SHA-256 в SQLite,
  `repo snapshot`, `repo verify-snapshot`, `repo snapshots`, `repo plan`.
  План профилей без исполнения: Python/Node в проектировании; Go/Rust/Java
  пока только распознаются. `scan`, shell и сеть к продуктам запрещены.
- 15 новых S6.2 тестов, 22 S6.1, 5 Blue-prompt, 7 sandbox и 3 reviewed
  variants теста PASS локально. Проверка S6.2 на Windows ожидается, общая
  старая suite здесь не завершилась из-за длительных AI-интеграционных тестов.
- Следующее: S6.3 безопасный исполнитель для одного явно разрешённого
  профиля, внешние проверяющие; затем S7 Red/Blue на сторонних проектах,
  S8 Dashboard, S9 устойчивость, S10 V1. См. `docs/S6_2.md`.
- Ниже — предыдущие контрольные точки, сохранены для истории.

---

# АКТУАЛЬНАЯ ТОЧКА — S6.1, 2026-11-09

- Source baseline: S5.1, Git `6bf3f56` (полный fixture AI pipeline подтверждён
  пользователем на Windows, AI run `f31d8098dbb5439db650a7f97e0328bb`,
  `PASS/FIXED`; не переносить этот статус на другие приложения).
- S6.1: реализованы `repo inspect/add/list/show` и профили определения стека,
  защищённая от простого обхода каталогов инвентаризация, регистрация в SQLite.
  Проекты не выполняются; `scan` по-прежнему BLOCKED. См. `docs/S6_1.md`.
- S6.1 прошёл отдельные unit/негативные тесты в окружении разработчика.
  Windows-приёмка S6.1 пока не проводилась. Полный legacy-suite здесь
  завис на интеграционных тестах; его PASS не заявлен.
- **Следом S6.2**: hash-verified source snapshot + профили запуска и новая
  trust boundary для тестирования разных проектов; потом общий Red/Blue,
  независимая проверка, Git integration и Dashboard.
- Все записи ниже — исторические этапы, а не текущие инструкции запуска.

---

# SecurityLab — S4 implementation, 2026-11-08

## Accepted on user's Windows PC
- Core UTF8 fix: 37 PASS + 1 expected Windows symlink SKIP.
- S1 isolation configuration: 16 PASS.
- S2 broker: normal/nonzero/timeout/output_limit/boundaries and all cleanup PASS.
- S3 full Docker fixture cycle: DONE/FIXED, one attempt, no error;
  run d6f559e8291348529e92dc44e55fb3f4. Do not repeat S1/S2/S3 without new cause.

## Current S4
Hermes adapter, isolated worker, sequential Red/Blue proposals, strict schemas,
AST-equivalent-to-reviewed-fix gate, child S3 validation, persisted AI summaries.
New ai-smoke / ai-demo and scripts/Start-S4.ps1. See S4_HERMES.md for exact boundary.
109 automated tests PASS; real pinned Hermes + fake HTTP model API probe PASS.
Live Docker image build, Ollama model generation, Windows S4: NOT TESTED.
Source base: 782916138b34f1e7893b7495ec7e067d3e5d16cb. Final commit in S4_MANIFEST.json.

## Next action
User overlays S4 archive and runs Start-S4.ps1. Obtain ai-smoke PASS and ai-demo
PASS/FIXED or diagnose first error. Do not claim live AI success from mocked tests.
Model Qwen3.5 2B, CPU initially, context64K, one model/two sequential roles.
Hermes pinned source e075441241b8d626789b4aae0e376f86eabf824d. No CS AIReviewer.

## Product plan and limitations
First constrained AI exercise → independent arbitrary-patch behavior checks on an
approved real project → Dashboard → multi-service support and stabilization.
Dashboard is the main UI; minimal CLI and HTML/JSON reports remain.
No arbitrary-project scan, cloud fallback, automatic merge or model-declared FIXED.
No hard-kill orphan reaper or resumable AI queue yet. Current AI workflow canonicalizes
only the reviewed AST; it is not a general autonomous security audit.

## S4.1 current checkpoint
User real ai-smoke PASS: a71a05e55388407788b15700a93cdd09.
S4 build/model/inference accepted; full AI cycle BLOCKED at Red in run
7b4972e37f7748908c658468e994babf. Original rejected response was not retained.
S4.1 replaces the two-pair whitelist and logs rejected replies. See S4_1_RED_FIX.md.
Next: cached Hermes rebuild then ai-demo only. Full cycle remains pending.

## S4.2 current checkpoint
User S4.1 run 5e36c06e6300438dbc0ac4e4ee1929d1 reached Blue. Invalid Blue
proposal blocked before execution (missing RECORDS, owner read before 404 guard).
S4.2 adds one bounded corrective retry, preserving strict AST/S3 checks and both replies.
Same total role timeouts. Next: cached Hermes rebuild and ai-demo; no model download.
Live full AI cycle still pending. See S4_2_BLUE_RETRY.md.

## S4.3 current checkpoint
User e81dfed72e514e2f9ab8f72c30b27ce4 timed out in Blue after 300.0245s, cleanup PASS.
S4.3 replaces shared-budget retries with separate containers and 300s per attempt.
Added system JSON contract, JSON response_format, explicit timeout status/progress.
119 automated tests and real-Hermes/fake-HTTP format probe PASS; live S4.3 pending.
Next: cached Hermes rebuild, ensure model running, ai-demo. See S4_3_ATTEMPTS.md.
