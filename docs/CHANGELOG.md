## S6.3a — guarded standalone Python Docker probe
- Opt-in `repo probe` runs one SHA-256-verified Python source file in existing DockerBroker; no host execution or dependency installation.
- Audits pinned receipt and cleanup; `NOT_EVALUATED` security verdict always, `scan` disabled.
- 12 mocked transport tests; user Windows live run pending.

# История изменений

## S6.2.1 — 2026-11-09
- Исправлена ложная фиксация подмены файла на Windows/Python 3.13,
  где `DirEntry.stat()` возвращает нулевые `st_dev/st_ino`.
- Свежий `lstat` для дальнейшего строгого сравнения с открытым fd,
  SHA-256 и ограничения доступа сохранены.
- Добавлены Windows-emulation и race-negative тесты; на Linux 17+22 PASS,
  ожидается повторная Windows-проверка.


## S6.2 — 2026-11-09
- Доказанная на Windows S6.1 инвентаризация подтверждена; 22 теста PASS.
- Подготовка bounded локальной копии проекта с SHA-256 содержимого, SQLite
  реестром снимков и проверкой наличия/целостности файлов.
- `repo snapshot/snapshots/verify-snapshot/plan`; описательные планы профилей
  без выполнения команд. `scan` остаётся заблокирован.
- Негативные тесты отказов при изменениях, подмене manifest, ссылках,
  ограничениях размера; старое `.securitylab` и модель не изменяются.
- Локальные S6.2 тесты PASS; Windows S6.2 ещё не проверен.


## 0.1.0 — 2026-11-08, контрольная точка M1/M2

- Новый stdlib Python-проект, CLI, TOML-лимиты, SQLite v1 и транзакционные события.
- Последовательная очередь, stop/retry, OS worker lock, восстановление после смерти процесса.
- Синтетический дефект доступа, protected suite, известное исправление и два регрессионных теста.
- Отдельная Git-ветка, неизменная main, commit/diff/revert.
- Валидатор с проверкой хешей/ревизий, нулевого exit status недостаточно.
- Статические HTML/JSON/JSONL-отчёты и пример результата.
- Негативные и интеграционные тесты ядра.
- Предварительные Docker CPU/GPU-конфигурации, исследование официального Hermes API.
- Реальный AI, универсальный sandbox и Windows/GPU-приёмка остаются открытыми.

## UTF8 hotfix для 0.1.0 — 2026-11-08

- Исправлено чтение отчёта в тесте на Windows с CP1251 по умолчанию.
- Явный UTF-8 для остальных файловых чтений/записей тестов и compile-проверки.
- Добавлен регрессионный сценарий CP1251/Unicode; 38 тестов PASS на Linux.
- Схема данных и сохранённые прогоны не меняются.

## S1 — 2026-11-08
- Модуль проверки 16 условий Docker-контейнера и негативные unit-тесты.
- Учтены подтверждённые Windows-тесты и контейнерный запуск пользователя.
- Dashboard возвращён в дорожную карту; минимальный CLI и отчёты сохранены.
- Hermes, модель и универсальный runner ещё не подключены.

## S2 — 2026-11-08
- Зафиксирован реальный S1 PASS: 16 условий контейнера на ПК пользователя.
- Новый Python-only job contract, stdin worker и trusted host Docker broker.
- Одноразовые контейнеры без mounts состояния/ПК, ограничение ресурсов и вывода.
- Inspect до исполнения, сравнение exit status, принудительная очистка, durable intent.
- Пять live self-test сценариев подготовлены, выполнение на ПК ожидается.
- Результат процесса не даёт FIXED; интеграция с очередью/валидатором ещё впереди.

## S3 — 2026-11-08
- Зафиксирован реальный PASS пяти S2-сценариев на ПК пользователя.
- Docker-режим очереди и полный учебный цикл через пять одноразовых контейнеров.
- Host receipts с привязкой к задаче/проверке/Git/хешам; повторная сверка перед FIXED.
- Прокидывание stop, запрет fallback, сохранение режима при восстановлении.
- Вывод finding_status и пути к отчёту в demo CLI.
- Живой S3-прогон ожидается; AI и произвольные проекты пока не допускаются.

## S4 — constrained Hermes integration
- Accepted user's S3 DONE/FIXED run.
- Added pinned Hermes worker and CPU Ollama Compose setup; private runtime network.
- Added strict Red/Blue proposals, AST admission and separate child S3 verification.
- Added ai-smoke/ai-demo, bounded transport, cleanup and immutable image identification.
- Added Windows setup script and 19 tests (109 total).
- Verified actual Hermes API with a fake model endpoint; live inference not yet verified.

## S4.1
- Confirmed user real Hermes/model smoke PASS; AI exercise blocked at Red.
- Generalized synthetic Red caller/record validation; retain rejected raw responses.
- Clarified literal-value prompt and added four regression tests.

## S4.2
- Added static Blue diagnostics and one fresh corrective conversation after rejected output.
- Preserve both attempts and feedback, share existing time budget, retain AST/S3 gates.
- Improved complete-module prompt; no retry on forbidden tools/provider failure.

## S4.3
- Separate Blue containers/time budgets with cleanup before correction.
- JSON response mode and system-level schema, verified on real Hermes API/fake server.
- Explicit timeout/resource/cancellation/output-limit diagnostics and console progress.

## S6.1 — 2026-11-09
- Добавлена самостоятельная read-only инвентаризация произвольного локального
  репозитория с лимитами и распознаванием нескольких стеков и сервисов.
- Добавлен реестр проектов в SQLite и CLI `repo inspect/add/list/show`;
  сохранено совместимое `meta.version=1` (добавлена новая таблица).
- Профили здесь только для обнаружения, без разрешения исполнения; `scan`
  остаётся BLOCKED. Нет передачи исходников модели.
- Добавлены 22 новых unit/негативных теста и три учебных разных проекта.
- Актуальные команды и ограничения: `README_S6_1_RU.md`, `docs/S6_1.md`.

## S6.2.2 — 2026-11-09
- Fixed Windows unittest cleanup of reopened SQLite connection in `tests/test_snapshots.py`.
- Added cross-platform regression test detecting the stale bound-method cleanup.
- No runtime code changed. Local: 18 snapshot + 22 repository tests PASS.
- Windows user verification pending; no change to execution permission.
