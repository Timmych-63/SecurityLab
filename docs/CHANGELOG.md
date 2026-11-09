# История изменений

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
