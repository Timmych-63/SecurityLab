# Архитектура и границы доверия

## Реализовано в M1/M2

CLI → Orchestrator → FixtureRunner / DemoGit → Store → Validator → Report.

| Модуль | Ответственность |
|---|---|
| cli.py, config.py | Команды, проверка TOML-лимитов |
| storage.py | SQLite, транзакционные события, атомарный JSONL, блокировка одного worker |
| orchestrator.py | Последовательные стадии, остановка, восстановление, учебный patch/rollback |
| runner.py, process.py | Только точные встроенные образцы; тайм-аут, bounded stdout/stderr |
| gitops.py | Новый учебный репозиторий, отдельная ветка, отключённые hooks, отсутствие push/merge |
| validator.py | Независимые от заявлений роли условия FIXED |
| fixture.py | Синтетический сервис, неизменяемый внешний тест, известное исправление |
| policy.py | Проверка путей, ролей и лимитов; это не OS sandbox |
| report.py | Статический HTML с escaping/CSP, JSON и JSONL |

Стадии: QUEUED → DISCOVERED → CONFIRMED → PATCHED → VERIFIED → DONE.
Отдельный операционный статус: QUEUED/RUNNING/STOPPED/BLOCKED/DONE/ROLLED_BACK.
У находки свои статусы: HYPOTHESIS/CONFIRMED/FIX_PENDING_VERIFICATION/FIXED/NEEDS_REVIEW/
REOPENED_AFTER_ROLLBACK. DONE означает окончание процедуры, не обязательно FIXED.

State + evidence + event коммитятся одной SQLite-транзакцией.
Внешние Git-действия идемпотентны в известных контрольных точках.
Падение ОС освобождает lock. После рестарта RUNNING можно возобновить.
Тесты покрывают смерть процесса и повтор после коммита, но до записи стадии.
Частичные сбои произвольных Git-операций (например, повреждение .git при отключении диска)
не считаются автоматически восстановимыми: это BLOCKED с ручной диагностикой.

## Текущая граница доверия

Локальная ОС, установленный Python/Git, код SecurityLab и каталог состояния доверенные.
Настоящих AI-агентов в процессе нет. Сервис перед запуском должен побайтно совпасть со встроенным
VULNERABLE или FIXED. Внешний тест не находится в ветке Blue. Произвольные команды,
проекты и сгенерированные моделью тесты на хосте не принимаются.

Это не полноценная песочница. Проверки пути и хешей не защищают от другого процесса того же
пользователя, который намеренно меняет файлы между проверкой и исполнением, или правит SQLite.
Нельзя выдавать агентам доступ к каталогу состояния/доказательствам и полагаться на эти guards.
Таблица permit — основа будущих разрешений; реального AI-диспетчера ещё нет.

Локальный process runner ограничивает время и сохранённый вывод, но не CPU/RAM процесса.
На POSIX завершается группа процессов; на Windows подтверждённой поддержки Job Objects нет,
поэтому произвольные дочерние деревья там запрещены. Учебные процессы потомков не создают.
Docker-ограничения подготовлены, фактическая изоляция ещё не проверена.

## Целевая архитектура M3–M5

- Один runtime с одной моделью; Red и Blue вызываются последовательно с новым контекстом.
- Hermes в отдельном агентном исполнителе без Docker socket, доступа к state и production.
- Оркестратор принимает строго типизированные предложения, но не сообщения «успех».
- Red читает ограниченный снимок; Blue предлагает патч только разрешённых путей.
- Runner запускает недоверенный проект в одноразовом контейнере, без сети по умолчанию,
  с ограничениями CPU/RAM/PID/времени, вне контейнера оркестратора.
- Доверенный broker на стороне оператора управляет созданием контейнеров; агенты не получают daemon.
- Хеши, argv, ревизии, фактические результаты и тесты хранятся вне доступного агентам тома.
- Нельзя принимать JSON от AI в качестве Evidence. Его выдаёт только runner.
- Содержимое repo/README/логов — данные, не инструкции и не конфигурация разрешений.

До реализации этой границы `scan` закрыт. По уточнению пользователя Dashboard нужен: основной локальный интерфейс поверх общего ядра. CLI остаётся минимальным; отчёты фиксируют результат конкретного прогона.

## Дорожная карта

| Этап | Результат / условие завершения |
|---|---|
| M0 | Разбор двух требований, отсутствие приложенного архива M0 зафиксировано |
| M1 | Ядро, CLI, очередь, SQLite, события, лимиты — выполнено для учебного режима |
| M2 | Учебный дефект, patch, recheck, валидатор, Git, отчёты — выполнено |
| M3 | Зафиксировать версию Hermes, инструментальные права, реальный локальный AI smoke test |
| M4 | Структурированные находки/патчи от AI, broker и runner, полный цикл на учебной копии |
| M5 | Docker CPU/GPU, egress denial, isolation tests, Windows smoke и resource tests |
| M6 | Dashboard поверх общего ядра: задачи, находки, модель, проверки, история; отчёты и минимальный CLI используют те же данные |
| M7 | Отказоустойчивость всей системы, негативные сценарии, независимая приёмка |
| M8 | Релиз только после PASS обязательных критериев |

Нет обещания сроков без запуска Hermes/model на доступном оборудовании.

## S1: проверка конфигурации контейнера

`sandbox_check.py` собирает наблюдения из /proc и cgroup v2, проверяет запись временного
файла в /data и /tmp. При единственном интерфейсе lo выполняет ограниченный по времени
connect к TEST-NET 192.0.2.1:443; только отсутствие маршрута принимается как успешный
результат, тайм-аут не засчитывается. При других интерфейсах попытка соединения не делается.
Проверяется отсутствие Docker socket в стандартных путях, но не неизвестных bind mounts.
CPU/memory/PID — чтение фактических cgroup-потолков без stress-тестов.
Этот модуль не является универсальным runner и не даёт агентам прав на исполнение кода.

Источники формата настроек:
- https://docs.kernel.org/admin-guide/cgroup-v2.html
- https://docs.docker.com/engine/network/drivers/none
- https://docs.docker.com/engine/containers/run/

## Реализация S2

container_runner.py — доверенный broker на хосте; job_contract.py — формат входных файлов;
container_worker.py — bootstrap внутри нового контейнера. process.py дополнен ограниченным
stdin-потоком с передачей EOF. Источник входа не управляет Docker flags/image/mounts.
Broker → Docker create/inspect → stdin job → ограниченное выполнение → rm/проверка cleanup.
Доказательства S2 пока не принимаются основным валидатором: stdout недоверен.
Реализован Python-only механизм, не универсальный тестовый стенд. См. S2_RUNNER.md.

## S3: соединение оркестратора с S2

Store.mode → Orchestrator → DockerFixtureRunner → DockerBroker → container_worker.
DockerFixtureRunner проверяет точные fixture bytes и формирует неизменяемый пакет.
Внешние JSON receipts связываются с SQLite evidence через ID, digest и binding.
При финальном VERIFIED перечитываются все пять receipts, затем применяется валидатор.
Отмена передаётся от SQLite stop к процессу attach и cleanup контейнера.
Новый режим не меняет schema v1 и не включает автоматический fallback на хост.
Граница доказательств ограничена известным fixture; не путать с произвольным AI-кодом.

## S4 current implementation (supersedes earlier no-adapter status)

CLI ai-demo → HermesAdapter → disposable Hermes worker → private Ollama.
Red then Blue, fresh context, no tools; strict JSON and known-fix AST admission.
After admission, the existing S3 orchestrator verifies the canonical reviewed fix.
AI summaries retain original proposals and verification_run; S3 child mode remains
scripted-demo-docker-no-ai. Queue state and Docker control remain host-only.
No general AI-generated code admission or independent arbitrary-project oracle yet.
See S4_HERMES.md for limits, pins, failure recovery and acceptance requirements.
