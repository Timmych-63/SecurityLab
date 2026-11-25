# S11.3 — навигация категорий для Red, идентификаторы стадий в UI, живой сценарий Blue

Итоги прогона №6 (20.11.2026, сборка S11.2) — первый полный живой цикл этапов 2–3:
гипотеза `/health` (anonymous, ожидание 200 по документации, наблюдение 200) независимо
подтверждена, статус `consistent`, нарушений не найдено, транспорт здоров. Обратная
сторона: 1 решение и 1 проверка — модель завершала исследование сразу после первой
проверки. Остановите dashboard, сделайте резервную копию папки SecurityLab и примените
update (см. «Установка»). Каталог `.securitylab` (история запусков и настройки) не
изменяется.

## Что изменилось (7 правок)

1. **Подсказки непроверенных пар (главное).** `research_contract.probe_suggestions()`
   считает за модель арифметику, которую qwen3.5:2b не делает сама: все GET-маршруты
   карты × все тестовые аккаунты минус уже наблюдённые пары. Порядок категорий:
   anonymous по документированным маршрутам → каждый аккаунт → по одной конкретизации
   каждого шаблонного маршрута (`/records/{id}` → `/records/probe-0`; конкретные
   идентификаторы записей модель находит сама инструментами `read`/`search`). Список
   (до 12 пар) попадает в промпт блоком `SUGGESTED NEXT PROBES (navigation only … not
   obligations and not defect hints)`. Источники — только карта и список аккаунтов:
   никаких исходников, ожидаемых статусов и списков дефектов в подсказках нет.
2. **Правило системного покрытия.** В промпт Red добавлено: перед финальными
   гипотезами закрыть категории (1) anonymous-доступ к документированным маршрутам,
   (2) каждый аккаунт против разрешённых и запрещённых документацией ресурсов,
   (3) неизвестные/несуществующие ресурсы, для которых документация задаёт статус.
   Завершение без покрытия недопустимо при оставшемся бюджете; пустой список
   гипотез по-прежнему честный результат. Ядро не блокирует и не переписывает
   финальные гипотезы — решение остаётся за моделью (прогон №6 показал, что
   http_assist-механика при этом не нужна; она сохранена без изменений).
3. **Идентификаторы стадий в гипотезах.** В строки гипотез `summary.json` добавлены
   `observed_stage` (стадия независимого наблюдения: `http_NN`, `http_assist_NN`)
   и `confirm_stage` (`confirm` для прошедших свежий стенд). DTO отдаёт их как
   `observedStage`/`confirmStage`.
4. **UI: колонка «Свежий стенд» больше не ставит загадочный «—».** Для
   confirmed/refuted строк показывается статус + стадия (`401 · confirm`);
   для consistent — «не требовался: наблюдение совпало с документацией»; для
   insufficient — «—». Ячейка «Наблюдение» показывает стадию Red (`200 · http_01`).
   Пояснение под таблицей дополнено. Дашборд пересобран; в update вложен готовый
   `dashboard/dist` — пересборка на вашей машине не требуется.
5. **`apply_S11_3.ps1` под PowerShell 5.1.** Внутри скрипта вокруг каждого вызова
   docker действует `$ErrorActionPreference='Continue'` — stderr живой сборки больше
   не превращается в `NativeCommandError` и не убивает шаги [5/6]/[6/6]. Скрипт сам:
   проверяет размер архива и маркеры правок до копирования, бэкапит заменяемые файлы
   в `_backup_S11_3\<метка времени>\`, пересобирает образ и **останавливается с
   ошибкой**, если шаг `COPY securitylab` вышел `CACHED`, затем запускает `ai-smoke`.
6. **`scripts/Start-SecurityLab.ps1` — старт после перезагрузки.** Проверяет/запускает
   Docker Desktop (оба стандартных пути установки), поднимает `model`, в цикле с
   повторами ждёт ответа `ollama list` (до 3 минут), затем запускает обычный
   `Start-Dashboard.ps1`. Тот же порядок действий, что вы выполняли вручную.
7. **`compose.ai.yaml`: `restart: unless-stopped` для model.** Как только Docker
   Desktop запущен, контейнер модели поднимается сам; скрипт из п.6 остаётся
   страховкой и синхронизатором. `ai.example.toml` дополнен закомментированными
   `frequency_penalty = 0.4` / `presence_penalty = 0.2` (ключи по-прежнему задаются
   в `ai.local.toml`).

## Установка

Вариант А (рекомендуется): остановите dashboard (Ctrl+C), положите
`SecurityLab_S11_3_update.zip` рядом с `apply_S11_3.ps1` (скрипт из корня архива)
и выполните из корня проекта:

```powershell
powershell -ExecutionPolicy Bypass -File .\apply_S11_3.ps1 -ZipPath .\SecurityLab_S11_3_update.zip
```

Вариант Б (вручную): скопируйте содержимое `update/` из архива в корень SecurityLab
с заменой файлов (папка `dashboard/dist` заменяется целиком), затем пересоберите образ
и запустите smoke:

```powershell
docker compose -f compose.ai.yaml --profile build build hermes
py -3 -m securitylab ai-smoke
```

Порядок обязательный: apply update → rebuild образа → (если меняли) `ai.local.toml` →
`py -3 -m securitylab ai-smoke`. Обратный порядок даёт `Unknown AI configuration keys`.
После установки перезапустите дашборд — он подхватит новый `dist` и новый код ядра.

## Проверка поставки

Маркеры в файлах после распаковки: `probe_suggestions` и `SUGGESTED NEXT PROBES`
(securitylab/research_contract.py), `observed_stage` (securitylab/research_cycle.py),
`observedStage` (securitylab/dashboard_dto.py), `observed_stage` в блоке research
(tests/test_research_cycle.py), `ollama list` (scripts/Start-SecurityLab.ps1),
`unless-stopped` (compose.ai.yaml), `frequency_penalty` (ai.example.toml),
`AuthzNotes` (examples/research/authznotes.md), `S11.3` (README_S11_3_RU.md).

```powershell
py -3 -m unittest discover -s tests -p "test_research_*.py" -v
py -3 -m unittest tests.test_dashboard tests.test_ai -v
docker compose -f compose.ai.yaml --profile build build hermes
py -3 -m securitylab ai-smoke
```

ВАЖНО: код worker'а внутри Docker-образа. Шаг `COPY securitylab` в сборке не должен
быть `CACHED` — иначе продолжит работать прежний код. `apply_S11_3.ps1` проверяет это
сам и останавливается с ошибкой.

## Прогон №7 — что ждать (качество исследования)

- В промпте каждого решения Red появился блок `SUGGESTED NEXT PROBES` — модель
  получает конкретные пары путь+аккаунт вместо самостоятельной арифметики по ROUTES.
- Ожидаемое поведение: несколько решений с http-проверками (anonymous → alice → bob),
  затем гипотезы, включая пары «чужая запись» (ожидание 403). В `summary.json`
  смотрите `coverage.decisions_used` и `coverage.requests_used` — при живой 2b
  реалистично 3–6 решений; если модель снова закрывает цикл после одной проверки,
  пришлите `summary.json` и последний receipt из `.securitylab/ai/<id>/calls/`.
- Если модель упорно выдаёт мусор — прежняя защита: два отклонённых решения подряд
  останавливают прогон с сохранением накопленного (BLOCKED, причина в `notes`).
- Если решите поднять бюджет — правьте `examples/research/*.setup.json` или шаг 03b
  в UI (`decisions` 1..30, `requests` 1..100, `seconds` 60..3600).

## Живой сценарий Blue (AuthzNotes) — первый прогон этапа 4

Готовый сценарий с известным дефектом в границах Blue v1: ожидание 403 (чужая запись),
наблюдение Red 200, разрешённый 200-якорь для владельца (body-hash). Дефект живёт в
самом приложении `examples/s7_repos/authz_vulnerable` (комментарий в коде), документация
`examples/research/authznotes.md` описывает только ожидаемое поведение — ни список
дефектов, ни эталонное исправление агентам не передаются. Красный путь ядро находит
само (подсказки ведут к парам alice/bob на `/records/{id}`).

```powershell
# 1. Регистрация проекта и снимок (state-каталог как у дашборда)
py -3 -m securitylab --state "$env:TEMP\SecurityLab_S72_DemoState" repo add .\examples\s7_repos\authz_vulnerable --name AuthzNotes
py -3 -m securitylab --state "$env:TEMP\SecurityLab_S72_DemoState" repo snapshot PROJECT_ID
# 2. Подготовка исследования
py -3 -m securitylab --state "$env:TEMP\SecurityLab_S72_DemoState" repo prepare-research SNAPSHOT_ID --entry app\main.py --knowledge .\examples\research\authznotes.md --setup .\examples\research\authznotes.setup.json
py -3 -m securitylab --state "$env:TEMP\SecurityLab_S72_DemoState" repo research-check PREPARATION_ID
# 3. Живой запуск (или шаг 05 в dashboard по подготовке из UI)
py -3 -m securitylab --state "$env:TEMP\SecurityLab_S72_DemoState" repo research PREPARATION_ID --execute
```

Ожидаемые стадии при успехе: `http_NN` (наблюдения Red) → `confirm` (свежий стенд,
`confirmed`) → `baseline` (нарушение воспроизведено против плана Blue) → `candidate`
(патч Blue прошёл независимую проверку политики) → `recheck` → `commit`. Итог:
`status=PASS`, `finding_status=FIXED`, в `summary.json` блок `git` с `verified_commit`
и diff. Исходный репозиторий и снимок не изменяются; коммит живёт в изолированной
копии (`git.directory` в summary). Возможные честные исходы: `NEEDS_REVIEW /
patch_not_verified` (Blue не дал проверяемого патча за 2 попытки), `NEEDS_REVIEW /
baseline_not_reproduced`, DONE при refuted — в этих случаях пришлите `summary.json`
и receipts, дальше по факту. Обратите внимание: бюджет в `authznotes.setup.json`
(1800 c / 12 решений / 40 запросов) рассчитан на живую генерацию — прогон №7 сделайте
на обычном проекте (TicketDesk), Blue-сценарий — вторым.

## Переход на qwen3.5:4b (опционально, после прогона №7)

Если покрытие на 2b останется скудным или повысятся частоты отклонений схемы.
Контейнер модели живёт в закрытой сети (`internal: true`) и в интернет не ходит,
поэтому пул делается сервисом `model-pull` (профиль `setup`) на обычной сети. Модель
задаётся переменной `OLLAMA_PULL_MODEL`, по умолчанию `qwen3.5:4b`; прогресс загрузки
виден в консоли. Аргументы после `model-pull` не передавать — они заменяют команду
сервиса, и контейнер завершится без загрузки.

```powershell
docker compose -f compose.ai.yaml --profile setup run --rm model-pull
docker compose -f compose.ai.yaml exec model ollama list   # 4b в списке (короткий ID)
docker compose -f compose.ai.yaml exec model sh -c "curl -s http://localhost:11434/api/tags"   # поле digest у qwen3.5:4b
# ai.local.toml: model = "qwen3.5:4b", model_digest = "<поле digest из /api/tags>", остальные ключи как были
py -3 -m securitylab ai-smoke
```

ВАЖНО: источник `model_digest` — только `/api/tags`. Worker сверяет `model_digest`
из `ai.local.toml` с полем `digest` из `/api/tags` (точное строковое сравнение в
hermes_worker.py). Sha256sum файла манифеста на диске — другой источник, значения
могут не совпадать: у qwen3.5:4b файл манифеста хешируется в `e0b8c85c…`, тогда как
ollama отдаёт в API digest, начинающийся с `d8b0f5e9760c` — короткий ID из
`ollama list`, его первые 12 символов, используйте их для сверки. У 2b оба значения
совпадали, поэтому прежняя инструкция со sha256sum работала. Если curl в контейнере
модели отсутствует:

```powershell
docker run --rm --network securitylab-ai-private curlimages/curl -s http://model:11434/api/tags
```

Если 4b не появился в списке у работающего контейнера модели —
`docker compose -f compose.ai.yaml restart model` и проверьте снова. Другая модель —
`$env:OLLAMA_PULL_MODEL = "<тег>"` перед командой пулла.

Замечания: сервис `model` ограничен `mem_limit: 6g` и `cpus: 2` — 4b в квантованном
виде помещается, но генерация медленнее 2b, поэтому для первого прогона держите
`max_output_tokens = 2048` и бюджет решений 8–12; если TIMEOUT начнёт преследовать,
уменьшайте `decisions`, а не `timeout_seconds`. Держать обе модели можно одновременно
(обе видны в `ollama list`, worker проверяет имя+digest по `/api/tags`), откат —
вернуть в `ai.local.toml` прежнюю пару model/digest и снова `ai-smoke`. Digest-пиннинг
обязателен: worker останавливает прогон, если digest модели изменился.

## Ограничения первой версии (без изменений)

Охват: небольшой многофайловый Python/FastAPI (до 31 модуля / 180 КБ, статические
маршруты, зависимости пиннутого образа, без внешних БД). Red — только GET с
подстановкой `X-Test-User`. Blue — только нарушения с ожидаемым 401/403 и
разрешённым 200-якорем. Подсказки Red — навигация, а не обязательства: финальные
гипотезы и их статус определяются моделью и ядром как раньше, независимое
воспроизведение — только для расхождений с документацией.

Подробности цикла: `docs/S11_1_RESEARCH_CYCLE_RU.md`; план: `docs/RESEARCH_PLAN_RU.md`;
статус: `docs/STATE.md`.
