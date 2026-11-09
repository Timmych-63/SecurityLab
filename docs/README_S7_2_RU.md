# SecurityLab S7.2 — ограниченный Red → независимый baseline → Blue → проверка → Git

## Что добавлено

Команда `repo access-ai` использует Hermes и уже загруженную локальную Qwen в двух отдельных последовательных ролях. Red выбирает один из заранее определённых в доверенной политике случаев отказа в доступе. Затем SecurityLab **до Blue** запускает исходное приложение в Docker и независимым HTTP-проверяющим подтверждает именно этот случай. Только после подтверждения Red получает статус обоснованной гипотезы, и Blue предлагает **полный текст одного выбранного Python-модуля**.

Система выполняет фактический текст Blue через существующий FastAPI Docker-профиль с защищённым независимым HTTP-проверяющим, дважды проверяет соответствие **неизменной операторской политике**, контрольные хеши и квитанции, затем создаёт коммит только в отдельном локальном Git-репозитории/ветке внутри state. Исходный репозиторий и snapshot не редактируются. Ничего не сливается в main автоматически.

Статус `PASS` и `finding_status: FIXED` относятся **только к конкретному независимому набору проверенных прав доступа**, а не к безопасности всего приложения. Кандидат может специально подстроиться под известные тесты. Нет автономного поиска неизвестных нарушений, сгенерированных Red тестов или нового AI-прохода Red после исправления. Режим пока ограничен одним выбранным модулем `app/main.py` небольшого FastAPI-пакета с заранее подготовленными FastAPI/Uvicorn. Для других проектов понадобится расширять профили/контракты, а не подставлять имена примера в ядро.

Критерии не контролируются AI; политика располагается вне проверяемого проекта и состояния SecurityLab. Нет произвольного выполнения команд или установки зависимостей из репозитория, нет Docker socket в контейнере агента, нет доступа к production-сети/секретам, нет автоматического merge/push.

## Установка поверх S7.1

Распаковать ZIP. **Только** файлы из папки `securitylab` скопировать с заменой в `securitylab`, из `tests` — в `tests`, из `docs` — в `docs`. Не удалять `.securitylab`, Docker volumes или модель. Новые файлы `access_ai.py`, `access_contract.py`, `proposal_modes.py`, `test_access_ai.py` также нужно скопировать. При установке вручную нельзя пропустить обновлённые `hermes_adapter.py`, `hermes_worker.py` и `cli.py`.

Тесты без настоящей модели/Docker:

```powershell
py -3 -m unittest discover -s tests -p test_access_ai.py -v
```

Ожидается: `Ran 18 tests`, `OK`.

Нужно пересобрать Hermes **после обновления Python-файлов**, чтобы контейнер видел новый тип предложения. Эта команда не перекачивает модель:

```powershell
docker build -f docker/Hermes.Dockerfile -t securitylab-hermes:s4 .
docker compose -f compose.ai.yaml up -d model
```

Ранее собранные `securitylab-demo:local` и `securitylab-fastapi:local` из S6.3d используются без изменений. Если Docker выключен, сначала запустить Docker Desktop обычным способом.

Первый реальный запуск на **синтетическом** тестовом проекте:

```powershell
$state = Join-Path $env:TEMP 'SecurityLab_S72_DemoState'
$policy = '.\examples\security_policies\record_ownership.json'

$p = py -3 -m securitylab --state "$state" repo add '.\examples\s7_repos\authz_vulnerable' --name 'S7.2 synthetic vulnerable' | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo add failed' }

$s = py -3 -m securitylab --state "$state" repo snapshot $p.id | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo snapshot failed' }

py -3 -m securitylab --state "$state" repo access-ai $s.snapshot_id --entry app/main.py --policy "$policy" --execute
```

**Возможные результаты:** `PASS/FIXED` — при правильном патче от реальной модели и трёх успешных независимых Docker-проверках; `NEEDS_REVIEW` — независимые проверки не приняли гипотезу или фактическое исправление; `BLOCKED` — ошибка модели, транспорта, безопасности, Git или доказательств. `BLOCKED` нельзя лечить отключением проверок. Прочитать поле `error` и соответствующий receipt. Вызовы Red/Blue могут занять значительное время, особенно на CPU; тайм-аут каждой попытки модели ограничен.

Отчёты лежат в каталоге `$state\access_ai\<run_id>\summary.json`, квитанции в подпапках `calls`, `baseline`, `candidate`, `recheck`. Если есть `git`, смотреть `git.directory`, `git.branch`, `git.base_commit`, `git.verified_commit`. Ветка и diff изолированы внутри state, оригинальный проект не меняется.

## Как принимались изменения до Windows

Unit-tests и интеграционные mock-tests доказывают контракты/логику, но не реальное Docker/Hermes inference. Реальная двухконтейнерная инфраструктура и S7.1-политика уже были успешно проверены пользователем на Windows; **новая объединённая команда `access-ai` ещё не проверена на его Windows**. Режим `scan` остаётся заблокированным.
