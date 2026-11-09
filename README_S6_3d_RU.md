# SecurityLab S6.3d — обновление поверх S6.3c

Установи файлы из ZIP **поверх соответствующих папок** проекта. Не трогай
`.securitylab`, SQLite, Docker-том модели, Hermes и существующие данные.

Теперь доступна отдельная команда `repo fastapi-package-probe`: проверка
небольшого многофайлового FastAPI-приложения, с локальными импортами.
Это **не** сканирование уязвимостей и не универсальное исполнение проекта.
Старый `fastapi-probe` не удалён.

Сначала проверка:

```powershell
py -3 -m unittest discover -s tests -p test_package_probe.py -v
```

**Важно:** обновился исполняемый код `container_worker` внутри Docker. Поэтому
надо пересобрать **два** небольших образа в таком порядке:

```powershell
docker compose build demo
docker build -f docker/FastAPI.Dockerfile -t securitylab-fastapi:local .
```

Модель Ollama, Hermes и Qwen не пересобираются и не скачиваются.

Затем из корня проекта:

```powershell
$state = Join-Path $env:TEMP 'SecurityLab_S63d_DemoState'
$p = py -3 -m securitylab --state "$state" repo add ".\examples\s6_repos\python_fastapi_package" --name "FastAPI multi-file" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo add failed' }
$s = py -3 -m securitylab --state "$state" repo snapshot $p.id | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'snapshot failed' }
py -3 -m securitylab --state "$state" repo fastapi-package-probe $s.snapshot_id --entry app/main.py --expect '/health=200' --expect '/version=200' --expect '/__missing__=404' --execute
```

Ожидается `HTTP_CHECKS_PASSED`, `cleanup: PASS`, `source_file_count: 3`,
`security_verdict: NOT_EVALUATED`. Значение `FIXED` здесь не выставляется.

Условия: максимум 31 `.py`-файл, пути модулей без пробелов, явные
`__init__.py` для вложенных пакетов, только FastAPI и Uvicorn в заранее
подготовленном Docker-образе. Для репозитория с несколькими сервисами можно
передать `--service services/api` и `--entry services/api/app/main.py`.
Никакие зависимости и скрипты из самого репозитория не устанавливаются.

Код и тесты: `docs/S6_3d.md`. Новая версия проверена локально с имитацией
Docker. Реальная Windows-приёмка S6.3d ещё не подтверждена.
