# SecurityLab S6.3c — FastAPI профиль (ограниченный)

Основа: S6.3b (подтверждено на Windows: 17 тестов и настоящий HTTP PASS).
Новый профиль: **один Python-файл с `app = FastAPI(...)`** из проверенного
снимка, без локальных импортов других файлов проекта. Это не универсальный
запуск requirements.txt, не скан безопасности, не Red/Blue.

Установка: распаковать обновление и перенести файлы с сохранением путей из
`securitylab`, `tests`, `docker`, `examples`, `docs` в существующую папку.
Не заменять/не удалять `.securitylab`, Git, Docker/Ollama volumes, модель.

```powershell
py -3 -m unittest discover -s tests -p test_fastapi_probe.py -v
```

Ожидается `Ran 10 tests`, `OK`.

Один раз собрать **только FastAPI-образ**, отдельно от модели:

```powershell
docker build -f docker/FastAPI.Dockerfile -t securitylab-fastapi:local .
```

При сборке зависимости скачиваются из package index; во время проверки
репозитория ничего не скачивается и наружной сети нет. Транзитивные зависимости
пока не запинены по SHA-256, supply-chain lock ещё не реализован.

Первый реальный запуск:

```powershell
$state = Join-Path $env:TEMP 'SecurityLab_S63c_DemoState'
$p = py -3 -m securitylab --state "$state" repo add '.\examples\s6_repos\python_fastapi_min' --name 'FastAPI fixture' | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo add failed' }
$s = py -3 -m securitylab --state "$state" repo snapshot $p.id | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'snapshot failed' }
py -3 -m securitylab --state "$state" repo fastapi-probe $s.snapshot_id --entry main.py --expect '/health=200' --expect '/__missing__=404' --execute
```

Ожидается `HTTP_CHECKS_PASSED`, `cleanup=PASS`, `security_verdict=NOT_EVALUATED`.
При `BLOCKED` покажи итоговый JSON и безопасно обезличенный
`$state\fastapi_probes\<run_id>\docker_receipt.json`; ограничения отключать
не нужно. `scan` остаётся отключённым, старый `http-probe` не удалён.
