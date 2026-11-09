# SecurityLab S6.3a — ограниченный Docker probe для Python

**Устанавливается поверх S6.2.2**, которую пользователь уже подтвердил на Windows:
18 тестов `test_snapshots.py` PASS.

Скопируйте с заменой из ZIP `securitylab/cli.py` и
`securitylab/profile_plan.py`. Скопируйте новый файл
`securitylab/probe_runner.py`. Добавьте `tests/test_probe.py` и папку
`examples/s6_repos/python_standalone/` целиком. Остальные файлы приложения,
старый `.securitylab`, модель и Docker volumes **не удалять**.

## Проверка

```powershell
py -3 -m unittest discover -s tests -p test_probe.py -v
```

Ожидаемый локальный результат: `Ran 12 tests / OK` (Docker подменён в тестах).

Для реальной пробы в Docker из корня SecurityLab:

```powershell
$state = Join-Path $env:TEMP 'SecurityLab_S63a_DemoState'
$project = py -3 -m securitylab --state "$state" repo add '.\examples\s6_repos\python_standalone' --name 'Standalone fixture' | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo add failed' }
$snapshot = py -3 -m securitylab --state "$state" repo snapshot $project.id | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo snapshot failed' }
py -3 -m securitylab --state "$state" repo verify-snapshot $snapshot.snapshot_id
if ($LASTEXITCODE -ne 0) { throw 'verification failed' }
py -3 -m securitylab --state "$state" repo probe $snapshot.snapshot_id --entry main.py --execute
```

Если Docker-образ `securitylab-demo:local` отсутствует, команда вернёт BLOCKED.
Проверить наличие образа: `docker image inspect securitylab-demo:local`.
Принудительно менять image ID, отключать ограничения или перескачивать модель
не нужно.

При штатном запуске ожидается `EXECUTED_UNTRUSTED`, `exit_code: 0`,
`cleanup: PASS`, `security_verdict: NOT_EVALUATED`. Это подтверждение работы
ограниченного транспорта, **не проверка безопасности Python-приложения**.
`repo scan` намеренно по-прежнему BLOCKED. Для реального FastAPI нужны отдельная
подготовка зависимостей, запуск сервиса и независимый HTTP-проверяющий.

Подробнее: `docs/S6_3a.md`.
