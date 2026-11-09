# SecurityLab S6.2.2 — исправление одной ошибки теста в Windows

Это небольшое обновление **поверх установленного S6.2.1**.

## Установка без команд распаковки

1. Распакуйте `SecurityLab_S6_2_2_SQLite_Test_Cleanup.zip`.
2. Из ZIP скопируйте `tests/test_snapshots.py` в папку `tests` установленного SecurityLab **с заменой**.
3. Больше ничего менять не нужно. `docs/` и `README` — справочные документы.

Не удаляйте `.securitylab`, том модели и установленные контейнеры.

## Проверка в PowerShell (из внутренней папки SecurityLab)

```powershell
py -3 -m unittest discover -s tests -p test_snapshots.py -v
```

Ожидаемый результат: **Ran 18 tests, OK**.

После успешных тестов можно проверить CLI на отдельном временном состоянии:

```powershell
$state = Join-Path $env:TEMP 'SecurityLab_S622_DemoState'
$project = py -3 -m securitylab --state "$state" repo add ".\examples\s6_repos\python_api" --name "Python example" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo add failed' }
$snapshot = py -3 -m securitylab --state "$state" repo snapshot $project.id | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo snapshot failed' }
py -3 -m securitylab --state "$state" repo verify-snapshot $snapshot.snapshot_id
```

Ожидаемый статус: `VERIFIED_CONTENT_HASHES`. Снимок — **только** копия
с проверкой хешей; выполнение кода проекта и `scan` остаются запрещены.

## Что исправлено

`test_restart_and_sqlite_snapshot_persistence` открывал SQLite повторно, а
teardown закрывал прежнее соединение. Windows блокировал временный `state.sqlite3`
и возвращал `WinError 32`. Исправлен порядок закрытия соединений в тесте.
Добавлен регрессионный тест, ловящий ошибку и на Linux.

В этом обновлении **нет изменений в `securitylab/`**: безопасность и работа
приложения не затронуты. Переустанавливать Docker/Ollama/Hermes не нужно.

Подробности и ограничения: `docs/S6_2_2.md`.
