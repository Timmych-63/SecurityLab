# SecurityLab S6.2.1 — исправление ошибки Windows

Этот ZIP — маленькое обновление **поверх уже установленной S6.2**.
На Windows S6.2 ошибочно писал `Source changed between enumeration and open`.
Исправлено сравнение идентификаторов файлов; защита от подмены не снята.

## Установка без команд распаковки

Распакуйте ZIP. Скопируйте с заменой ровно два файла:

- `securitylab/snapshots.py` в существующую папку `securitylab`;
- `tests/test_snapshots.py` в существующую папку `tests`.

Остальные файлы нужны для истории и восстановления. НЕ удаляйте `.securitylab`,
не пересобирайте Docker, не скачивайте модель заново.

## Проверка (PowerShell в корне SecurityLab)

```powershell
py -3 -m unittest discover -s tests -p test_snapshots.py -v
py -3 -m unittest discover -s tests -p test_repository.py -v
```

Ожидается **17 тестов S6.2.1** и **22 теста S6.1**; FIFO может быть
ожидаемо пропущен в Windows.

Пробный снимок и его проверка:

```powershell
$state = Join-Path $env:TEMP 'SecurityLab_S621_DemoState'
$project = py -3 -m securitylab --state "$state" repo add ".\examples\s6_repos\python_api" --name "Python example" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo add failed' }
$snapshot = py -3 -m securitylab --state "$state" repo snapshot $project.id | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo snapshot failed' }
py -3 -m securitylab --state "$state" repo verify-snapshot $snapshot.snapshot_id
```

Ожидается `VERIFIED_CONTENT_HASHES`. `scan` и исполнение кода проекта
по-прежнему заблокированы. Linux-тесты прошли, настоящий Windows PASS ожидается.

Подробности: `docs/S6_2_1.md`. Архив содержит полный Git bundle.
