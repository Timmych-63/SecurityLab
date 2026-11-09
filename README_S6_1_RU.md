# SecurityLab S6.1 — подключение и инвентаризация разных проектов

**Тип обновления:** overlay поверх установленной S5.1 (`6bf3f56`); полный
Git bundle в архиве для восстановления исходников. Модель Qwen и том Docker
не затрагиваются. `.securitylab` не удалять.

## Установка overlay в существующую папку на Windows

Откройте PowerShell в каталоге SecurityLab (там, где лежат `securitylab/cli.py`
и `compose.ai.yaml`). Архив ZIP должен быть в Downloads:

```powershell
$zip = "$env:USERPROFILE\Downloads\SecurityLab_S6_1_Repository_Inventory.zip"
$update = "$env:TEMP\SecurityLab_S6_1_Overlay"
Expand-Archive -LiteralPath $zip -DestinationPath $update -Force
Copy-Item "$update\securitylab\*.py" ".\securitylab\" -Force
Copy-Item "$update\tests\test_repository.py" ".\tests\" -Force
py -3 -m unittest discover -s tests -p test_repository.py -v
```

Документация и примеры в ZIP необязательны для запуска; можно скопировать
`docs/S6_1.md` и `examples/s6_repos` вручную, если хотите держать их в проекте.
Перед обновлением незакоммиченные ручные правки в `cli.py` и `storage.py`
сохраните отдельно: эти два файла заменяются.

## Что попробовать

```powershell
py -3 -m securitylab repo inspect "C:\ПУТЬ\К\КОПИИ_ПРОЕКТА"
py -3 -m securitylab repo add "C:\ПУТЬ\К\КОПИИ_ПРОЕКТА" --name "Мой проект"
py -3 -m securitylab repo list
py -3 -m securitylab profiles
```

Команда `repo add` только сохраняет сведения в SQLite; она НЕ запускает проект,
не клонирует репозиторий, не исправляет код и не обращается к модели. Используйте
копию проекта без секретов. Если текущий каталог — сам проверяемый репозиторий,
укажите `--state "C:\SecurityLabState"` перед `repo add`, чтобы состояние
не записывалось внутрь проверяемого каталога.

`repo show <ID>` повторно смотрит метаданные и сообщает CHANGED_METADATA или
UNCHANGED_METADATA. Это не криптографическая проверка кода. `scan` всё ещё
намеренно заблокирован до безопасного исполнения. Для S6.1 Docker не нужен.

## Восстановление исходников отдельно

Извлеките из ZIP `SecurityLab_S6_1.bundle` и выполните в пустой директории:

```powershell
git clone ".\SecurityLab_S6_1.bundle" ".\SecurityLab_Source"
git -C ".\SecurityLab_Source" rev-parse --short HEAD
```

Нужный HEAD указан в manifest S6.1. Это альтернативный путь восстановления,
**не нужно** клонировать bundle поверх рабочей папки или удалять `.securitylab`.
