# SecurityLab S4.4 — исправление фильтра Blue

Обновление поверх установленной S4.3. Распакуйте содержимое архива в папку
проекта, где находятся compose.ai.yaml и каталог securitylab, с заменой файлов.
Состояние запусков и скачанная модель не затрагиваются.

Из PowerShell в этой папке:

```powershell
py -3 -m unittest discover -s tests -v
docker compose -f compose.ai.yaml --profile build build hermes
docker compose -f compose.ai.yaml up -d model
docker compose -f compose.ai.yaml exec -T model ollama list
py -3 -m securitylab ai-demo
```

Если Ollama ещё запускается, дождитесь появления списка моделей перед ai-demo.
Заново скачивать модель не нужно. При ошибке сборки не запускайте старый образ.

Теперь принимается показанный вами вариант с owner = record["owner"].
Разрешены четыре проверенные формы сравнения; произвольный код по-прежнему
не допускается. В summary указаны reviewed_variant и canonicalization:
Docker проверяет канонический учебный вариант, а не исходный текст Blue.
PASS новой реальной AI-проверки пока не подтверждён.

При BLOCKED пришлите результат и stderr указанной в нём квитанции calls.
Не повторяйте запуск многократно без разбора причины.
