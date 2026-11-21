SecurityLab — S4 / Hermes

Распакуйте содержимое в существующую папку SecurityLab с compose.yaml, разрешите замену. Не удаляйте .securitylab.

В PowerShell из папки проекта:
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Start-S4.ps1

Скрипт собирает Hermes, загружает Qwen3.5 2B (~2.7 GB), запускает модель, затем ai-smoke и ai-demo. Docker Desktop должен работать. CPU-профиль: модель до 6 GiB и Hermes до 1.5 GiB; Docker VM потребуется достаточно памяти (ориентир 8 GiB). Подробности и отдельные команды: docs/S4_HERMES.md.

При первой ошибке скрипт останавливается — пришлите вывод. При успехе пришлите два итоговых JSON. До этого S4 live acceptance остаётся NOT TESTED.

Проверено: 109 автоматических тестов, API настоящего закреплённого Hermes с подставным HTTP endpoint. Реальная локальная модель и Docker-образ в среде разработки не запускались.

Red/Blue работают только с учебным сервисом. Произвольные патчи запрещены; допускается AST проверенного исправления, после чего выполняется S3. Это ещё не аудит произвольных проектов.

SecurityLab_S4.git.bundle содержит полную историю исходников; для обычного обновления не нужен. Восстановление отдельно: git clone SecurityLab_S4.git.bundle SecurityLab_restored
