SecurityLab — этап 3 / S3

Распакуйте содержимое этого архива в существующую папку проекта, где находятся compose.yaml и папка securitylab. Разрешите замену файлов. Не удаляйте .securitylab: там ваши предыдущие прогоны.

В PowerShell из папки проекта:
docker compose build
py -3 -m securitylab demo --executor docker

Вторую команду выполняйте после успешной сборки.
Ожидаемый результат: stage/status DONE, mode scripted-demo-docker-no-ai, finding_status FIXED. Пришлите итоговый JSON.

Теперь пять проверок учебного цикла проходят через отдельные контейнеры; перед FIXED проверяются привязанные к прогону записи результатов. AI пока не подключён.
90 автоматических тестов PASS; Docker-транспорт в них подменён. Реальный S3-запуск ещё нужно подтвердить на вашем ПК. Старые S1/S2 повторять не требуется.

Подробности: docs/S3_WORKFLOW.md; контрольная точка: docs/STATE.md.
SecurityLab_S3.git.bundle содержит полную историю исходников. Для обычного обновления он не нужен; восстановление в новую папку: git clone SecurityLab_S3.git.bundle SecurityLab_restored
