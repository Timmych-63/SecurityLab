Обновление S2 поверх установленного SecurityLab с UTF8 fix и S1.
Распаковать СОДЕРЖИМОЕ в текущую папку проекта с README.md, compose.yaml, securitylab и tests.
Разрешить замену. База .securitylab и результаты не включены и не заменяются.
Выполнить по очереди, при ошибке остановиться:
docker compose build
py -3 -m securitylab.container_runner --self-test
Пришлите итоговый JSON. Ожидается 5 PASS и cleanup PASS у каждого.
Это реальные проверки нового runner; обычный demo и S1 повторять не требуется.
70 тестов ядра/логики PASS на Linux. Живой Docker S2 пока NOT TESTED.
Пять сценариев: нормальный запуск, exit 7, тайм-аут, лимит вывода, файловые/сетевые границы.
Подробности: docs/S2_RUNNER.md. COMPlETED не означает исправление уязвимости.
Полные исходники и история сохранены в SecurityLab_S2.git.bundle.
