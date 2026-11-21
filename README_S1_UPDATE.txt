Обновление S1 поверх SecurityLab 0.1.0 с UTF8 fix.
Распакуйте содержимое в папку проекта с README.md, securitylab и tests, заменив файлы.
База .securitylab не включена и не изменяется.
Выполните по очереди (при ошибке остановиться):
docker compose build
docker compose run --rm --entrypoint python demo -m securitylab.sandbox_check
Пришлите JSON проверки. Общий PASS относится только к 16 перечисленным условиям.
Произвольные проекты и AI ещё не запускаем.
45 тестов логики/ядра прошли на Linux; реальные проверки Docker S1 ожидаются.
Git-история и все исходники сохранены в приложенном bundle.
