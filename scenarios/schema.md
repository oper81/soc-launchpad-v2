# Формат сценария (schema.md)

Сценарий — это JSON-файл, который описывает, какие события сгенерировать.
Сценарий не содержит кода, только параметры.

## Обязательные поля
- `schema_version` (int): Должно быть `1`.
- `name` (str): Имя сценария.
- `duration_days` (int): Длительность генерации в днях.
- `seed` (int): Зерно для генератора случайных чисел. Одинаковый seed = одинаковые события.
- `hosts` (list[str]): Список имен хостов (например, `["web01", "db01"]`).
- `campaigns` (list[dict]): Список кампаний (атак).

## Опциональные поля
- `description` (str): Описание сценария.
- `background` (dict): Какие фоновые события генерировать. Ключи: `"ssh"`, `"web"`, `"cron"` (по умолчанию все `true`).
- `traps` (list[str]): Список ловушек (легитимных событий, похожих на атаки).

## Формат кампании (внутри `campaigns`)
- `type` (str): Тип атаки. Доступные типы: `ssh_bruteforce_compromise`, `web_exploitation`, `port_scan_recon`, `slow_port_scan`, `valid_account_after_hours`.
- `start_day` (int): День начала (0 = первый день).
- `start_hour` (int): Час начала (0-23).
- `attacker_ip` (str): IP атакующего (только из RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- `target_host` (str): Имя хоста-цели (должен быть в списке `hosts`).
- `target_user` (str, опционально): Имя пользователя (для SSH-атак).

## Доступные ловушки (внутри `traps`)
- `expired_password_service_account`
- `forgotten_password`
- `nessus_scan`
- `admin_useradd_crontab`
- `dev_tmp_binary`