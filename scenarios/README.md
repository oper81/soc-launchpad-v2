# Сценарии

Здесь лежат JSON-файлы сценариев для `socsim`.

- `default.json` — полный сценарий на 7 дней (6 кампаний, ловушки, фон).
- `demo.json` — мини-сценарий на 1 день (1 кампания), используется в `python -m socsim demo`.

Чтобы создать свой сценарий:
1. Скопируй `default.json` в `my_scenario.json`.
2. Измени `name`, `seed`, `hosts`, `campaigns` и `traps`.
3. Запусти: `python -m socsim generate --scenario scenarios\my_scenario.json --out labs`.

Формат описан в [schema.md](schema.md).