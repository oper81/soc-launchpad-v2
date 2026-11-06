# Как добавить свой сценарий

Сценарии — это данные (JSON), а не код. Чтобы добавить новую атаку, не нужно
трогать Python-файлы (если только это не совсем новый тип атаки).

## Шаги
1. Открой `scenarios/default.json`.
2. Скопируй его в новый файл, например `scenarios/my_test.json`.
3. Поменяй параметры:
   - `name` — название сценария.
   - `seed` — поменяй, если хочешь другой набор случайных событий.
   - `hosts` — список хостов.
   - `campaigns` — список атак (можно оставить одну или добавить новых).
   - `traps` — список ловушек.
4. Запусти конвейер с новым сценарием:
   ```powershell
   python -m socsim generate --scenario scenarios\my_test.json --out labs\my_test
   python -m socsim detect --events labs\my_test\events.jsonl --out labs\my_test\alerts.jsonl
   python -m socsim evaluate --alerts labs\my_test\alerts.jsonl --events labs\my_test\events.jsonl --truth labs\my_test\groundtruth.jsonl
   ```

## Ограничения
- IP атакующих должны быть из документационных диапазонов (192.0.2.0/24 и т.д.).
- `target_host` должен быть в списке `hosts`.
- Если указан неизвестный `type` кампании, генератор выдаст ошибку.