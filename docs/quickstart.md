# Быстрый старт (Windows PowerShell)

Цель: за 5 минут получить первый прогон и увидеть алерты. Всё локально,
без Docker и без Wazuh.

## 0. Требования
- Python 3.9+ (проверено на 3.14.4).
- Больше ничего: только стандартная библиотека.

Проверка:
```powershell
python --version
```

## 1. Из корня проекта
```powershell
python -m socsim --help
python -m socsim version
```

## 2. Полный конвейер на мини-сценарии (одна команда)
```powershell
python -m socsim demo
```
Печатает `generate: N events`, `detect: M alerts`, `evaluate: {...}`.
Артефакты — в `labs\demo\`.

## 3. Полный конвейер на сценарии по умолчанию (7 дней)
```powershell
python -m socsim generate --scenario scenarios\default.json --out labs
python -m socsim detect --events labs\events.jsonl --out labs\alerts.jsonl
python -m socsim evaluate --alerts labs\alerts.jsonl --events labs\events.jsonl --truth labs\groundtruth.jsonl
```

## 4. Очередь алертов для L1
```powershell
python -m socsim queue --alerts labs\alerts.jsonl --verdicts labs\verdicts.csv
```
Откроется читаемая очередь и создастся `labs\verdicts.csv`:
колонки `alert_index,timestamp,rule_id,host,verdict,comment`, `verdict` пустой.

Заполни `verdict` (`true_positive`, `false_positive`, `benign`), затем:
```powershell
python -m socsim evaluate --alerts labs\alerts.jsonl --events labs\events.jsonl --truth labs\groundtruth.jsonl --verdicts labs\verdicts.csv
```
В отчёте появится блок `verdicts: {correct, wrong}`.

## 5. Тюнинг (исключения ловушек)
```powershell
python -m socsim detect --events labs\events.jsonl --out labs\alerts_after.jsonl --tuning
python -m socsim evaluate --alerts labs\alerts_after.jsonl --events labs\events.jsonl --truth labs\groundtruth.jsonl
```
Сравни с прогоном без `--tuning`. Подробно — `docs/tuning.md`.

## 6. Replay (проигрывание событий)
```powershell
python -m socsim replay --events labs\demo\events.jsonl --speed 100 --max-gap 0.1
```
**Внимание:** `--speed > 1` сжимает окна корреляции; evasive-кампании могут
перестать быть evasive — в stderr будет предупреждение.

## Тесты
```powershell
python -m unittest discover -s tests -v
```
Ожидаемо: 64 теста, `OK`.

## Что дальше
- Свой сценарий: `docs/scenarios.md`.
- Wazuh-часть (нужна ВМ): `docs/lab-setup.md`.
- Тюнинг и метрики: `docs/tuning.md`.