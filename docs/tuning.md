# Тюнинг: исключения ловушек и метрики до/после

> **Честно:** тюнинг сделан на **синтетическом** стенде (seed=2026, 7 дней).
> Результат `precision = 1.0` — артефакт спокойного фона и малого числа
> алертов (11). Это **не** «качество правил в проде».

## Что исключили и почему

| Ловушка | Правило | Исключение | Риск |
|---|---|---|---|
| `nessus_scan` (плановое сканирование уязвимостей) | 100120 (port scan) | не срабатывать на `src` из `198.18.0.0/15` | **Широкое**: атакующий из этого диапазона будет пропущен. Для стенда ок — атакующие только RFC 5737 |
| `dev_tmp_binary` (`/tmp/pytest_runner` разработчика) | 100130 (exec from /tmp) | не срабатывать на `exe`, заканчивающийся на `/tmp/pytest_runner` | Узкое и безопасное: только конкретный путь |

Исключения включаются флагом `--tuning` (по умолчанию **выключены**, чтобы
«до/после» считалось на одних и тех же данных).

## Метрики до/после (факт из прогона)

| Метрика | До | После |
|---|---|---|
| `alerts_total` | 13 | 11 |
| `tp` | 11 | 11 |
| `fp_trap` | 2 | **0** |
| `fp_normal` | 0 | 0 |
| `precision` | 0.846 | **1.0** |
| `campaigns_detected` | 4/5 | **4/5** |
| `traps_alerted` | `rule_100120:1`, `rule_100130:1` | **пусто** |

**Честный вывод:** тюнинг убрал 2 FP на ловушках и **не потерял TP** на этом
сценарии. Это не значит, что он не может навредить: широкое исключение
`198.18.0.0/15` — компромисс стенда.

## Почему `slow_port_scan` не обнаружен — это не баг

`slow_port_scan` намеренно идёт медленнее окна правила 100120 (60с / 15 DROP),
поэтому не срабатывает. В отчёте он помечен `evasive: true`. Это демонстрация
ограничения порогового правила: чтобы ловить медленные сканы, нужны другие
подходы (baseline, длинные окна, аномалии), а не только порог.

## Как воспроизвести

```powershell
python -m socsim generate --scenario scenarios\default.json --out labs
python -m socsim detect --events labs\events.jsonl --out labs\alerts_before.jsonl
python -m socsim detect --events labs\events.jsonl --out labs\alerts_after.jsonl --tuning
python -m socsim evaluate --alerts labs\alerts_before.jsonl --events labs\events.jsonl --truth labs\groundtruth.jsonl
python -m socsim evaluate --alerts labs\alerts_after.jsonl --events labs\events.jsonl --truth labs\groundtruth.jsonl
```