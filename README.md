# soc-launchpad-v2

Тренажёр для входа в SOC (Junior SOC Analyst, L1). Репозиторий:
`soc-launchpad-v2`, пакет и команда: `socsim`. Автор: [oper81](https://github.com/oper81).

> **Важно, честно:** журналы здесь **синтетические** — сгенерированы по шаблонам
> реальных форматов (sshd, syslog, kern/iptables, nginx combined, auditd SYSCALL),
> а не сняты с реальных атак. Это **тренажёр**, а не SIEM и не «система
> обнаружения». Все «атаки» — только в изолированной лаборатории на своих ВМ.

## Что это и зачем

Стенд, максимально похожий на работу L1: движок генерирует поток обычных событий
(99%) и редкие вредоносные кампании, офлайн-детектор ловит их правилами
(100100–100140), а оценщик сравнивает результат с эталоном (ground truth).
Ты работаешь как L1: разбираешь очередь алертов, ставишь вердикты, скрипт
считает твои вердикты и качество правил.

Что **не** делает проект: не заменяет Wazuh, не «детектит в проде», не
гарантирует совпадение с реальной телеметрией. Это учебный стенд.

## Быстрый старт (Windows PowerShell)

```powershell
python -m socsim --help
python -m socsim demo
```

`demo` прогоняет весь конвейер на мини-сценарии (`scenarios/demo.json`) и
печатает сводку. Подробнее — [`docs/quickstart.md`](docs/quickstart.md).

Опционально (после установки): `pip install -e .` → команда `socsim` (то же самое).

## Полный конвейер (на своих данных)

```powershell
# 1. Сгенерировать сценарий (7 дней, 6 кампаний)
python -m socsim generate --scenario scenarios\default.json --out labs

# 2. Детектор (без тюнинга)
python -m socsim detect --events labs\events.jsonl --out labs\alerts_before.jsonl

# 3. Оценка
python -m socsim evaluate --alerts labs\alerts_before.jsonl --events labs\events.jsonl --truth labs\groundtruth.jsonl

# 4. Очередь для L1 + шаблон verdicts.csv
python -m socsim queue --alerts labs\alerts_before.jsonl --verdicts labs\verdicts.csv

# 5. Заполнить verdicts.csv (true_positive / false_positive / benign), затем:
python -m socsim evaluate --alerts labs\alerts_before.jsonl --events labs\events.jsonl --truth labs\groundtruth.jsonl --verdicts labs\verdicts.csv
```

## Результаты на синтетическом стенде (seed=2026, 7 дней)

> **Оговорка, без которой цифры врут:** это **синтетика**, фон спокойный,
> алертов мало (11–13). `precision = 1.0` после тюнинга **не означает**
> качество правил в проде. Цифры воспроизводимы при том же seed и той же
> версии кода.

| Метрика | До тюнинга | После тюнинга |
|---|---|---|
| Всего алертов | 13 | 11 |
| TP | 11 | 11 |
| FP на ловушках | 2 | **0** |
| FP на фоне | 0 | 0 |
| Precision | 0.846 | **1.0** |
| Кампаний обнаружено | 4 из 5 | **4 из 5** |
| `slow_port_scan` (evasive) | не обнаружен | не обнаружен (по замыслу) |

Что это значит честно: тюнинг убрал 2 ложных срабатывания на ловушках
(`nessus_scan`, `dev_tmp_binary`) и **не потерял ни одного TP** на этом
сценарии. Подробно — [`docs/tuning.md`](docs/tuning.md).

## Структура

```
socsim/            движок (только stdlib): модель, рендер, фон, ловушки,
                   кампании, генератор, детектор, оценщик, очередь, CLI
scenarios/         сценарии (JSON) и описание формата
tests/             unit-тесты (unittest)
wazuh/             правила/декодеры Wazuh + примеры для wazuh-logtest
sigma/             Sigma-версии правил
windows/           Sysmon-фрагмент, правила Wazuh для Windows, Atomic runbook
docs/              quickstart, tuning, scenarios, report-example, playbooks/
labs/              артефакты прогонов (в .gitignore)
```

## Что проверено, а что нет (честно)

**Проверено на Python 3.14.4 (Windows), локально:**
- 64 unit-теста (`python -m unittest discover -s tests -v`) — `OK`;
- генерация, детектор, оценщик, очередь, CLI, `demo`;
- XML-синтаксис `wazuh/rules/local_rules.xml`, `wazuh/decoders/local_decoder.xml`,
  `windows/rules/windows_rules.xml`;
- XML-синтаксис фрагментов (`wazuh/ossec/ossec.conf.fragment.xml`,
  `windows/sysmon/sysmon-config-fragment.xml`) — с обёрткой, т.к. это фрагменты;
- YAML-синтаксис `sigma/*.yml`.

**НЕ проверено (нужна инфраструктура, которой нет в среде разработки):**
- **Wazuh:** поведение правил 100100–100140 и декодеров. Нужна ВМ с Wazuh и
  `wazuh-logtest`; см. [`docs/lab-setup.md`](docs/lab-setup.md). **Docker нет**,
  поэтому путь — ВМ (Ubuntu + Wazuh Manager/Agent).
- **Windows-часть:** правила `windows_rules.xml`, Sysmon-фильтры, Atomic
  Red Team. Нужна Windows-ВМ. `if_sid` (60122, 60106, …) **не гарантирую** —
  проверять `wazuh-logtest`.
- **Sigma-конвертация:** `sigma convert -t wazuh` **не работает** без
  backend-плагина (в среде его нет). YAML парсится, конвертация — нет.
- **`replay --speed > 1`:** сжимает окна корреляции; evasive-кампании
  (`slow_port_scan`) могут перестать быть evasive. Предупреждение выводится
  в stderr.

**Формулировка для резюме (честная):** «Учебный стенд: синтетическая
телеметрия + офлайн-детектор + оценка. 64 unit-теста. Правила/декодеры Wazuh,
Sigma и Windows-часть приложены как артефакты; в живой инфраструктуре не
проверены».

## Ограничения (честно)

- Телеметрия **синтетическая**; реализм форматов — приблизительный, не
  гарантирую совпадение с конкретной версией демона.
- Исключение тюнинга для `100120` **широкое** (`198.18.0.0/15`). В реальном
  SOC так делать нельзя без анализа: атакующий из этого диапазона будет
  пропущен. Для стенда ок, т.к. атакующие IP — только RFC 5737.
- `auditd`-строки упрощены; реальный auditd богаче полями.
- `precision = 1.0` — артефакт спокойного синтетического фона, не «качество
  правил».

## Безопасность

- Атакующие IP — только документационные диапазоны
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- Легитимные внешние клиенты — `198.18.0.0/15`.
- Никакого реального вредоносного кода. Все «атаки» — только в изолированной
  лаборатории на своих ВМ.

## Лицензия

MIT, см. [`LICENSE`](LICENSE).
