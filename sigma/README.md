# Sigma-правила (ЧЕРНОВИК, НЕ ПРОВЕРЕНО)

Соответствуют правилам socsim 100100, 100110, 100120, 100140.

> **Статус:** конвертация в Wazuh/Elastic **не проверена** — в среде разработки
> нет `sigma-cli`/`sigmac`. Файлы приложены как артефакт портфолио, а не как
> «готовые к продакшену» правила.

Почему нет правила для 100101 (compromise after bruteforce): это корреляция
состояния («сначала 5 fail, потом success с того же IP»), Sigma такое выражает
плохо. Логика остаётся в `socsim/detect.py` и Wazuh-правиле 100101.

## Как проверить (когда появится sigma-cli)

pip install sigma-cli
sigma convert -t wazuh -p sysmon sigma/ssh_bruteforce.yml
sigma convert -t elasticsearch sigma/web_exploitation.yml

Ожидаемо: YAML → правило целевого формата. Если конвертация падает — правило
надо править (у Sigma строгие требования к полям logsource).