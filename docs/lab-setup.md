# Лаборатория Wazuh (ЧЕРНОВИК, НЕ ПРОВЕРЕНО)

> **Статус:** конфиги в `wazuh/` — **артефакт**, они **не проверены** в этой
> среде (нет Docker, нет ВМ Wazuh). Ниже — как проверить их у себя.
> Пока не прогнан `wazuh-logtest` — **нельзя** писать «правила работают».

## Что нужно
- Изолированная ВМ с Wazuh Manager (Ubuntu 22.04, официальная установка).
- Агент на Linux-ВМ (можно та же ВМ).
- **Никакого выхода в интернет** с атакующих машин (у нас всё синтетическое, но правило гигиены).

## Установка (кратко, не проверено)
1. Установить Wazuh Manager по официальной инструкции.
2. Скопировать:
   - `wazuh/rules/local_rules.xml` → `/var/ossec/etc/rules/local_rules.xml`
   - `wazuh/decoders/local_decoder.xml` → `/var/ossec/etc/decoders/local_decoder.xml`
   - фрагмент из `wazuh/ossec/ossec.conf.fragment.xml` → в `/var/ossec/etc/ossec.conf`
   - `wazuh/ossec/auditd.rules` → `/etc/audit/rules.d/99-socsim.rules`, затем `augenrules --load`
3. `systemctl restart wazuh-manager` (и агент).

## Проверка правил — `wazuh-logtest` (ключевой шаг)

sudo /var/ossec/bin/wazuh-logtest

Вставить по очереди строки из `wazuh/logtest/samples.txt`.
**Ожидаемо (не гарантия):**
- строка 1 (Failed password) — matched by 5710 (sshd), но **100100 сработает только после 5 таких за 120с**. `wazuh-logtest` **не накапливает** состояние между вставками — для frequency-правил нужен реальный поток или `localfile`.
- строка 3 (`/.env`) — ожидаем 100110 (если декодер nginx распознает формат).
- строка 4 (`IPTABLES DROP`) — 100120 только после 15 за 60с; см. выше.
- строка 5 (`exe="/tmp/payload" key="exec_tmp"`) — ожидаем 100130, **если** декодер `auditd-exec-tmp` сработал.

## Как подать синтетические логи
Проще всего: на агенте в `localfile` указать **наши** файлы из `labs/logs/<host>/`, например:

<localfile> <log_format>syslog</log_format> <location>/home/user/soc-launchpad-v2/labs/logs/web01/auth.log</location> </localfile> 
``` Либо проигрывать через `python -m socsim replay` и дописывать в файл, который читает агент.