"""Офлайн-детектор: правила 100100-100140 -> alerts.jsonl (формат Wazuh).

Эталон (groundtruth.jsonl) НЕ читает — только события. Одно событие -> максимум
один алерт (самое специфичное правило), как в Wazuh. Для корреляционных правил
(100100, 100120) есть подавление: один алерт на эпизод, пока не пройдёт
SUPPRESS_WINDOW без новых событий с того же IP.

tuning=True включает исключения для ловушек (см. TUNING ниже). По умолчанию
False — чтобы "до/после" считалось на одних и тех же данных.

TUNING (честные компромиссы):
  - 100120 не срабатывает на src из LEGIT_EXTERNAL_NETS (ловушка nessus_scan).
    Риск: атакующий из этого диапазона будет пропущен. У нас атакующие — только
    в RFC 5737, так что для стенда ок.
  - 100130 не срабатывает на exe, заканчивающийся на /tmp/pytest_runner
    (ловушка dev_tmp_binary). Узко и безопасно.
"""
import json
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List, Optional, Tuple

from .common import is_legit_external_ip

RULE_SSH_BRUTEFORCE = 100100
RULE_SSH_COMPROMISE = 100101
RULE_WEB_EXPLOIT = 100110
RULE_PORT_SCAN = 100120
RULE_EXEC_TMP = 100130
RULE_VALID_AFTER_HOURS = 100140

WEB_SUSPICIOUS = ("/admin", "/.env", "/../../", "/shell.php", "/wp-login.php")

SSH_WINDOW = timedelta(seconds=120)
SSH_THRESHOLD = 5
COMPROMISE_LOOKBACK = timedelta(minutes=10)
SCAN_WINDOW = timedelta(seconds=60)
SCAN_THRESHOLD = 15
SUPPRESS_WINDOW = timedelta(seconds=300)

TUNING_EXEC_TMP_SUFFIX = "/tmp/pytest_runner"


def _load_events(path: str) -> List[Dict[str, Any]]:
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _ts(ev: Dict[str, Any]) -> datetime:
    return datetime.fromisoformat(ev["ts"])


def _full_log(ev: Dict[str, Any]) -> str:
    from .model import Event, Truth
    from .render import render
    e = Event(ts=_ts(ev), source=ev["source"], host=ev["host"], kind=ev["kind"],
              fields=ev.get("fields", {}), truth=Truth())
    return render(e)


def _alert(ev: Dict[str, Any], rule_id: int, level: int, desc: str) -> Dict[str, Any]:
    return {
        "timestamp": ev["ts"],
        "rule": {"id": rule_id, "level": level, "description": desc},
        "agent": {"name": ev["host"]},
        "full_log": _full_log(ev),
    }


def detect(events_path: str, out_path: str, tuning: bool = False) -> Dict[str, Any]:
    events = _load_events(events_path)
    events.sort(key=_ts)

    alerts: List[Dict[str, Any]] = []
    ssh_fail_by_ip: Dict[str, Deque[datetime]] = defaultdict(deque)
    bruteforce_ips: Dict[str, datetime] = {}
    scan_by_ip: Dict[str, Deque[datetime]] = defaultdict(deque)
    last_alert_bruteforce: Dict[str, datetime] = {}
    last_alert_scan: Dict[str, datetime] = {}

    for ev in events:
        src = ev["source"]
        kind = ev["kind"]
        f = ev.get("fields", {})
        ip = f.get("ip") or f.get("src")
        ts = _ts(ev)

        # 100130: exec from /tmp (с исключением при tuning)
        if src == "auditd" and kind == "exec_tmp" and str(f.get("exe", "")).startswith("/tmp/"):
            exe = str(f.get("exe", ""))
            if tuning and exe.endswith(TUNING_EXEC_TMP_SUFFIX):
                continue  # ловушка dev_tmp_binary
            alerts.append(_alert(ev, RULE_EXEC_TMP, 12, "Execution from /tmp (auditd exec_tmp)"))
            continue

        # 100110: web exploitation
        if src == "nginx" and kind == "http_request":
            path = str(f.get("path", ""))
            if any(p in path for p in WEB_SUSPICIOUS):
                alerts.append(_alert(ev, RULE_WEB_EXPLOIT, 10, "Suspicious web request path"))
                continue

        # 100120: port scan (окно 60с, >=15 DROP), с подавлением и исключением при tuning
        if src == "kern" and kind == "iptables_drop" and ip:
            if tuning and is_legit_external_ip(str(ip)):
                continue  # ловушка nessus_scan (легитимный диапазон)
            q = scan_by_ip[ip]
            q.append(ts)
            while q and ts - q[0] > SCAN_WINDOW:
                q.popleft()
            if len(q) >= SCAN_THRESHOLD:
                last = last_alert_scan.get(ip)
                if last is None or ts - last > SUPPRESS_WINDOW:
                    last_alert_scan[ip] = ts
                    alerts.append(_alert(ev, RULE_PORT_SCAN, 10, "Port scan detected (many DROPs)"))
                continue

        # 100100: ssh brute force (окно 120с, >=5 fail), с подавлением
        if src == "sshd" and kind == "ssh_login_fail" and ip:
            q = ssh_fail_by_ip[ip]
            q.append(ts)
            while q and ts - q[0] > SSH_WINDOW:
                q.popleft()
            if len(q) >= SSH_THRESHOLD:
                bruteforce_ips[ip] = ts
                last = last_alert_bruteforce.get(ip)
                if last is None or ts - last > SUPPRESS_WINDOW:
                    last_alert_bruteforce[ip] = ts
                    alerts.append(_alert(ev, RULE_SSH_BRUTEFORCE, 10, "SSH brute force"))
                continue

        # 100101: compromise
        if src == "sshd" and kind == "ssh_login_ok" and ip:
            last = bruteforce_ips.get(ip)
            if last is not None and ts - last <= COMPROMISE_LOOKBACK:
                alerts.append(_alert(ev, RULE_SSH_COMPROMISE, 12, "SSH compromise after brute force"))
                continue
            if 0 <= ts.hour < 6:
                alerts.append(_alert(ev, RULE_VALID_AFTER_HOURS, 8, "Valid account login after hours"))
                continue

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a, ensure_ascii=False) + "\n")

    by_rule: Dict[int, int] = defaultdict(int)
    for a in alerts:
        by_rule[a["rule"]["id"]] += 1
    return {"total_alerts": len(alerts), "by_rule": dict(by_rule), "tuning": tuning}