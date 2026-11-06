"""Кампании с шагами и техниками ATT&CK.

Каждая функция принимает spec (из JSON сценария) и возвращает список Event.
Шаги/техники захардкожены: пользователь задаёт параметры, не структуру.
"""
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List

from .model import Event, Truth

# Правила (совпадают с detect.py шага 6)
RULE_SSH_BRUTEFORCE = 100100
RULE_SSH_COMPROMISE = 100101
RULE_WEB_EXPLOIT = 100110
RULE_PORT_SCAN = 100120
RULE_EXEC_TMP = 100130
RULE_VALID_AFTER_HOURS = 100140

CAMPAIGN_BUILDERS = {}  # type: Dict[str, Any]


def _register(name):
    def deco(fn):
        CAMPAIGN_BUILDERS[name] = fn
        return fn
    return deco


def build_campaign(spec: Dict[str, Any], rng: random.Random, base_ts: datetime) -> List[Event]:
    ctype = spec.get("type")
    if ctype not in CAMPAIGN_BUILDERS:
        raise ValueError("unknown campaign type: %r" % ctype)
    start = base_ts + timedelta(days=spec.get("start_day", 0), hours=spec.get("start_hour", 0))
    return CAMPAIGN_BUILDERS[ctype](spec, rng, start)


@_register("ssh_bruteforce_compromise")
def _ssh_bruteforce(spec, rng, start):
    host = spec["target_host"]
    user = spec.get("target_user", "root")
    ip = spec["attacker_ip"]
    campaign = "ssh_bruteforce_compromise"
    events = []
    t = start
    for step in range(1, 21):  # 20 попыток
        events.append(Event(
            ts=t, source="sshd", host=host, kind="ssh_login_fail",
            fields={"user": user, "ip": ip, "port": rng.randint(40000, 60000),
                    "pid": rng.randint(1000, 65000)},
            truth=Truth(malicious=True, campaign=campaign,
                        campaign_type=campaign, step=step, technique="T1110",
                        expected_rules=[RULE_SSH_BRUTEFORCE]),
        ))
        t += timedelta(seconds=rng.randint(5, 15))
    # успех (компромисс)
    events.append(Event(
        ts=t, source="sshd", host=host, kind="ssh_login_ok",
        fields={"user": user, "ip": ip, "port": rng.randint(40000, 60000),
                "pid": rng.randint(1000, 65000)},
        truth=Truth(malicious=True, campaign=campaign, campaign_type=campaign,
                    step=21, technique="T1078", expected_rules=[RULE_SSH_COMPROMISE]),
    ))
    return events


@_register("web_exploitation")
def _web_exploitation(spec, rng, start):
    host = spec["target_host"]
    ip = spec["attacker_ip"]
    campaign = "web_exploitation"
    paths = ["/admin", "/wp-login.php", "/.env", "/../../etc/passwd", "/shell.php"]
    events = []
    t = start
    for step, path in enumerate(paths, start=1):
        events.append(Event(
            ts=t, source="nginx", host=host, kind="http_request",
            fields={"ip": ip, "method": "GET", "path": path, "status": 404,
                    "size": rng.randint(0, 500), "ua": "sqlmap/1.7"},
            truth=Truth(malicious=True, campaign=campaign, campaign_type=campaign,
                        step=step, technique="T1190", expected_rules=[RULE_WEB_EXPLOIT]),
        ))
        t += timedelta(seconds=rng.randint(10, 30))
    return events


@_register("port_scan_recon")
def _port_scan(spec, rng, start):
    host = spec["target_host"]
    ip = spec["attacker_ip"]
    campaign = "port_scan_recon"
    events = []
    t = start
    for step, port in enumerate(range(20, 120), start=1):
        events.append(Event(
            ts=t, source="kern", host=host, kind="iptables_drop",
            fields={"src": ip, "dst": host, "dport": port},
            truth=Truth(malicious=True, campaign=campaign, campaign_type=campaign,
                        step=step, technique="T1046", expected_rules=[RULE_PORT_SCAN]),
        ))
        t += timedelta(milliseconds=rng.randint(50, 200))
    return events


@_register("slow_port_scan")
def _slow_port_scan(spec, rng, start):
    host = spec["target_host"]
    ip = spec["attacker_ip"]
    campaign = "slow_port_scan"
    events = []
    t = start
    for step, port in enumerate(range(20, 40), start=1):
        events.append(Event(
            ts=t, source="kern", host=host, kind="iptables_drop",
            fields={"src": ip, "dst": host, "dport": port},
            truth=Truth(malicious=True, campaign=campaign, campaign_type=campaign,
                        step=step, technique="T1046", expected_rules=[RULE_PORT_SCAN],
                        evasive=True),
        ))
        t += timedelta(minutes=rng.randint(8, 12))  # медленно, ниже окна правила
    return events


@_register("valid_account_after_hours")
def _valid_after_hours(spec, rng, start):
    host = spec["target_host"]
    ip = spec["attacker_ip"]
    user = spec.get("target_user", "alice")
    campaign = "valid_account_after_hours"
    t = start.replace(hour=2, minute=rng.randint(0, 30))
    events = [
        Event(ts=t, source="sshd", host=host, kind="ssh_login_ok",
              fields={"user": user, "ip": ip, "port": rng.randint(40000, 60000),
                      "pid": rng.randint(1000, 65000)},
              truth=Truth(malicious=True, campaign=campaign, campaign_type=campaign,
                          step=1, technique="T1078",
                          expected_rules=[RULE_VALID_AFTER_HOURS])),
        Event(ts=t + timedelta(minutes=2), source="auditd", host=host, kind="exec_tmp",
              fields={"comm": "payload", "exe": "/tmp/payload",
                      "pid": rng.randint(1000, 65000), "serial": rng.randint(1, 999),
                      "key": "exec_tmp"},
              truth=Truth(malicious=True, campaign=campaign, campaign_type=campaign,
                          step=2, technique="T1059", expected_rules=[RULE_EXEC_TMP])),
    ]
    return events