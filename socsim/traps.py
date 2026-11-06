"""Ловушки: легитимное поведение, похожее на атаку. Truth(trap=True), НЕ malicious."""
import random
from datetime import datetime, timedelta
from typing import List

from .model import Event, Truth

TRAP_TYPES = (
    "expired_password_service_account",
    "forgotten_password",
    "nessus_scan",
    "admin_useradd_crontab",
    "dev_tmp_binary",
)


def build_trap(kind: str, host: str, base_ts: datetime, rng: random.Random) -> List[Event]:
    t = base_ts + timedelta(minutes=rng.randint(0, 120))
    trap = Truth(trap=True)
    if kind == "expired_password_service_account":
        return [
            Event(ts=t, source="sshd", host=host, kind="ssh_login_fail",
                  fields={"user": "svc_backup", "ip": "198.18.0.10",
                          "port": rng.randint(40000, 60000), "pid": rng.randint(1000, 65000)},
                  truth=trap),
        ]
    if kind == "forgotten_password":
        return [
            Event(ts=t + timedelta(seconds=i * 20), source="sshd", host=host,
                  kind="ssh_login_fail",
                  fields={"user": "alice", "ip": "198.18.0.11",
                          "port": 51000 + i, "pid": rng.randint(1000, 65000)},
                  truth=trap)
            for i in range(2)
        ]
    if kind == "nessus_scan":
        return [
            Event(ts=t + timedelta(seconds=i), source="kern", host=host, kind="iptables_drop",
                  fields={"src": "198.18.0.20", "dst": host, "dport": 22 + i},
                  truth=trap)
            for i in range(20)
        ]
    if kind == "admin_useradd_crontab":
        return [
            Event(ts=t, source="syslog", host=host, kind="useradd",
                  fields={"name": "deploy_bot", "uid": 1005, "pid": rng.randint(1000, 65000)},
                  truth=trap),
            Event(ts=t + timedelta(minutes=1), source="syslog", host=host, kind="crontab_edit",
                  fields={"user": "deploy_bot", "pid": rng.randint(1000, 65000)},
                  truth=trap),
        ]
    if kind == "dev_tmp_binary":
        return [
            Event(ts=t, source="auditd", host=host, kind="exec_tmp",
                  fields={"comm": "pytest_runner", "exe": "/tmp/pytest_runner",
                          "pid": rng.randint(1000, 65000), "serial": rng.randint(1, 999),
                          "key": "exec_tmp"},
                  truth=trap),
        ]
    raise ValueError("unknown trap: %r" % kind)