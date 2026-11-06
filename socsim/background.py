"""Нормальный фон: SSH-сессии по рабочим часам, веб-трафик, cron.

Всё — обычные события (Truth() по умолчанию). Никаких атак.
"""
import random
from datetime import datetime, timedelta
from typing import List

from .model import Event, Truth

LEGIT_CLIENTS = ["198.18.0.10", "198.18.0.11", "198.18.1.20", "198.19.5.7"]
INTERNAL_USERS = ["alice", "bob", "carol", "dave"]
SERVICE_USERS = ["svc_backup", "svc_deploy"]
WEB_PATHS = ["/", "/index.html", "/login", "/api/health", "/static/app.js", "/about"]
USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
               "Mozilla/5.0 (X11; Linux x86_64)",
               "curl/8.0.1"]


def _pid(rng: random.Random) -> int:
    return rng.randint(1000, 65000)


def ssh_background(host: str, start: datetime, end: datetime, rng: random.Random) -> List[Event]:
    events = []
    t = start
    while t < end:
        t += timedelta(minutes=rng.randint(20, 90))
        hour = t.hour
        if not (8 <= hour < 19):   # рабочие часы
            continue
        user = rng.choice(INTERNAL_USERS)
        ip = rng.choice(LEGIT_CLIENTS)
        port = rng.randint(40000, 60000)
        pid = _pid(rng)
        # иногда опечатка в пароле -> один fail, потом ok
        if rng.random() < 0.15:
            events.append(Event(ts=t, source="sshd", host=host, kind="ssh_login_fail",
                                fields={"user": user, "ip": ip, "port": port, "pid": pid}))
            t += timedelta(seconds=rng.randint(3, 15))
        events.append(Event(ts=t, source="sshd", host=host, kind="ssh_login_ok",
                            fields={"user": user, "ip": ip, "port": port, "pid": pid}))
        t += timedelta(minutes=rng.randint(5, 60))
        events.append(Event(ts=t, source="sshd", host=host, kind="ssh_disconnect",
                            fields={"ip": ip, "port": port, "pid": pid}))
    return events


def web_background(host: str, start: datetime, end: datetime, rng: random.Random) -> List[Event]:
    events = []
    t = start
    while t < end:
        # суточная кривая: днём чаще, ночью реже
        hour = t.hour
        weight = 1.0 if 9 <= hour < 20 else 0.2
        t += timedelta(seconds=int(rng.expovariate(1.0 / (60 * weight))))
        events.append(Event(
            ts=t, source="nginx", host=host, kind="http_request",
            fields={"ip": rng.choice(LEGIT_CLIENTS), "method": "GET",
                    "path": rng.choice(WEB_PATHS), "status": 200,
                    "size": rng.randint(100, 5000), "ua": rng.choice(USER_AGENTS)},
        ))
    return events


def cron_background(host: str, start: datetime, end: datetime, rng: random.Random) -> List[Event]:
    events = []
    t = start.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    while t < end:
        events.append(Event(ts=t, source="syslog", host=host, kind="cron_run",
                            fields={"user": "root", "cmd": "run-parts /etc/cron.hourly",
                                    "pid": _pid(rng)}))
        t += timedelta(hours=1)
    return events