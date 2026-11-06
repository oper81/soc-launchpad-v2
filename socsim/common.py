"""Общие утилиты: IP-диапазоны, проверки, время."""
import ipaddress
import random
from datetime import datetime, timedelta
from typing import Tuple

# Атакующие IP — только документационные диапазоны (RFC 5737).
ATTACKER_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
# Легитимные внешние клиенты (RFC 2544, benchmarking).
LEGIT_EXTERNAL_NETS = [ipaddress.ip_network("198.18.0.0/15")]


def is_attacker_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in ATTACKER_NETS)


def is_legit_external_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in LEGIT_EXTERNAL_NETS)


def make_rng(seed: int) -> random.Random:
    return random.Random(seed)


def split_window(start: datetime, end: datetime, parts: int) -> Tuple[datetime, timedelta]:
    """Делит окно [start, end) на parts отрезков. Возвращает (start, длина шага)."""
    if parts <= 0:
        raise ValueError("parts must be > 0")
    if end <= start:
        raise ValueError("end must be > start")
    total = end - start
    return start, total / parts