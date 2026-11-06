"""Модель данных: событие и его "истина" (разметка эталона)."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class Truth:
    """Разметка эталона. Обычное событие: всё по умолчанию."""
    malicious: bool = False
    trap: bool = False
    campaign: Optional[str] = None
    campaign_type: Optional[str] = None
    step: Optional[int] = None
    technique: Optional[str] = None
    expected_rules: List[int] = field(default_factory=list)
    evasive: bool = False


@dataclass
class Event:
    """Одно событие журнала. fields — то, что нужно render.py для строки."""
    ts: datetime
    source: str              # sshd | syslog | kern | nginx | auditd
    host: str
    kind: str                # ssh_login_fail, cron_run, iptables_drop, ...
    fields: Dict[str, object] = field(default_factory=dict)
    truth: Truth = field(default_factory=Truth)

    def is_normal(self) -> bool:
        return not self.truth.malicious and not self.truth.trap