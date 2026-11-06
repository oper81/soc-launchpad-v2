"""Проигрывание events.jsonl с управлением скоростью и фильтрами.

ВНИМАНИЕ: --speed > 1 сжимает окна корреляции. Правила с окнами (100100, 100120)
и evasive-кампании (slow_port_scan) могут вести себя иначе, чем при реальном
времени. Это предупреждение печатается всегда, когда speed != 1.
"""
import json
import sys
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional


def _load(path: str) -> List[Dict[str, Any]]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    out.sort(key=lambda e: e["ts"])
    return out


def replay(events_path: str, speed: float = 1.0, max_gap: float = 5.0,
           only_host: Optional[str] = None, start_at: Optional[str] = None,
           out=sys.stdout) -> int:
    events = _load(events_path)
    if start_at:
        t0 = datetime.fromisoformat(start_at)
        events = [e for e in events if datetime.fromisoformat(e["ts"]) >= t0]
    if only_host:
        events = [e for e in events if e.get("host") == only_host]

    if speed != 1.0:
        print("WARNING: speed=%s сжимает окна корреляции; evasive-кампании "
              "могут перестать быть evasive." % speed, file=out)

    printed = 0
    prev_ts = None
    for e in events:
        ts = datetime.fromisoformat(e["ts"])
        if prev_ts is not None and speed > 0:
            delta = (ts - prev_ts).total_seconds() / speed
            if delta > max_gap:
                delta = max_gap
            if delta > 0:
                time.sleep(delta)
        line = "%s %s %s %s" % (e["ts"], e.get("host", "?"), e.get("source", "?"),
                                e.get("kind", "?"))
        print(line, file=out)
        printed += 1
        prev_ts = ts
    return printed