"""Сборка сценария: фон + ловушки + кампании -> labs/.

Пишет:
  labs/logs/<host>/<source>.log   — строки журналов
  labs/events.jsonl               — все события (машинный формат)
  labs/groundtruth.jsonl          — эталон (malicious + traps)
  labs/manifest.json              — метаданные прогона
"""
import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List

from . import __version__
from .background import cron_background, ssh_background, web_background
from .campaigns import build_campaign
from .common import make_rng
from .model import Event
from .render import render
from .scenario import load_scenario
from .traps import build_trap

SOURCE_FILE = {
    "sshd": "auth.log",
    "syslog": "syslog",
    "kern": "kern.log",
    "nginx": "nginx-access.log",
    "auditd": "audit.log",
}


def _event_to_dict(e: Event) -> Dict[str, Any]:
    return {
        "ts": e.ts.isoformat(),
        "source": e.source,
        "host": e.host,
        "kind": e.kind,
        "fields": e.fields,
        "truth": {
            "malicious": e.truth.malicious,
            "trap": e.truth.trap,
            "campaign": e.truth.campaign,
            "campaign_type": e.truth.campaign_type,
            "step": e.truth.step,
            "technique": e.truth.technique,
            "expected_rules": e.truth.expected_rules,
            "evasive": e.truth.evasive,
        },
    }


def _collect(scenario: Dict[str, Any]) -> List[Event]:
    seed = scenario["seed"]
    rng = make_rng(seed)
    start = datetime(2026, 1, 5, 0, 0, 0)  # фиксированная точка отсчёта
    end = start + timedelta(days=scenario["duration_days"])
    hosts = scenario["hosts"]
    bg = scenario.get("background", {})
    events: List[Event] = []

    for host in hosts:
        if bg.get("ssh", True):
            events.extend(ssh_background(host, start, end, rng))
        if bg.get("web", True):
            events.extend(web_background(host, start, end, rng))
        if bg.get("cron", True):
            events.extend(cron_background(host, start, end, rng))

    # ловушки: раскидываем по хостам
    for i, trap_kind in enumerate(scenario.get("traps", [])):
        host = hosts[i % len(hosts)]
        events.extend(build_trap(trap_kind, host, start + timedelta(days=i % scenario["duration_days"]), rng))

    # кампании
    for spec in scenario.get("campaigns", []):
        events.extend(build_campaign(spec, rng, start))

    events.sort(key=lambda e: e.ts)
    return events


def generate(scenario_path: str, out_dir: str) -> Dict[str, Any]:
    scenario = load_scenario(scenario_path)
    events = _collect(scenario)
    os.makedirs(out_dir, exist_ok=True)
    logs_dir = os.path.join(out_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)

    # журналы по хостам
    per_host: Dict[str, Dict[str, list]] = {}
    for e in events:
        per_host.setdefault(e.host, {}).setdefault(e.source, []).append(render(e))
    for host, by_source in per_host.items():
        hdir = os.path.join(logs_dir, host)
        os.makedirs(hdir, exist_ok=True)
        for source, lines in by_source.items():
            fname = SOURCE_FILE.get(source, source + ".log")
            with open(os.path.join(hdir, fname), "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")

    # events.jsonl
    with open(os.path.join(out_dir, "events.jsonl"), "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(_event_to_dict(e), ensure_ascii=False) + "\n")

    # groundtruth.jsonl (только malicious + trap)
    with open(os.path.join(out_dir, "groundtruth.jsonl"), "w", encoding="utf-8") as f:
        for e in events:
            if e.truth.malicious or e.truth.trap:
                f.write(json.dumps(_event_to_dict(e), ensure_ascii=False) + "\n")

    manifest = {
        "generator_version": __version__,
        "scenario_path": os.path.abspath(scenario_path),
        "scenario_name": scenario["name"],
        "seed": scenario["seed"],
        "duration_days": scenario["duration_days"],
        "hosts": scenario["hosts"],
        "total_events": len(events),
        "malicious_events": sum(1 for e in events if e.truth.malicious),
        "trap_events": sum(1 for e in events if e.truth.trap),
        "campaigns": [c.get("type") for c in scenario.get("campaigns", [])],
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return manifest