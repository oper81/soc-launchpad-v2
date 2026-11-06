"""Очередь алертов для L1 + шаблон verdicts.csv.

Читает alerts.jsonl, печатает читаемую очередь и пишет CSV-шаблон, который
аналитик заполняет вердиктами. Формат колонок фиксирован:
  alert_index,timestamp,rule_id,host,verdict,comment
Вердикты: true_positive | false_positive | benign (для ловушек) | пусто.
"""
import csv
import json
import os
from typing import Any, Dict, List


def load_alerts(path: str) -> List[Dict[str, Any]]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def format_queue(alerts: List[Dict[str, Any]]) -> str:
    lines = []
    for i, a in enumerate(alerts):
        rule = a.get("rule", {})
        agent = a.get("agent", {})
        lines.append("[%d] %s  rule=%s (level %s)  host=%s" % (
            i, a.get("timestamp", "?"), rule.get("id", "?"),
            rule.get("level", "?"), agent.get("name", "?")))
        lines.append("    %s" % rule.get("description", ""))
        fl = a.get("full_log", "")
        if fl:
            lines.append("    log: %s" % fl)
    return "\n".join(lines)


def write_verdicts_template(alerts: List[Dict[str, Any]], path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["alert_index", "timestamp", "rule_id", "host", "verdict", "comment"])
        for i, a in enumerate(alerts):
            rule = a.get("rule", {})
            agent = a.get("agent", {})
            w.writerow([i, a.get("timestamp", ""), rule.get("id", ""),
                        agent.get("name", ""), "", ""])


def build_queue(alerts_path: str, verdicts_path: str) -> Dict[str, Any]:
    alerts = load_alerts(alerts_path)
    write_verdicts_template(alerts, verdicts_path)
    return {"alerts": len(alerts), "verdicts_path": os.path.abspath(verdicts_path),
            "queue_text": format_queue(alerts)}