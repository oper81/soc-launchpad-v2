"""Оценка: alerts + events + groundtruth (+ verdicts.csv) -> отчёт (dict).

Привязка алертов к событиям — по тексту full_log (как в описании проекта).
events.jsonl нужен, чтобы отличать "алерт на normal" (fp_normal) от
"алерт вообще без основания" (unmatched). groundtruth.jsonl даёт разметку
malicious/trap.
"""
import csv
import json
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from .detect import _full_log


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _load_verdicts(path: Optional[str]) -> Optional[Dict[int, str]]:
    if not path or not os.path.exists(path):
        return None
    result = {}
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            idx = (row.get("alert_index") or "").strip()
            if idx.isdigit():
                result[int(idx)] = (row.get("verdict") or "").strip()
    return result


def evaluate(alerts_path: str, events_path: str, truth_path: str,
             verdicts_path: Optional[str] = None) -> Dict[str, Any]:
    alerts = _load_jsonl(alerts_path)
    events = _load_jsonl(events_path)
    truth = _load_jsonl(truth_path)
    verdicts = _load_verdicts(verdicts_path) if verdicts_path else None

    events_by_log: Dict[str, Dict[str, Any]] = {_full_log(e): e for e in events}
    truth_by_log: Dict[str, Dict[str, Any]] = {_full_log(t): t for t in truth}

    matched = unmatched = 0
    alerts_by_rule: Dict[int, int] = defaultdict(int)
    tp = fp_trap = fp_normal = 0
    per_trap: Dict[str, Dict[str, int]] = defaultdict(lambda: {"alerts": 0})
    per_campaign: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"first_malicious_ts": None, "first_alert_ts": None,
                 "steps_total": set(), "steps_covered": set(),
                 "techniques_total": set(), "techniques_covered": set(),
                 "alerts": 0, "evasive": False})

    for t in truth:
        tr = t["truth"]
        if tr["malicious"] and tr["campaign_type"]:
            c = per_campaign[tr["campaign_type"]]
            ts = datetime.fromisoformat(t["ts"])
            if c["first_malicious_ts"] is None or ts < c["first_malicious_ts"]:
                c["first_malicious_ts"] = ts
            if tr["step"] is not None:
                c["steps_total"].add(tr["step"])
            if tr["technique"]:
                c["techniques_total"].add(tr["technique"])
            if tr["evasive"]:
                c["evasive"] = True

    for a in alerts:
        rule_id = a["rule"]["id"]
        alerts_by_rule[rule_id] += 1
        log = a.get("full_log", "")
        if log not in events_by_log:
            unmatched += 1
            continue
        matched += 1
        t = truth_by_log.get(log)
        if t is not None and t["truth"]["malicious"] and t["truth"]["campaign_type"]:
            tr = t["truth"]
            c = per_campaign[tr["campaign_type"]]
            c["alerts"] += 1
            if tr["step"] is not None:
                c["steps_covered"].add(tr["step"])
            if tr["technique"]:
                c["techniques_covered"].add(tr["technique"])
            ts = datetime.fromisoformat(a["timestamp"])
            if c["first_alert_ts"] is None or ts < c["first_alert_ts"]:
                c["first_alert_ts"] = ts
            tp += 1
        elif t is not None and t["truth"]["trap"]:
            fp_trap += 1
            per_trap["rule_%d" % rule_id]["alerts"] += 1
        else:
            fp_normal += 1

    campaigns_out = {}
    detected = 0
    for ctype, c in per_campaign.items():
        is_detected = c["first_alert_ts"] is not None
        if is_detected:
            detected += 1
        ttd = None
        if c["first_malicious_ts"] and c["first_alert_ts"]:
            ttd = (c["first_alert_ts"] - c["first_malicious_ts"]).total_seconds()
        campaigns_out[ctype] = {
            "detected": is_detected,
            "evasive": c["evasive"],
            "alerts": c["alerts"],
            "time_to_detect_sec": ttd,
            "steps_total": len(c["steps_total"]),
            "steps_covered": len(c["steps_covered"]),
            "techniques_total": len(c["techniques_total"]),
            "techniques_covered": len(c["techniques_covered"]),
        }

    denom = tp + fp_trap + fp_normal
    precision = (tp / denom) if denom else None

    report: Dict[str, Any] = {
        "alerts_total": len(alerts),
        "alerts_matched_to_events": matched,
        "alerts_unmatched": unmatched,
        "alerts_by_rule": dict(alerts_by_rule),
        "confusion": {"tp": tp, "fp_trap": fp_trap, "fp_normal": fp_normal},
        "precision": precision,
        "campaigns": campaigns_out,
        "campaigns_detected": detected,
        "campaigns_total": len(per_campaign),
        "traps_alerted": dict(per_trap),
    }
    if verdicts is not None:
        correct = wrong = 0
        for idx, v in verdicts.items():
            if not v or idx < 0 or idx >= len(alerts):
                continue
            log = alerts[idx].get("full_log", "")
            t = truth_by_log.get(log)
            expected = "true_positive" if (t and t["truth"]["malicious"]) else "false_positive"
            if v == expected:
                correct += 1
            else:
                wrong += 1
        report["verdicts"] = {"correct": correct, "wrong": wrong}
    return report