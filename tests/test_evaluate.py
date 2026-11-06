import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta

from socsim.detect import detect, _full_log
from socsim.evaluate import evaluate
from socsim.generate import _event_to_dict
from socsim.model import Event, Truth


def _write_events(path, events):
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(_event_to_dict(e), ensure_ascii=False) + "\n")


class TestEvaluate(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="socsim_eval_")
        self.events = os.path.join(self.dir, "events.jsonl")
        self.alerts = os.path.join(self.dir, "alerts.jsonl")
        self.truth = os.path.join(self.dir, "groundtruth.jsonl")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write_truth(self, events):
        with open(self.truth, "w", encoding="utf-8") as f:
            for e in events:
                if e.truth.malicious or e.truth.trap:
                    f.write(json.dumps(_event_to_dict(e), ensure_ascii=False) + "\n")

    def test_bruteforce_detected(self):
        base = datetime(2026, 1, 5, 14, 0, 0)
        evs = [Event(ts=base + timedelta(seconds=i * 10), source="sshd", host="web01",
                     kind="ssh_login_fail",
                     fields={"user": "root", "ip": "192.0.2.10", "port": 50000 + i, "pid": 1},
                     truth=Truth(malicious=True, campaign="c1",
                                 campaign_type="ssh_bruteforce_compromise", step=i + 1,
                                 technique="T1110", expected_rules=[100100]))
               for i in range(6)]
        _write_events(self.events, evs)
        self._write_truth(evs)
        detect(self.events, self.alerts)
        r = evaluate(self.alerts, self.events, self.truth)
        self.assertEqual(r["campaigns_total"], 1)
        self.assertEqual(r["campaigns_detected"], 1)
        self.assertIn("ssh_bruteforce_compromise", r["campaigns"])

    def test_evasive_not_detected(self):
        base = datetime(2026, 1, 5, 9, 0, 0)
        evs = [Event(ts=base + timedelta(minutes=10 * i), source="kern", host="db01",
                     kind="iptables_drop",
                     fields={"src": "192.0.2.20", "dst": "db01", "dport": 20 + i},
                     truth=Truth(malicious=True, campaign="c2",
                                 campaign_type="slow_port_scan", step=i + 1,
                                 technique="T1046", expected_rules=[100120], evasive=True))
               for i in range(20)]
        _write_events(self.events, evs)
        self._write_truth(evs)
        detect(self.events, self.alerts)
        r = evaluate(self.alerts, self.events, self.truth)
        self.assertEqual(r["campaigns_detected"], 0)
        self.assertTrue(r["campaigns"]["slow_port_scan"]["evasive"])

    def test_trap_alert_counted_as_fp(self):
        base = datetime(2026, 1, 5, 12, 0, 0)
        ev = Event(ts=base, source="auditd", host="web01", kind="exec_tmp",
                   fields={"comm": "pytest_runner", "exe": "/tmp/pytest_runner",
                           "pid": 1, "serial": 1, "key": "exec_tmp"},
                   truth=Truth(trap=True))
        _write_events(self.events, [ev])
        self._write_truth([ev])
        detect(self.events, self.alerts)
        r = evaluate(self.alerts, self.events, self.truth)
        self.assertEqual(r["confusion"]["fp_trap"], 1)
        self.assertEqual(r["campaigns_detected"], 0)

    def test_normal_event_alert_counted_as_fp_normal(self):
        # Алерт на событие, которое есть в events, но не в groundtruth -> fp_normal
        base = datetime(2026, 1, 5, 10, 0, 0)
        ev = Event(ts=base, source="nginx", host="web01", kind="http_request",
                   fields={"ip": "198.51.100.7", "method": "GET", "path": "/.env",
                           "status": 404, "size": 0, "ua": "sqlmap"})
        _write_events(self.events, [ev])
        self._write_truth([])
        detect(self.events, self.alerts)
        r = evaluate(self.alerts, self.events, self.truth)
        self.assertEqual(r["alerts_unmatched"], 0)
        self.assertEqual(r["confusion"]["fp_normal"], 1)

    def test_unmatched_alert_reported(self):
        # Алерт, чей full_log не соответствует ни одному событию -> unmatched
        base = datetime(2026, 1, 5, 10, 0, 0)
        ev = Event(ts=base, source="nginx", host="web01", kind="http_request",
                   fields={"ip": "198.51.100.7", "method": "GET", "path": "/.env",
                           "status": 404, "size": 0, "ua": "sqlmap"})
        _write_events(self.events, [ev])
        self._write_truth([])
        detect(self.events, self.alerts)
        # Подменяем events.jsonl: события, которого нет в алертах
        other = Event(ts=base, source="nginx", host="web01", kind="http_request",
                      fields={"ip": "198.18.0.10", "method": "GET", "path": "/",
                              "status": 200, "size": 100, "ua": "curl/8.0"})
        _write_events(self.events, [other])
        r = evaluate(self.alerts, self.events, self.truth)
        self.assertEqual(r["alerts_unmatched"], 1)


if __name__ == "__main__":
    unittest.main()