import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta

from socsim.detect import detect
from socsim.generate import _event_to_dict
from socsim.model import Event, Truth


def _write_events(path, events):
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(_event_to_dict(e), ensure_ascii=False) + "\n")


class TestTuning(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="socsim_tuning_")
        self.events = os.path.join(self.dir, "events.jsonl")
        self.alerts = os.path.join(self.dir, "alerts.jsonl")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _nessus_scan(self):
        base = datetime(2026, 1, 5, 3, 0, 0)
        return [Event(ts=base + timedelta(seconds=i), source="kern", host="db01",
                      kind="iptables_drop",
                      fields={"src": "198.18.0.20", "dst": "db01", "dport": 22 + i},
                      truth=Truth(trap=True))
                for i in range(30)]

    def _dev_tmp_binary(self):
        return [Event(ts=datetime(2026, 1, 5, 12, 0, 0), source="auditd", host="web01",
                      kind="exec_tmp",
                      fields={"comm": "pytest_runner", "exe": "/tmp/pytest_runner",
                              "pid": 1, "serial": 1, "key": "exec_tmp"},
                      truth=Truth(trap=True))]

    def test_nessus_scan_fp_before_tuning(self):
        _write_events(self.events, self._nessus_scan())
        r = detect(self.events, self.alerts, tuning=False)
        self.assertGreaterEqual(r["by_rule"].get(100120, 0), 1)

    def test_nessus_scan_no_alert_after_tuning(self):
        _write_events(self.events, self._nessus_scan())
        r = detect(self.events, self.alerts, tuning=True)
        self.assertEqual(r["by_rule"].get(100120, 0), 0)

    def test_dev_tmp_fp_before_tuning(self):
        _write_events(self.events, self._dev_tmp_binary())
        r = detect(self.events, self.alerts, tuning=False)
        self.assertEqual(r["by_rule"].get(100130, 0), 1)

    def test_dev_tmp_no_alert_after_tuning(self):
        _write_events(self.events, self._dev_tmp_binary())
        r = detect(self.events, self.alerts, tuning=True)
        self.assertEqual(r["by_rule"].get(100130, 0), 0)

    def test_tuning_does_not_suppress_real_malicious_exec(self):
        ev = Event(ts=datetime(2026, 1, 5, 2, 0, 0), source="auditd", host="web01",
                   kind="exec_tmp",
                   fields={"comm": "payload", "exe": "/tmp/payload",
                           "pid": 1, "serial": 1, "key": "exec_tmp"},
                   truth=Truth(malicious=True))
        _write_events(self.events, [ev])
        r = detect(self.events, self.alerts, tuning=True)
        self.assertEqual(r["by_rule"].get(100130, 0), 1)

    def test_tuning_does_not_suppress_real_attacker_scan(self):
        base = datetime(2026, 1, 5, 3, 0, 0)
        evs = [Event(ts=base + timedelta(milliseconds=100 * i), source="kern", host="db01",
                     kind="iptables_drop",
                     fields={"src": "203.0.113.9", "dst": "db01", "dport": 20 + i},
                     truth=Truth(malicious=True))
               for i in range(30)]
        _write_events(self.events, evs)
        r = detect(self.events, self.alerts, tuning=True)
        self.assertGreaterEqual(r["by_rule"].get(100120, 0), 1)


if __name__ == "__main__":
    unittest.main()