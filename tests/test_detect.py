import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta

from socsim.detect import detect
from socsim.model import Event, Truth
from socsim.generate import _event_to_dict


def _write_events(path, events):
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(_event_to_dict(e), ensure_ascii=False) + "\n")


class TestDetect(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="socsim_detect_")
        self.events = os.path.join(self.dir, "events.jsonl")
        self.alerts = os.path.join(self.dir, "alerts.jsonl")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_ssh_bruteforce_rule(self):
        base = datetime(2026, 1, 5, 14, 0, 0)
        evs = [Event(ts=base + timedelta(seconds=i * 10), source="sshd", host="web01",
                     kind="ssh_login_fail",
                     fields={"user": "root", "ip": "192.0.2.10", "port": 50000 + i, "pid": 1},
                     truth=Truth(malicious=True))
               for i in range(6)]
        _write_events(self.events, evs)
        res = detect(self.events, self.alerts)
        self.assertGreaterEqual(res["by_rule"].get(100100, 0), 1)

    def test_slow_scan_not_detected(self):
        base = datetime(2026, 1, 5, 9, 0, 0)
        evs = [Event(ts=base + timedelta(minutes=10 * i), source="kern", host="db01",
                     kind="iptables_drop",
                     fields={"src": "192.0.2.20", "dst": "db01", "dport": 20 + i},
                     truth=Truth(malicious=True, evasive=True))
               for i in range(20)]
        _write_events(self.events, evs)
        res = detect(self.events, self.alerts)
        self.assertEqual(res["by_rule"].get(100120, 0), 0)

    def test_exec_tmp_rule(self):
        base = datetime(2026, 1, 5, 2, 0, 0)
        ev = Event(ts=base, source="auditd", host="web01", kind="exec_tmp",
                   fields={"comm": "payload", "exe": "/tmp/payload", "pid": 1,
                           "serial": 1, "key": "exec_tmp"},
                   truth=Truth(malicious=True))
        _write_events(self.events, [ev])
        res = detect(self.events, self.alerts)
        self.assertEqual(res["by_rule"].get(100130), 1)

    def test_web_exploit_rule(self):
        base = datetime(2026, 1, 5, 10, 0, 0)
        ev = Event(ts=base, source="nginx", host="web01", kind="http_request",
                   fields={"ip": "198.51.100.7", "method": "GET", "path": "/.env",
                           "status": 404, "size": 0, "ua": "sqlmap"},
                   truth=Truth(malicious=True))
        _write_events(self.events, [ev])
        res = detect(self.events, self.alerts)
        self.assertEqual(res["by_rule"].get(100110), 1)

    def test_valid_after_hours(self):
        base = datetime(2026, 1, 5, 2, 30, 0)
        ev = Event(ts=base, source="sshd", host="web01", kind="ssh_login_ok",
                   fields={"user": "alice", "ip": "198.51.100.30", "port": 40000, "pid": 1},
                   truth=Truth(malicious=True))
        _write_events(self.events, [ev])
        res = detect(self.events, self.alerts)
        self.assertEqual(res["by_rule"].get(100140), 1)

    def test_compromise_after_bruteforce(self):
        base = datetime(2026, 1, 5, 14, 0, 0)
        fails = [Event(ts=base + timedelta(seconds=i * 10), source="sshd", host="web01",
                       kind="ssh_login_fail",
                       fields={"user": "root", "ip": "192.0.2.10", "port": 50000 + i, "pid": 1},
                       truth=Truth(malicious=True)) for i in range(6)]
        ok = Event(ts=base + timedelta(minutes=3), source="sshd", host="web01",
                   kind="ssh_login_ok",
                   fields={"user": "root", "ip": "192.0.2.10", "port": 50000, "pid": 1},
                   truth=Truth(malicious=True))
        _write_events(self.events, fails + [ok])
        res = detect(self.events, self.alerts)
        self.assertGreaterEqual(res["by_rule"].get(100101, 0), 1)

    def test_port_scan_suppressed_to_single_alert(self):
        base = datetime(2026, 1, 5, 3, 0, 0)
        evs = [Event(ts=base + timedelta(milliseconds=100 * i), source="kern", host="db01",
                     kind="iptables_drop",
                     fields={"src": "203.0.113.9", "dst": "db01", "dport": 20 + i},
                     truth=Truth(malicious=True))
               for i in range(100)]
        _write_events(self.events, evs)
        res = detect(self.events, self.alerts)
        self.assertLessEqual(res["by_rule"].get(100120, 0), 2)

    def test_bruteforce_suppressed_to_single_alert(self):
        base = datetime(2026, 1, 5, 14, 0, 0)
        evs = [Event(ts=base + timedelta(seconds=10 * i), source="sshd", host="web01",
                     kind="ssh_login_fail",
                     fields={"user": "root", "ip": "192.0.2.10", "port": 50000 + i, "pid": 1},
                     truth=Truth(malicious=True))
               for i in range(20)]
        _write_events(self.events, evs)
        res = detect(self.events, self.alerts)
        self.assertLessEqual(res["by_rule"].get(100100, 0), 2)


if __name__ == "__main__":
    unittest.main()