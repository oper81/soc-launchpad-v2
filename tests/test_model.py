import unittest
from datetime import datetime

from socsim.model import Event, Truth


class TestModel(unittest.TestCase):
    def test_default_event_is_normal(self):
        e = Event(ts=datetime(2026, 1, 1), source="sshd", host="web01", kind="ssh_login_fail")
        self.assertTrue(e.is_normal())
        self.assertFalse(e.truth.malicious)

    def test_malicious_not_normal(self):
        e = Event(ts=datetime(2026, 1, 1), source="sshd", host="web01",
                  kind="ssh_login_fail", truth=Truth(malicious=True, campaign="c1"))
        self.assertFalse(e.is_normal())
        self.assertEqual(e.truth.campaign, "c1")

    def test_trap_not_normal(self):
        e = Event(ts=datetime(2026, 1, 1), source="syslog", host="web01",
                  kind="useradd", truth=Truth(trap=True))
        self.assertFalse(e.is_normal())

    def test_truth_mutable_defaults_are_isolated(self):
        a = Truth()
        b = Truth()
        a.expected_rules.append(100100)
        self.assertEqual(b.expected_rules, [])


if __name__ == "__main__":
    unittest.main()