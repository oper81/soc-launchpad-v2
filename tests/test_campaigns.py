import unittest
from datetime import datetime

from socsim.campaigns import build_campaign
from socsim.common import make_rng


BASE = datetime(2026, 1, 5, 0, 0, 0)


def _spec(ctype, **kw):
    s = {"type": ctype, "target_host": "web01", "attacker_ip": "192.0.2.10"}
    s.update(kw)
    return s


class TestCampaigns(unittest.TestCase):
    def _assert_malicious(self, events, ctype):
        self.assertTrue(events)
        for e in events:
            self.assertTrue(e.truth.malicious)
            self.assertEqual(e.truth.campaign_type, ctype)
            self.assertIsNotNone(e.truth.step)
            self.assertIsNotNone(e.truth.technique)
            self.assertTrue(e.truth.expected_rules)

    def test_ssh_bruteforce(self):
        ev = build_campaign(_spec("ssh_bruteforce_compromise", target_user="root"),
                            make_rng(1), BASE)
        self._assert_malicious(ev, "ssh_bruteforce_compromise")
        self.assertEqual(ev[-1].kind, "ssh_login_ok")

    def test_web_exploitation(self):
        ev = build_campaign(_spec("web_exploitation"), make_rng(1), BASE)
        self._assert_malicious(ev, "web_exploitation")

    def test_port_scan(self):
        ev = build_campaign(_spec("port_scan_recon"), make_rng(1), BASE)
        self._assert_malicious(ev, "port_scan_recon")

    def test_slow_port_scan_evasive(self):
        ev = build_campaign(_spec("slow_port_scan"), make_rng(1), BASE)
        self._assert_malicious(ev, "slow_port_scan")
        self.assertTrue(all(e.truth.evasive for e in ev))

    def test_valid_account_after_hours(self):
        ev = build_campaign(_spec("valid_account_after_hours", target_user="alice"),
                            make_rng(1), BASE)
        self._assert_malicious(ev, "valid_account_after_hours")
        self.assertEqual(ev[0].ts.hour, 2)

    def test_unknown_campaign(self):
        with self.assertRaises(ValueError):
            build_campaign(_spec("nope"), make_rng(1), BASE)


if __name__ == "__main__":
    unittest.main()