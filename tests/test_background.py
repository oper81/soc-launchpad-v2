import unittest
from datetime import datetime

from socsim.background import cron_background, ssh_background, web_background
from socsim.common import make_rng


START = datetime(2026, 1, 5, 0, 0, 0)
END = datetime(2026, 1, 6, 0, 0, 0)


class TestBackground(unittest.TestCase):
    def test_ssh_all_normal(self):
        ev = ssh_background("web01", START, END, make_rng(1))
        self.assertTrue(ev)
        self.assertTrue(all(e.is_normal() for e in ev))

    def test_ssh_only_working_hours(self):
        ev = ssh_background("web01", START, END, make_rng(1))
        logins = [e for e in ev if e.kind == "ssh_login_ok"]
        self.assertTrue(all(8 <= e.ts.hour < 19 for e in logins))

    def test_web_all_normal(self):
        ev = web_background("web01", START, END, make_rng(2))
        self.assertTrue(ev)
        self.assertTrue(all(e.is_normal() and e.source == "nginx" for e in ev))

    def test_cron_hourly(self):
        ev = cron_background("web01", START, END, make_rng(3))
        self.assertEqual(len(ev), 23)  # с 01:00 до 23:00
        self.assertTrue(all(e.kind == "cron_run" for e in ev))

    def test_deterministic(self):
        a = ssh_background("web01", START, END, make_rng(7))
        b = ssh_background("web01", START, END, make_rng(7))
        self.assertEqual(len(a), len(b))


if __name__ == "__main__":
    unittest.main()