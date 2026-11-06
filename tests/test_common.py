import unittest
from datetime import datetime

from socsim.common import (
    is_attacker_ip,
    is_legit_external_ip,
    make_rng,
    split_window,
)


class TestCommon(unittest.TestCase):
    def test_attacker_ip_in_doc_ranges(self):
        self.assertTrue(is_attacker_ip("192.0.2.5"))
        self.assertTrue(is_attacker_ip("198.51.100.7"))
        self.assertTrue(is_attacker_ip("203.0.113.9"))

    def test_attacker_ip_rejects_others(self):
        self.assertFalse(is_attacker_ip("8.8.8.8"))
        self.assertFalse(is_attacker_ip("not-an-ip"))
        self.assertFalse(is_attacker_ip("198.18.0.1"))  # это легитимный внешний

    def test_legit_external(self):
        self.assertTrue(is_legit_external_ip("198.18.0.1"))
        self.assertTrue(is_legit_external_ip("198.19.255.254"))
        self.assertFalse(is_legit_external_ip("192.0.2.5"))

    def test_make_rng_deterministic(self):
        self.assertEqual(make_rng(42).random(), make_rng(42).random())
        self.assertNotEqual(make_rng(1).random(), make_rng(2).random())

    def test_split_window(self):
        start, step = split_window(datetime(2026, 1, 1), datetime(2026, 1, 11), 10)
        self.assertEqual(start, datetime(2026, 1, 1))
        self.assertEqual(step.total_seconds(), 86400)

    def test_split_window_errors(self):
        with self.assertRaises(ValueError):
            split_window(datetime(2026, 1, 1), datetime(2026, 1, 2), 0)
        with self.assertRaises(ValueError):
            split_window(datetime(2026, 1, 2), datetime(2026, 1, 1), 1)


if __name__ == "__main__":
    unittest.main()