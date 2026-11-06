import unittest
from datetime import datetime

from socsim.common import make_rng
from socsim.traps import TRAP_TYPES, build_trap


class TestTraps(unittest.TestCase):
    def test_all_traps_are_trap_not_malicious(self):
        for kind in TRAP_TYPES:
            ev = build_trap(kind, "web01", datetime(2026, 1, 5, 12, 0), make_rng(1))
            self.assertTrue(ev, kind)
            for e in ev:
                self.assertTrue(e.truth.trap, kind)
                self.assertFalse(e.truth.malicious, kind)

    def test_unknown_trap(self):
        with self.assertRaises(ValueError):
            build_trap("nope", "web01", datetime(2026, 1, 5), make_rng(1))


if __name__ == "__main__":
    unittest.main()