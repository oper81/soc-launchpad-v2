import json
import os
import shutil
import tempfile
import unittest

from socsim.generate import generate


SCENARIO = os.path.join("scenarios", "demo.json")


class TestGenerate(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="socsim_test_")

    def tearDown(self):
        shutil.rmtree(self.out, ignore_errors=True)

    def test_files_created(self):
        m = generate(SCENARIO, self.out)
        for name in ("events.jsonl", "groundtruth.jsonl", "manifest.json", "logs"):
            self.assertTrue(os.path.exists(os.path.join(self.out, name)), name)
        self.assertGreater(m["total_events"], 0)

    def test_events_sorted(self):
        generate(SCENARIO, self.out)
        ts = []
        with open(os.path.join(self.out, "events.jsonl"), encoding="utf-8") as f:
            for line in f:
                ts.append(json.loads(line)["ts"])
        self.assertEqual(ts, sorted(ts))

    def test_groundtruth_only_malicious_or_trap(self):
        generate(SCENARIO, self.out)
        with open(os.path.join(self.out, "groundtruth.jsonl"), encoding="utf-8") as f:
            for line in f:
                t = json.loads(line)["truth"]
                self.assertTrue(t["malicious"] or t["trap"])

    def test_deterministic_by_seed(self):
        m1 = generate(SCENARIO, self.out)
        n1 = m1["total_events"]
        out2 = tempfile.mkdtemp(prefix="socsim_test2_")
        try:
            m2 = generate(SCENARIO, out2)
            self.assertEqual(n1, m2["total_events"])
            self.assertEqual(m1["malicious_events"], m2["malicious_events"])
            self.assertEqual(m1["trap_events"], m2["trap_events"])
        finally:
            shutil.rmtree(out2, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()