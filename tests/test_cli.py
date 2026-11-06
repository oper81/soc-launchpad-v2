import csv
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from socsim.cli import main


class TestCli(unittest.TestCase):
    def test_version(self):
        buf = StringIO()
        with redirect_stdout(buf):
            rc = main(["version"])
        self.assertEqual(rc, 0)
        self.assertIn("socsim", buf.getvalue())

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(StringIO()):
                main(["--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_demo_runs(self):
        buf = StringIO()
        with redirect_stdout(buf):
            rc = main(["demo"])
        self.assertEqual(rc, 0)
        text = buf.getvalue()
        self.assertIn("generate:", text)
        self.assertIn("detect:", text)
        self.assertIn("evaluate:", text)
        self.assertTrue(os.path.exists(os.path.join("labs", "demo", "events.jsonl")))

    def test_queue_writes_template(self):
        # Сначала демо, чтобы был alerts.jsonl
        with redirect_stdout(StringIO()):
            main(["demo"])
        alerts = os.path.join("labs", "demo", "alerts.jsonl")
        vdir = tempfile.mkdtemp(prefix="socsim_cli_")
        try:
            vpath = os.path.join(vdir, "verdicts.csv")
            with redirect_stdout(StringIO()):
                rc = main(["queue", "--alerts", alerts, "--verdicts", vpath])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(vpath))
            with open(vpath, encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                self.assertEqual(reader.fieldnames,
                                 ["alert_index", "timestamp", "rule_id", "host", "verdict", "comment"])
                rows = list(reader)
                self.assertTrue(rows)
                self.assertEqual(rows[0]["verdict"], "")
        finally:
            shutil.rmtree(vdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()