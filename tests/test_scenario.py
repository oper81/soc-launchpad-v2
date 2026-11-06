import json
import os
import tempfile
import unittest

from socsim.scenario import ScenarioError, load_scenario, validate_scenario


class TestScenario(unittest.TestCase):
    def test_load_demo(self):
        data = load_scenario(os.path.join("scenarios", "demo.json"))
        self.assertEqual(data["name"], "demo")

    def test_missing_field(self):
        with self.assertRaises(ScenarioError):
            validate_scenario({"schema_version": 1})

    def test_bad_schema_version(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump({"schema_version": 99, "name": "x", "duration_days": 1,
                       "seed": 1, "hosts": ["h"], "campaigns": []}, f)
            path = f.name
        try:
            with self.assertRaises(ScenarioError):
                load_scenario(path)
        finally:
            os.unlink(path)

    def test_empty_hosts(self):
        with self.assertRaises(ScenarioError):
            validate_scenario({"schema_version": 1, "name": "x", "duration_days": 1,
                               "seed": 1, "hosts": [], "campaigns": []})


if __name__ == "__main__":
    unittest.main()