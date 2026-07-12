from __future__ import annotations

import unittest
from pathlib import Path

from detection_replay_lab.scenarios import load_scenario, run_scenario

ROOT = Path(__file__).parents[1]


class BuiltinScenarioTests(unittest.TestCase):
    def test_all_bundled_scenarios_pass_perfect_quality_gates(self) -> None:
        manifests = sorted((ROOT / "scenarios").glob("*/scenario.yml"))
        self.assertGreaterEqual(len(manifests), 2)
        for manifest in manifests:
            with self.subTest(scenario=manifest.parent.name):
                run = run_scenario(load_scenario(manifest))
                self.assertTrue(run.passed, run.failures)
                self.assertEqual(run.evaluation.metrics.precision, 1.0)
                self.assertEqual(run.evaluation.metrics.recall, 1.0)
                self.assertEqual(run.evaluation.metrics.f1, 1.0)


if __name__ == "__main__":
    unittest.main()
