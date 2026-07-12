from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from detection_replay_lab.scenarios import load_scenario, run_scenario


class ScenarioTests(unittest.TestCase):
    def test_manifest_runs_acceptance_gates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "events.ndjson").write_text(
                '{"id":"e1","timestamp":"2026-01-01T00:00:00Z","action":"evil","label":"malicious","expected_rules":["evil-action"]}\n'
                '{"id":"e2","timestamp":"2026-01-01T00:00:01Z","action":"safe","label":"benign"}\n',
                encoding="utf-8",
            )
            (root / "rule.yml").write_text(
                "id: evil-action\ntitle: Evil action\nlevel: high\ntags: [attack.t1003]\ndetection:\n  selection:\n    event.action: evil\n  condition: selection\n",
                encoding="utf-8",
            )
            (root / "scenario.yml").write_text(
                "id: complete\ntitle: Complete\nevents: [events.ndjson]\nrules: [rule.yml]\ntechniques: [attack.t1003]\ngates:\n  minimum_f1: 1.0\n  expected_alerts: 1\n",
                encoding="utf-8",
            )
            run = run_scenario(load_scenario(root))
        self.assertTrue(run.passed)
        self.assertEqual(run.evaluation.metrics.precision, 1.0)

    def test_failed_gate_is_explained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "events.ndjson").write_text('{"id":"e1","timestamp":1,"label":"malicious"}\n', encoding="utf-8")
            (root / "rule.yml").write_text("id: no-match\ntitle: No match\ndetection:\n  selection:\n    event.action: absent\n", encoding="utf-8")
            (root / "scenario.yml").write_text("events: [events.ndjson]\nrules: [rule.yml]\ngates:\n  minimum_recall: 1.0\n", encoding="utf-8")
            run = run_scenario(load_scenario(root))
        self.assertFalse(run.passed)
        self.assertIn("recall", run.failures[0])


if __name__ == "__main__":
    unittest.main()
