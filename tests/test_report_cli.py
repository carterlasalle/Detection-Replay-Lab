from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from detection_replay_lab.cli import main
from detection_replay_lab.evaluate import evaluate
from detection_replay_lab.events import load_events
from detection_replay_lab.replay import ReplayRunner
from detection_replay_lab.report import render_coverage, render_replay, render_scenario_runs
from detection_replay_lab.rules import load_rules
from detection_replay_lab.scenarios import load_scenario, run_scenario


def kit(root: Path) -> None:
    with contextlib.redirect_stdout(io.StringIO()):
        code = main(["init", str(root)])
    if code != 0:
        raise AssertionError("starter kit failed")


class ReportTests(unittest.TestCase):
    def test_replay_formats_are_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "scenario"
            kit(root)
            rules = load_rules([root / "rule.yml"])
            events = load_events([root / "events.ndjson"])
            result = ReplayRunner(rules).run(events)
            self.assertEqual(json.loads(render_replay(result, "json", rules))["schema_version"], 1)
            self.assertEqual(len(render_replay(result, "jsonl", rules).splitlines()), 1)
            sarif = json.loads(render_replay(result, "sarif", rules))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertIn("Encoded PowerShell", render_replay(result, "table", rules))

    def test_scenario_junit_and_markdown_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "scenario"
            kit(root)
            run = run_scenario(load_scenario(root))
            junit = render_scenario_runs([run], "junit")
            self.assertIn("testsuite", junit)
            self.assertIn("starter", junit)
            events = load_events([root / "events.ndjson"])
            report = evaluate(events, run.replay.alerts, run.rules)
            markdown = render_coverage(report, run.rules, markdown=True)
            self.assertIn("attack.t1059.001", markdown)
            self.assertIn("| F1 | 1.000 |", markdown)


class CliTests(unittest.TestCase):
    def test_starter_kit_validates_tests_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "scenario"
            kit(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["validate", "--scenarios", str(root)]), 0)
                self.assertEqual(main(["test", str(root)]), 0)
                self.assertEqual(main(["replay", "--events", str(root / "events.ndjson"), "--rules", str(root / "rule.yml")]), 0)
            self.assertIn("PASS", output.getvalue())
            self.assertIn("Encoded PowerShell", output.getvalue())

    def test_fail_on_alert_and_explain_miss_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "scenario"
            kit(root)
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["replay", "--events", str(root / "events.ndjson"), "--rules", str(root / "rule.yml"), "--fail-on-alert"])
                explain = main(["explain", "--event", str(root / "events.ndjson"), "--rules", str(root / "rule.yml"), "--rule-id", "starter-encoded-powershell"])
            self.assertEqual(code, 1)
            self.assertEqual(explain, 2)  # explain requires exactly one event


if __name__ == "__main__":
    unittest.main()
