from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from detection_replay_lab.engine import DetectionEngine
from detection_replay_lab.models import Event, ValidationError
from detection_replay_lab.rules import load_rules, parse_rule


RULE = {
    "id": "drl-test-powershell",
    "title": "Encoded PowerShell",
    "status": "test",
    "level": "high",
    "logsource": {"product": "windows", "category": "process_creation"},
    "tags": ["attack.execution", "attack.t1059.001"],
    "detection": {
        "selection": {
            "process.name|endswith": "powershell.exe",
            "process.command_line|contains": [" -enc ", " -encodedcommand "],
        },
        "filter_admin": {"user.name": "lab-admin"},
        "condition": "selection and not filter_admin",
    },
}


class RuleTests(unittest.TestCase):
    def test_loads_yaml_directory_and_detects_duplicate_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = """
id: drl-test-one
title: Test one
level: medium
detection:
  selection:
    event.action: login
  condition: selection
"""
            (root / "one.yml").write_text(content, encoding="utf-8")
            self.assertEqual(load_rules([root])[0].id, "drl-test-one")
            (root / "two.yml").write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "duplicate"):
                load_rules([root])

    def test_rejects_invalid_condition_during_parse(self) -> None:
        invalid = dict(RULE)
        invalid["detection"] = {"selection": {"field": "x"}, "condition": "missing"}
        with self.assertRaisesRegex(ValidationError, "unknown selection"):
            parse_rule(invalid)


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = parse_rule(RULE)
        self.event = Event(
            "e1",
            datetime(2026, 1, 1, tzinfo=UTC),
            {
                "drl.product": "windows",
                "event.category": "process_creation",
                "process.name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "process.command_line": "powershell.exe -NoP -enc AAAA",
                "user.name": "analyst",
            },
        )

    def test_emits_deterministic_alert_with_attack_tags(self) -> None:
        first = DetectionEngine([self.rule]).evaluate(self.event)[0]
        second = DetectionEngine([self.rule]).evaluate(self.event)[0]
        self.assertEqual(first.id, second.id)
        self.assertEqual(first.level, "high")
        self.assertIn("attack.t1059.001", first.tags)

    def test_filter_and_logsource_prevent_false_alert(self) -> None:
        admin = Event(self.event.id, self.event.timestamp, {**self.event.fields, "user.name": "lab-admin"})
        linux = Event(self.event.id, self.event.timestamp, {**self.event.fields, "drl.product": "linux"})
        self.assertFalse(DetectionEngine([self.rule]).evaluate(admin))
        self.assertFalse(DetectionEngine([self.rule]).evaluate(linux))

    def test_explain_preserves_selection_checks(self) -> None:
        trace = DetectionEngine([self.rule]).explain(self.rule, self.event)
        self.assertTrue(trace.matched)
        self.assertTrue(trace.logsource_matched)
        self.assertIn("process.name|endswith: match", trace.selections[0].checks)


if __name__ == "__main__":
    unittest.main()
