from __future__ import annotations

import unittest
from datetime import UTC, datetime

from detection_replay_lab.models import Event, ValidationError
from detection_replay_lab.predicates import evaluate_condition, match_selection


def event(**fields: object) -> Event:
    return Event("e1", datetime(2026, 1, 1, tzinfo=UTC), fields)


class PredicateTests(unittest.TestCase):
    def test_string_list_numeric_cidr_and_exists_modifiers(self) -> None:
        subject = event(
            **{
                "process.name": "PowerShell.EXE",
                "process.command_line": "powershell -NoP -enc AAAA",
                "source.ip": "10.2.3.4",
                "risk.score": 85,
            }
        )
        selection = {
            "process.name|endswith": "powershell.exe",
            "process.command_line|contains|all": ["-nop", "-enc"],
            "source.ip|cidr": "10.0.0.0/8",
            "risk.score|gte": 80,
            "user.name|exists": False,
        }
        self.assertTrue(match_selection("selection", selection, subject).matched)

    def test_wildcards_boolean_conditions_and_group_quantifiers(self) -> None:
        matches = {"selection_one": True, "selection_two": False, "filter": False}
        self.assertTrue(evaluate_condition("1 of selection_* and not filter", matches))
        self.assertFalse(evaluate_condition("all of selection_*", matches))
        self.assertTrue(
            evaluate_condition("(selection_one or selection_two) and not filter", matches)
        )

    def test_rejects_unknown_modifier_and_condition_reference(self) -> None:
        with self.assertRaisesRegex(ValidationError, "modifier"):
            match_selection("selection", {"field|magic": "x"}, event(field="x"))
        with self.assertRaisesRegex(ValidationError, "unknown selection"):
            evaluate_condition("missing", {"selection": True})


if __name__ == "__main__":
    unittest.main()
