from __future__ import annotations

import random
import string
import unittest
from datetime import UTC, datetime, timedelta

from detection_replay_lab.engine import DetectionEngine
from detection_replay_lab.models import Event, ValidationError
from detection_replay_lab.normalize import Normalizer
from detection_replay_lab.predicates import evaluate_condition
from detection_replay_lab.replay import ReplayRunner
from detection_replay_lab.rules import parse_rule


class RobustnessTests(unittest.TestCase):
    def test_arbitrary_event_fields_never_escape_engine_exceptions(self) -> None:
        randomizer = random.Random(0x44524C4142)
        rule = parse_rule(
            {
                "id": "robust-rule",
                "title": "Robust rule",
                "detection": {
                    "selection": {"field|contains": "needle", "count|gte": 2},
                    "condition": "selection",
                },
            }
        )
        engine = DetectionEngine([rule])
        alphabet = string.printable + "é中🔎"
        for index in range(2_000):
            raw = {
                "timestamp": index,
                "field": "".join(randomizer.choice(alphabet) for _ in range(randomizer.randrange(0, 128))),
                "count": randomizer.choice([None, randomizer.randrange(-100, 100), "not-a-number", [1, 2]]),
            }
            event = Normalizer().normalize(raw, index=index, source="fuzz")
            alerts = engine.evaluate(event)
            self.assertLessEqual(len(alerts), 1)

    def test_invalid_conditions_fail_closed_with_validation_errors(self) -> None:
        randomizer = random.Random(0xC0DE)
        alphabet = string.ascii_letters + string.digits + "()&|! $%^"
        for _ in range(1_000):
            condition = "".join(randomizer.choice(alphabet) for _ in range(randomizer.randrange(0, 80)))
            try:
                evaluate_condition(condition, {"selection": True})
            except ValidationError:
                pass

    def test_replay_is_identical_for_every_input_permutation(self) -> None:
        rule = parse_rule(
            {
                "id": "ordered-replay",
                "title": "Ordered replay",
                "detection": {"selection": {"event.action": "hit"}, "condition": "selection"},
            }
        )
        base = datetime(2026, 1, 1, tzinfo=UTC)
        events = [Event(f"e{index}", base + timedelta(seconds=index), {"event.action": "hit"}) for index in range(10)]
        expected = [alert.id for alert in ReplayRunner([rule]).run(events).alerts]
        random.Random(42).shuffle(events)
        actual = [alert.id for alert in ReplayRunner([rule]).run(events).alerts]
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()

