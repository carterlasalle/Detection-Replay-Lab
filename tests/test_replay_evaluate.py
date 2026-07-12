from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from detection_replay_lab.evaluate import evaluate
from detection_replay_lab.models import Event
from detection_replay_lab.replay import ReplayRunner
from detection_replay_lab.rules import parse_rule


def make_event(index: int, action: str, *, user: str = "alice", label: str = "malicious") -> Event:
    return Event(
        f"e{index}",
        datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=index * 10),
        {"event.action": action, "user.name": user, "expected_rules": []},
        label=label,
    )


class ReplayTests(unittest.TestCase):
    def test_threshold_groups_and_clears_completed_windows(self) -> None:
        rule = parse_rule(
            {
                "id": "login-failures",
                "title": "Repeated login failures",
                "level": "high",
                "detection": {
                    "selection": {"event.action": "login_failed"},
                    "condition": "selection",
                },
                "correlation": {
                    "type": "threshold",
                    "group_by": ["user.name"],
                    "timespan": "2m",
                    "count": 3,
                },
            }
        )
        events = [make_event(index, "login_failed") for index in range(1, 5)]
        alerts = ReplayRunner([rule]).run(list(reversed(events))).alerts
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_ids, ("e1", "e2", "e3"))
        self.assertEqual(alerts[0].group, (("user.name", "alice"),))

    def test_sequence_requires_order_within_window(self) -> None:
        rule = parse_rule(
            {
                "id": "download-execute",
                "title": "Download then execute",
                "level": "critical",
                "detection": {
                    "download": {"event.action": "file_downloaded"},
                    "execute": {"event.action": "process_started"},
                    "condition": "1 of *",
                },
                "correlation": {
                    "type": "sequence",
                    "group_by": ["user.name"],
                    "timespan": "1m",
                    "ordered": ["download", "execute"],
                },
            }
        )
        events = [make_event(1, "file_downloaded"), make_event(2, "process_started")]
        alert = ReplayRunner([rule]).run(events).alerts[0]
        self.assertEqual(alert.event_ids, ("e1", "e2"))
        reversed_actions = [make_event(1, "process_started"), make_event(2, "file_downloaded")]
        self.assertFalse(ReplayRunner([rule]).run(reversed_actions).alerts)

    def test_replay_speed_uses_scaled_bounded_delays(self) -> None:
        delays: list[float] = []
        events = [make_event(1, "safe"), make_event(2, "safe")]
        ReplayRunner([], speed=2.0, max_sleep=3.0, sleep=delays.append).run(events)
        self.assertEqual(delays, [3.0])


class EvaluationTests(unittest.TestCase):
    def test_computes_confusion_matrix_and_attack_coverage(self) -> None:
        rule = parse_rule(
            {
                "id": "malicious-action",
                "title": "Malicious action",
                "level": "high",
                "tags": ["attack.t1003"],
                "detection": {"selection": {"event.action": "evil"}, "condition": "selection"},
            }
        )
        malicious = make_event(1, "evil")
        malicious.fields["expected_rules"] = [rule.id]
        benign = make_event(2, "safe", label="benign")
        result = ReplayRunner([rule]).run([malicious, benign])
        report = evaluate([malicious, benign], result.alerts, [rule])
        self.assertEqual((report.metrics.true_positive, report.metrics.true_negative), (1, 1))
        self.assertEqual(report.metrics.f1, 1.0)
        self.assertEqual(report.techniques_observed, ("attack.t1003",))
        self.assertEqual(report.rule_scores[0].detected_events, 1)


if __name__ == "__main__":
    unittest.main()
