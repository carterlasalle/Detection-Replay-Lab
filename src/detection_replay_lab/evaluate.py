"""Ground-truth metrics and ATT&CK coverage calculation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .models import Alert, Event, Rule


@dataclass(frozen=True, slots=True)
class Metrics:
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float
    recall: float
    f1: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RuleScore:
    rule_id: str
    expected_events: int
    detected_events: int
    unexpected_events: int
    missed_event_ids: tuple[str, ...]


@dataclass(slots=True)
class EvaluationReport:
    metrics: Metrics
    rule_scores: list[RuleScore] = field(default_factory=list)
    techniques_loaded: tuple[str, ...] = ()
    techniques_observed: tuple[str, ...] = ()
    unlabeled_events: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "metrics": self.metrics.to_dict(),
            "rule_scores": [asdict(score) for score in self.rule_scores],
            "techniques_loaded": list(self.techniques_loaded),
            "techniques_observed": list(self.techniques_observed),
            "unlabeled_events": self.unlabeled_events,
        }


def evaluate(events: list[Event], alerts: list[Alert], rules: list[Rule]) -> EvaluationReport:
    alert_events = {event_id for alert in alerts for event_id in alert.event_ids}
    labeled = [event for event in events if event.label in {"malicious", "benign"}]
    true_positive = sum(event.label == "malicious" and event.id in alert_events for event in labeled)
    false_negative = sum(event.label == "malicious" and event.id not in alert_events for event in labeled)
    false_positive = sum(event.label == "benign" and event.id in alert_events for event in labeled)
    true_negative = sum(event.label == "benign" and event.id not in alert_events for event in labeled)
    precision = _ratio(true_positive, true_positive + false_positive)
    recall = _ratio(true_positive, true_positive + false_negative)
    f1 = _ratio(2 * precision * recall, precision + recall)
    metrics = Metrics(true_positive, false_positive, false_negative, true_negative, precision, recall, f1)

    alerts_by_rule: dict[str, set[str]] = {}
    for alert in alerts:
        alerts_by_rule.setdefault(alert.rule_id, set()).update(alert.event_ids)
    scores: list[RuleScore] = []
    for rule in rules:
        expected = {
            event.id
            for event in events
            if rule.id in _expected_rules(event)
        }
        observed = alerts_by_rule.get(rule.id, set())
        scores.append(
            RuleScore(
                rule_id=rule.id,
                expected_events=len(expected),
                detected_events=len(expected & observed),
                unexpected_events=len(observed - expected) if expected else 0,
                missed_event_ids=tuple(sorted(expected - observed)),
            )
        )
    loaded = tuple(sorted({technique for rule in rules for technique in rule.attack_techniques}))
    observed_rule_ids = {alert.rule_id for alert in alerts}
    observed = tuple(sorted({technique for rule in rules if rule.id in observed_rule_ids for technique in rule.attack_techniques}))
    return EvaluationReport(metrics, scores, loaded, observed, len(events) - len(labeled))


def _expected_rules(event: Event) -> set[str]:
    value = event.get("drl.expected_rules", event.get("expected_rules", []))
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()


def _ratio(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0

