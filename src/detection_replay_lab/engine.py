"""Stateless event-to-rule evaluation with explain traces."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Alert, EvaluationTrace, Event, Rule, stable_id
from .predicates import evaluate_condition, match_selection


@dataclass(slots=True)
class DetectionEngine:
    rules: list[Rule]
    include_traces: bool = False

    def evaluate(self, event: Event) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            alert = self.evaluate_rule(rule, event)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def evaluate_rule(self, rule: Rule, event: Event) -> Alert | None:
        logsource_matched = _logsource_matches(rule, event)
        traces = tuple(
            match_selection(name, selection, event) for name, selection in rule.detection.items()
        )
        matches = {trace.name: trace.matched for trace in traces}
        matched = logsource_matched and evaluate_condition(rule.condition, matches)
        trace = EvaluationTrace(rule.id, rule.condition, matched, traces, logsource_matched)
        if not matched or rule.correlation is not None:
            return None
        return Alert(
            id=stable_id(rule.id, event.id),
            rule_id=rule.id,
            rule_title=rule.title,
            level=rule.level,
            timestamp=event.timestamp,
            event_ids=(event.id,),
            tags=rule.tags,
            trace=trace if self.include_traces else None,
        )

    def explain(self, rule: Rule, event: Event) -> EvaluationTrace:
        logsource_matched = _logsource_matches(rule, event)
        traces = tuple(
            match_selection(name, selection, event) for name, selection in rule.detection.items()
        )
        matched = logsource_matched and evaluate_condition(
            rule.condition, {trace.name: trace.matched for trace in traces}
        )
        return EvaluationTrace(rule.id, rule.condition, matched, traces, logsource_matched)


def _logsource_matches(rule: Rule, event: Event) -> bool:
    checks = (
        (rule.logsource.product, event.get("drl.product") or event.get("observer.product")),
        (rule.logsource.category, event.get("event.category")),
        (rule.logsource.service, event.get("service.name") or event.get("event.provider")),
    )
    return all(expected is None or (actual is not None and str(actual).casefold() == expected) for expected, actual in checks)

