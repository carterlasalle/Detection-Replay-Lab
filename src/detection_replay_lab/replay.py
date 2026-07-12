"""Deterministic replay clock and stateful correlation engine."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .engine import DetectionEngine
from .models import Alert, Event, ReplayResult, Rule, stable_id
from .predicates import match_selection


@dataclass(slots=True)
class ReplayRunner:
    rules: list[Rule]
    include_traces: bool = False
    speed: float = 0.0
    max_sleep: float = 5.0
    sleep: Callable[[float], None] = time.sleep
    _thresholds: dict[tuple[str, tuple[tuple[str, str], ...]], deque[Event]] = field(default_factory=dict, init=False)
    _sequences: dict[tuple[str, tuple[tuple[str, str], ...]], list[Event]] = field(default_factory=dict, init=False)

    def run(self, events: list[Event]) -> ReplayResult:
        if self.speed < 0:
            raise ValueError("replay speed cannot be negative")
        result = ReplayResult()
        engine = DetectionEngine(self.rules, include_traces=self.include_traces)
        ordered = sorted(events, key=lambda item: (item.timestamp, item.id))
        started = time.perf_counter()
        previous: datetime | None = None
        for event in ordered:
            if previous is not None and self.speed > 0:
                delay = max(0.0, (event.timestamp - previous).total_seconds() / self.speed)
                if delay:
                    self.sleep(min(delay, self.max_sleep))
            previous = event.timestamp
            result.stats.events_read += 1
            result.stats.events_evaluated += 1
            for rule in self.rules:
                result.stats.rules_evaluated += 1
                if rule.correlation is None:
                    alert = engine.evaluate_rule(rule, event)
                    if alert is not None:
                        result.alerts.append(alert)
                    continue
                if rule.correlation.kind == "threshold":
                    alert = self._threshold(rule, event, engine)
                else:
                    alert = self._sequence(rule, event)
                if alert is not None:
                    result.alerts.append(alert)
        result.alerts.sort(key=lambda item: (item.timestamp, item.rule_id, item.id))
        result.stats.alerts_emitted = len(result.alerts)
        result.stats.duration_seconds = round(time.perf_counter() - started, 6)
        return result

    def _threshold(self, rule: Rule, event: Event, engine: DetectionEngine) -> Alert | None:
        correlation = rule.correlation
        assert correlation is not None
        if not engine.explain(rule, event).matched:
            return None
        group = _group(rule, event)
        key = (rule.id, group)
        window = self._thresholds.setdefault(key, deque())
        cutoff = event.timestamp.timestamp() - correlation.timespan_seconds
        while window and window[0].timestamp.timestamp() < cutoff:
            window.popleft()
        window.append(event)
        if len(window) < correlation.count:
            return None
        matched = tuple(window)
        window.clear()
        return _correlation_alert(rule, matched, group)

    def _sequence(self, rule: Rule, event: Event) -> Alert | None:
        correlation = rule.correlation
        assert correlation is not None
        group = _group(rule, event)
        key = (rule.id, group)
        progress = self._sequences.setdefault(key, [])
        if progress and (event.timestamp - progress[0].timestamp).total_seconds() > correlation.timespan_seconds:
            progress.clear()
        expected_index = len(progress)
        expected_name = correlation.ordered[expected_index]
        if match_selection(expected_name, rule.detection[expected_name], event).matched:
            progress.append(event)
        elif match_selection(correlation.ordered[0], rule.detection[correlation.ordered[0]], event).matched:
            progress[:] = [event]
        if len(progress) != len(correlation.ordered):
            return None
        matched = tuple(progress)
        progress.clear()
        return _correlation_alert(rule, matched, group)


def _group(rule: Rule, event: Event) -> tuple[tuple[str, str], ...]:
    correlation = rule.correlation
    assert correlation is not None
    return tuple((field, str(event.get(field, "<missing>"))) for field in correlation.group_by)


def _correlation_alert(rule: Rule, events: tuple[Event, ...], group: tuple[tuple[str, str], ...]) -> Alert:
    joined = ",".join(event.id for event in events)
    group_text = ",".join(f"{key}={value}" for key, value in group)
    return Alert(
        id=stable_id(rule.id, joined, group_text),
        rule_id=rule.id,
        rule_title=rule.title,
        level=rule.level,
        timestamp=events[-1].timestamp,
        event_ids=tuple(event.id for event in events),
        group=group,
        tags=rule.tags,
    )

