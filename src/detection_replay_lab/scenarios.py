"""Portable scenario manifests joining rules, events, and acceptance gates."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .evaluate import EvaluationReport, evaluate
from .events import load_events
from .models import ReplayResult, Rule, ValidationError
from .replay import ReplayRunner
from .rules import load_rules


@dataclass(frozen=True, slots=True)
class Gates:
    minimum_precision: float = 0.0
    minimum_recall: float = 0.0
    minimum_f1: float = 0.0
    expected_alerts: int | None = None


@dataclass(frozen=True, slots=True)
class Scenario:
    id: str
    title: str
    root: Path
    event_paths: tuple[Path, ...]
    rule_paths: tuple[Path, ...]
    techniques: tuple[str, ...]
    gates: Gates
    description: str = ""


@dataclass(slots=True)
class ScenarioRun:
    scenario: Scenario
    rules: list[Rule]
    replay: ReplayResult
    evaluation: EvaluationReport
    failures: list[str]

    @property
    def passed(self) -> bool:
        return not self.failures and not self.replay.errors


def load_scenario(path: str | Path) -> Scenario:
    manifest = Path(path)
    if manifest.is_dir():
        manifest = manifest / "scenario.yml"
    try:
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValidationError(f"cannot load scenario {manifest}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError("scenario manifest must be an object")
    root = manifest.parent.resolve()
    gate_data = data.get("gates", {})
    if not isinstance(gate_data, dict):
        raise ValidationError("scenario gates must be an object")
    gates = Gates(
        minimum_precision=_probability(gate_data.get("minimum_precision", 0.0), "minimum_precision"),
        minimum_recall=_probability(gate_data.get("minimum_recall", 0.0), "minimum_recall"),
        minimum_f1=_probability(gate_data.get("minimum_f1", 0.0), "minimum_f1"),
        expected_alerts=int(gate_data["expected_alerts"]) if "expected_alerts" in gate_data else None,
    )
    return Scenario(
        id=str(data.get("id") or root.name),
        title=str(data.get("title") or root.name),
        root=root,
        event_paths=tuple(_resolve_paths(root, data.get("events", ["events.ndjson"]))),
        rule_paths=tuple(_resolve_paths(root, data.get("rules", ["rules"]), allow_external=True)),
        techniques=tuple(str(item).casefold() for item in _list(data.get("techniques", []), "techniques")),
        gates=gates,
        description=str(data.get("description", "")),
    )


def run_scenario(scenario: Scenario, *, include_traces: bool = False) -> ScenarioRun:
    rules = load_rules(list(scenario.rule_paths))
    events = load_events(list(scenario.event_paths))
    replay = ReplayRunner(rules, include_traces=include_traces).run(events)
    report = evaluate(events, replay.alerts, rules)
    failures: list[str] = []
    metrics = report.metrics
    if metrics.precision < scenario.gates.minimum_precision:
        failures.append(f"precision {metrics.precision:.3f} below {scenario.gates.minimum_precision:.3f}")
    if metrics.recall < scenario.gates.minimum_recall:
        failures.append(f"recall {metrics.recall:.3f} below {scenario.gates.minimum_recall:.3f}")
    if metrics.f1 < scenario.gates.minimum_f1:
        failures.append(f"f1 {metrics.f1:.3f} below {scenario.gates.minimum_f1:.3f}")
    if scenario.gates.expected_alerts is not None and len(replay.alerts) != scenario.gates.expected_alerts:
        failures.append(f"alerts {len(replay.alerts)} != expected {scenario.gates.expected_alerts}")
    missing_techniques = set(scenario.techniques) - set(report.techniques_loaded)
    if missing_techniques:
        failures.append(f"techniques lack loaded rules: {', '.join(sorted(missing_techniques))}")
    return ScenarioRun(scenario, rules, replay, report, failures)


def _resolve_paths(root: Path, value: Any, *, allow_external: bool = False) -> list[Path]:
    values = _list(value, "scenario paths")
    paths: list[Path] = []
    for item in values:
        candidate = (root / str(item)).resolve()
        if not allow_external and root not in candidate.parents and candidate != root:
            raise ValidationError(f"scenario path escapes root: {item}")
        if not candidate.exists():
            raise ValidationError(f"scenario path does not exist: {candidate}")
        paths.append(candidate)
    return paths


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError(f"{name} must be a list")
    return value


def _probability(value: Any, name: str) -> float:
    parsed = float(value)
    if not 0.0 <= parsed <= 1.0:
        raise ValidationError(f"{name} must be between 0 and 1")
    return parsed

