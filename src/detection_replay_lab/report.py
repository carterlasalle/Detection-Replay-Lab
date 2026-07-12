"""Terminal, JSON, JSONL, Markdown, JUnit, and SARIF reports."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Any

from .evaluate import EvaluationReport
from .models import ReplayResult, Rule
from .scenarios import ScenarioRun


def render_replay(
    result: ReplayResult, format_name: str, rules: list[Rule], *, traces: bool = False
) -> str:
    if format_name == "json":
        return json.dumps(result.to_dict(include_traces=traces), indent=2, sort_keys=True)
    if format_name == "jsonl":
        return "\n".join(
            json.dumps(alert.to_dict(include_trace=traces), sort_keys=True)
            for alert in result.alerts
        )
    if format_name == "sarif":
        return json.dumps(replay_sarif(result, rules), indent=2, sort_keys=True)
    return replay_table(result)


def replay_table(result: ReplayResult) -> str:
    if not result.alerts:
        return f"✓ No alerts\nEvaluated {result.stats.events_evaluated} event(s) against {result.stats.rules_evaluated} rule-event pair(s)"
    rows = []
    for alert in result.alerts:
        group = ", ".join(f"{key}={value}" for key, value in alert.group) or "—"
        rows.append(
            [
                alert.timestamp.isoformat().replace("+00:00", "Z"),
                alert.level.upper(),
                alert.rule_id,
                str(len(alert.event_ids)),
                group,
                alert.rule_title,
            ]
        )
    counts = Counter(alert.level for alert in result.alerts)
    summary = ", ".join(f"{count} {level}" for level, count in sorted(counts.items()))
    return (
        _table(["TIME", "LEVEL", "RULE", "EVENTS", "GROUP", "TITLE"], rows)
        + f"\n\nEmitted {len(result.alerts)} alert(s): {summary}"
    )


def render_scenario_runs(runs: list[ScenarioRun], format_name: str) -> str:
    if format_name == "json":
        return json.dumps([_scenario_dict(run) for run in runs], indent=2, sort_keys=True)
    if format_name == "junit":
        return scenario_junit(runs)
    rows = []
    for run in runs:
        metrics = run.evaluation.metrics
        rows.append(
            [
                "PASS" if run.passed else "FAIL",
                run.scenario.id,
                str(run.replay.stats.events_read),
                str(len(run.replay.alerts)),
                f"{metrics.precision:.3f}",
                f"{metrics.recall:.3f}",
                f"{metrics.f1:.3f}",
                "; ".join(run.failures) or "—",
            ]
        )
    return _table(
        ["STATUS", "SCENARIO", "EVENTS", "ALERTS", "PRECISION", "RECALL", "F1", "DETAIL"], rows
    )


def render_coverage(report: EvaluationReport, rules: list[Rule], *, markdown: bool = False) -> str:
    if not markdown:
        return json.dumps(report.to_dict(), indent=2, sort_keys=True)
    lines = [
        "# Detection coverage",
        "",
        "## Quality",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Precision | {report.metrics.precision:.3f} |",
        f"| Recall | {report.metrics.recall:.3f} |",
        f"| F1 | {report.metrics.f1:.3f} |",
        f"| True positive | {report.metrics.true_positive} |",
        f"| False positive | {report.metrics.false_positive} |",
        f"| False negative | {report.metrics.false_negative} |",
        "",
        "## ATT&CK techniques",
        "",
        "| Technique | Loaded rule(s) | Observed |",
        "| --- | ---: | --- |",
    ]
    for technique in report.techniques_loaded:
        count = sum(technique in rule.attack_techniques for rule in rules)
        lines.append(
            f"| `{technique}` | {count} | {'yes' if technique in report.techniques_observed else 'no'} |"
        )
    lines.extend(
        [
            "",
            "## Rule results",
            "",
            "| Rule | Expected | Detected | Unexpected | Missed IDs |",
            "| --- | ---: | ---: | ---: | --- |",
        ]
    )
    for score in report.rule_scores:
        lines.append(
            f"| `{score.rule_id}` | {score.expected_events} | {score.detected_events} | {score.unexpected_events} | {', '.join(score.missed_event_ids) or '—'} |"
        )
    return "\n".join(lines) + "\n"


def replay_sarif(result: ReplayResult, rules: list[Rule]) -> dict[str, Any]:
    used = {alert.rule_id for alert in result.alerts}
    catalog = {rule.id: rule for rule in rules}
    sarif_rules = []
    for rule_id in sorted(used):
        rule = catalog[rule_id]
        sarif_rules.append(
            {
                "id": rule.id,
                "name": "".join(part.capitalize() for part in rule.id.replace("_", "-").split("-")),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description or rule.title},
                "defaultConfiguration": {"level": _sarif_level(rule.level)},
                "properties": {
                    "tags": list(rule.tags),
                    "security-severity": str(_security_score(rule.level)),
                },
            }
        )
    results = []
    for alert in result.alerts:
        results.append(
            {
                "ruleId": alert.rule_id,
                "level": _sarif_level(alert.level),
                "message": {
                    "text": f"{alert.rule_title}; matched event(s): {', '.join(alert.event_ids)}"
                },
                "logicalLocations": [{"name": alert.rule_id, "kind": "detection rule"}],
                "partialFingerprints": {"detectionReplayAlert/v1": alert.id},
                "properties": {
                    "eventIds": list(alert.event_ids),
                    "group": dict(alert.group),
                    "timestamp": alert.timestamp.isoformat().replace("+00:00", "Z"),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Detection Replay Lab",
                        "informationUri": "https://github.com/carterlasalle/Detection-Replay-Lab",
                        "semanticVersion": "0.1.0",
                        "rules": sarif_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def scenario_junit(runs: list[ScenarioRun]) -> str:
    suite = ET.Element(
        "testsuite",
        name="Detection Replay Lab",
        tests=str(len(runs)),
        failures=str(sum(not run.passed for run in runs)),
    )
    for run in runs:
        case = ET.SubElement(
            suite,
            "testcase",
            classname="drl.scenario",
            name=run.scenario.id,
            time=f"{run.replay.stats.duration_seconds:.6f}",
        )
        if not run.passed:
            failure = ET.SubElement(
                case, "failure", message="; ".join(run.failures) or "replay error"
            )
            failure.text = "\n".join([*run.failures, *run.replay.errors])
        output = ET.SubElement(case, "system-out")
        output.text = json.dumps(_scenario_dict(run), sort_keys=True)
    return ET.tostring(suite, encoding="unicode", xml_declaration=True)


def _scenario_dict(run: ScenarioRun) -> dict[str, Any]:
    return {
        "id": run.scenario.id,
        "title": run.scenario.title,
        "passed": run.passed,
        "failures": run.failures,
        "replay": run.replay.to_dict(),
        "evaluation": run.evaluation.to_dict(),
    }


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "No rows."
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = min(72, max(widths[index], len(value)))

    def line(values: list[str]) -> str:
        return "  ".join(
            value[: widths[index]].ljust(widths[index]) for index, value in enumerate(values)
        ).rstrip()

    return "\n".join(
        [line(headers), line(["─" * width for width in widths]), *(line(row) for row in rows)]
    )


def _sarif_level(level: str) -> str:
    return "error" if level in {"critical", "high"} else "warning" if level == "medium" else "note"


def _security_score(level: str) -> float:
    return {"informational": 1.0, "low": 3.0, "medium": 5.5, "high": 8.0, "critical": 9.5}[level]
