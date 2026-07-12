"""Detection Replay Lab command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import __version__
from .engine import DetectionEngine
from .evaluate import evaluate
from .events import event_from_stdin, load_event, load_events
from .models import LEVEL_ORDER, EvaluationTrace, Rule, ValidationError
from .replay import ReplayRunner
from .report import render_coverage, render_replay, render_scenario_runs
from .rules import load_rules
from .scenarios import load_scenario, run_scenario


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="drl", description="Replay telemetry and prove detection behavior"
    )
    parser.add_argument(
        "--version", action="version", version=f"Detection Replay Lab {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    replay = commands.add_parser("replay", help="replay events against rules")
    replay.add_argument("--events", nargs="+", required=False)
    replay.add_argument("--rules", nargs="+", required=True)
    replay.add_argument("--stdin", action="store_true")
    replay.add_argument("--stdin-filename", default="stdin.ndjson")
    replay.add_argument("--speed", type=_nonnegative_float, default=0.0)
    replay.add_argument("--max-sleep", type=_nonnegative_float, default=5.0)
    replay.add_argument("--trace", action="store_true")
    replay.add_argument("--minimum-level", choices=tuple(LEVEL_ORDER), default="informational")
    replay.add_argument("--format", choices=("table", "json", "jsonl", "sarif"), default="table")
    replay.add_argument("--output")
    replay.add_argument("--fail-on-alert", action="store_true")

    test = commands.add_parser("test", help="run scenario acceptance gates")
    test.add_argument("scenarios", nargs="+", help="scenario directories or manifests")
    test.add_argument("--format", choices=("table", "json", "junit"), default="table")
    test.add_argument("--output")
    test.add_argument("--trace", action="store_true")

    validate = commands.add_parser("validate", help="validate rules and scenario manifests")
    validate.add_argument("--rules", nargs="*", default=[])
    validate.add_argument("--scenarios", nargs="*", default=[])

    coverage = commands.add_parser("coverage", help="evaluate labeled events and ATT&CK coverage")
    coverage.add_argument("--events", nargs="+", required=True)
    coverage.add_argument("--rules", nargs="+", required=True)
    coverage.add_argument("--format", choices=("json", "markdown"), default="markdown")
    coverage.add_argument("--output")

    explain = commands.add_parser("explain", help="show why one rule matches or misses one event")
    explain.add_argument("--event", required=True)
    explain.add_argument("--rules", nargs="+", required=True)
    explain.add_argument("--rule-id", required=True)

    rules = commands.add_parser("rules", help="list rule metadata")
    rules.add_argument("paths", nargs="+")
    rules.add_argument("--format", choices=("table", "json"), default="table")

    init = commands.add_parser("init", help="write a minimal scenario starter kit")
    init.add_argument("path", nargs="?", default="drl-scenario")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "replay":
            return _replay(args)
        if args.command == "test":
            return _test(args)
        if args.command == "validate":
            return _validate(args)
        if args.command == "coverage":
            return _coverage(args)
        if args.command == "explain":
            return _explain(args)
        if args.command == "rules":
            return _rules(args)
        return _init(Path(args.path))
    except (OSError, ValidationError, ValueError) as exc:
        print(f"drl: error: {exc}", file=sys.stderr)
        return 2


def _replay(args: argparse.Namespace) -> int:
    if args.stdin:
        if args.events:
            raise ValidationError("--stdin and --events cannot be combined")
        events = event_from_stdin(sys.stdin.read(), filename=args.stdin_filename)
    else:
        if not args.events:
            raise ValidationError("--events is required unless --stdin is used")
        events = load_events(args.events)
    rules = [
        rule
        for rule in load_rules(args.rules)
        if LEVEL_ORDER[rule.level] >= LEVEL_ORDER[args.minimum_level]
    ]
    result = ReplayRunner(
        rules, include_traces=args.trace, speed=args.speed, max_sleep=args.max_sleep
    ).run(events)
    output = render_replay(result, args.format, rules, traces=args.trace)
    _write(output, args.output)
    if result.errors:
        return 2
    return 1 if args.fail_on_alert and result.alerts else 0


def _test(args: argparse.Namespace) -> int:
    runs = [run_scenario(load_scenario(path), include_traces=args.trace) for path in args.scenarios]
    _write(render_scenario_runs(runs, args.format), args.output)
    return 1 if any(not run.passed for run in runs) else 0


def _validate(args: argparse.Namespace) -> int:
    rule_count = len(load_rules(args.rules)) if args.rules else 0
    scenarios = [load_scenario(path) for path in args.scenarios]
    for scenario in scenarios:
        load_rules(list(scenario.rule_paths))
        load_events(list(scenario.event_paths))
    print(f"✓ Validated {rule_count} direct rule(s) and {len(scenarios)} scenario(s)")
    return 0


def _coverage(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    events = load_events(args.events)
    replay = ReplayRunner(rules).run(events)
    report = evaluate(events, replay.alerts, rules)
    _write(render_coverage(report, rules, markdown=args.format == "markdown"), args.output)
    return 0


def _explain(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    rule = next((item for item in rules if item.id == args.rule_id), None)
    if rule is None:
        raise ValidationError(f"unknown rule id {args.rule_id!r}")
    event = load_event(args.event)
    trace = DetectionEngine(rules).explain(rule, event)
    print(json.dumps({"event_id": event.id, "trace": _trace_dict(trace)}, indent=2, sort_keys=True))
    return 0 if trace.matched else 1


def _rules(args: argparse.Namespace) -> int:
    rules = load_rules(args.paths)
    if args.format == "json":
        print(json.dumps([_rule_dict(rule) for rule in rules], indent=2, sort_keys=True))
    else:
        for rule in rules:
            print(f"{rule.level.upper():13} {rule.id:36} {rule.title}")
    return 0


def _init(root: Path) -> int:
    if root.exists():
        raise FileExistsError(f"{root} already exists")
    root.mkdir(parents=True)
    (root / "scenario.yml").write_text(_STARTER_SCENARIO, encoding="utf-8")
    (root / "events.ndjson").write_text(_STARTER_EVENTS, encoding="utf-8")
    (root / "rule.yml").write_text(_STARTER_RULE, encoding="utf-8")
    print(f"Created {root} (run: drl test {root})")
    return 0


def _write(content: str, path: str | None) -> None:
    if path:
        Path(path).write_text(content + ("" if content.endswith("\n") else "\n"), encoding="utf-8")
    else:
        print(content)


def _trace_dict(trace: EvaluationTrace) -> dict[str, Any]:
    return asdict(trace)


def _rule_dict(rule: Rule) -> dict[str, Any]:
    data = asdict(rule)
    data.pop("detection", None)
    return data


def _nonnegative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


_STARTER_SCENARIO = """id: starter
title: Starter scenario
description: One malicious and one benign process event
events: [events.ndjson]
rules: [rule.yml]
techniques: [attack.t1059.001]
gates:
  minimum_precision: 1.0
  minimum_recall: 1.0
  minimum_f1: 1.0
  expected_alerts: 1
"""

_STARTER_EVENTS = """{"id":"malicious-1","timestamp":"2026-01-01T00:00:00Z","drl.product":"windows","category":"process_creation","process_name":"powershell.exe","command_line":"powershell.exe -enc SYNTHETIC","label":"malicious","expected_rules":["starter-encoded-powershell"]}
{"id":"benign-1","timestamp":"2026-01-01T00:00:01Z","drl.product":"windows","category":"process_creation","process_name":"powershell.exe","command_line":"powershell.exe -File inventory.ps1","label":"benign"}
"""

_STARTER_RULE = """id: starter-encoded-powershell
title: Encoded PowerShell
status: test
level: high
logsource:
  product: windows
  category: process_creation
tags: [attack.execution, attack.t1059.001]
detection:
  selection:
    process.name|endswith: powershell.exe
    process.command_line|contains: " -enc "
  condition: selection
"""


if __name__ == "__main__":
    raise SystemExit(main())
