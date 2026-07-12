"""Dependency-free replay benchmark: `python benchmarks/benchmark_replay.py`."""

from __future__ import annotations

import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from detection_replay_lab.models import Event
from detection_replay_lab.replay import ReplayRunner
from detection_replay_lab.rules import load_rules


def main() -> None:
    root = Path(__file__).parents[1]
    rules = load_rules([root / "rules"])
    base = datetime(2026, 1, 1, tzinfo=UTC)
    events = [
        Event(
            f"event-{index}",
            base + timedelta(milliseconds=index),
            {
                "drl.product": "windows",
                "event.category": "process_creation",
                "event.action": "process_started",
                "process.name": "notepad.exe",
                "process.command_line": "notepad.exe notes.txt",
                "user.name": f"user-{index % 100}",
                "source.ip": f"10.0.{(index // 250) % 255}.{index % 250 + 1}",
            },
        )
        for index in range(25_000)
    ]
    started = time.perf_counter()
    result = ReplayRunner(rules).run(events)
    elapsed = time.perf_counter() - started
    evaluations = len(events) * len(rules)
    print(
        f"Evaluated {evaluations:,} rule-event pairs in {elapsed:.3f}s ({evaluations / elapsed:,.0f}/s); alerts={len(result.alerts)}"
    )


if __name__ == "__main__":
    main()
