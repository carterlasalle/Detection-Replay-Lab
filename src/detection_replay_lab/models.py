"""Stable event, rule, trace, and alert models."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal


Level = Literal["informational", "low", "medium", "high", "critical"]
LEVEL_ORDER: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class ValidationError(ValueError):
    """Raised when events or rules cannot be interpreted safely."""


@dataclass(frozen=True, slots=True)
class Event:
    """One normalized telemetry event."""

    id: str
    timestamp: datetime
    fields: dict[str, Any]
    source: str = "unknown"
    label: str | None = None
    scenario: str | None = None

    def get(self, path: str, default: Any = None) -> Any:
        if path in self.fields:
            return self.fields[path]
        current: Any = self.fields
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return default
            current = current[part]
        return current

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat().replace("+00:00", "Z")
        return result


@dataclass(frozen=True, slots=True)
class LogSource:
    product: str | None = None
    category: str | None = None
    service: str | None = None


@dataclass(frozen=True, slots=True)
class Correlation:
    kind: Literal["threshold", "sequence"]
    group_by: tuple[str, ...] = ()
    timespan_seconds: float = 300.0
    count: int = 1
    ordered: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    level: Level
    detection: dict[str, Any]
    condition: str
    status: str = "experimental"
    description: str = ""
    author: str = ""
    date: str | None = None
    modified: str | None = None
    logsource: LogSource = LogSource()
    tags: tuple[str, ...] = ()
    falsepositives: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    correlation: Correlation | None = None
    source_path: str | None = None

    @property
    def attack_techniques(self) -> tuple[str, ...]:
        return tuple(tag for tag in self.tags if tag.startswith("attack.t"))


@dataclass(frozen=True, slots=True)
class SelectionTrace:
    name: str
    matched: bool
    checks: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvaluationTrace:
    rule_id: str
    condition: str
    matched: bool
    selections: tuple[SelectionTrace, ...]
    logsource_matched: bool = True


@dataclass(frozen=True, slots=True)
class Alert:
    id: str
    rule_id: str
    rule_title: str
    level: Level
    timestamp: datetime
    event_ids: tuple[str, ...]
    group: tuple[tuple[str, str], ...] = ()
    tags: tuple[str, ...] = ()
    trace: EvaluationTrace | None = None

    def to_dict(self, *, include_trace: bool = False) -> dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat().replace("+00:00", "Z")
        if not include_trace:
            result.pop("trace", None)
        return result


@dataclass(slots=True)
class RunStats:
    events_read: int = 0
    events_evaluated: int = 0
    rules_evaluated: int = 0
    alerts_emitted: int = 0
    malformed_events: int = 0
    duration_seconds: float = 0.0


@dataclass(slots=True)
class ReplayResult:
    alerts: list[Alert] = field(default_factory=list)
    stats: RunStats = field(default_factory=RunStats)
    errors: list[str] = field(default_factory=list)

    def to_dict(self, *, include_traces: bool = False) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "alerts": [alert.to_dict(include_trace=include_traces) for alert in self.alerts],
            "stats": asdict(self.stats),
            "errors": self.errors,
        }


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = datetime.fromtimestamp(float(value), tz=UTC)
    elif isinstance(value, str):
        normalized = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValidationError(f"invalid timestamp {value!r}") from exc
    else:
        raise ValidationError(f"timestamp must be RFC3339 or epoch, got {type(value).__name__}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def stable_id(*parts: str) -> str:
    digest = hashlib.blake2s(digest_size=16, person=b"DRLab-v1")
    for part in parts:
        digest.update(part.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
    return digest.hexdigest()

