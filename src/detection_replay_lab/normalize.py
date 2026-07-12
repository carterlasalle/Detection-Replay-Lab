"""Configurable field normalization for common telemetry shapes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Event, ValidationError, parse_timestamp, stable_id

DEFAULT_ALIASES: dict[str, tuple[str, ...]] = {
    "@timestamp": ("timestamp", "time", "eventTime", "TimeCreated", "UtcTime"),
    "event.action": ("action", "eventName", "EventName"),
    "event.category": ("category", "Channel"),
    "event.code": ("event_id", "EventID", "eventID"),
    "event.provider": ("provider", "source", "eventSource", "ProviderName"),
    "host.name": ("hostname", "computer_name", "Computer", "device.hostname"),
    "process.name": ("process_name", "Image", "NewProcessName"),
    "process.command_line": ("command_line", "CommandLine", "ProcessCommandLine"),
    "process.parent.name": ("parent_process_name", "ParentImage"),
    "process.pid": ("pid", "ProcessId", "ProcessID"),
    "user.name": ("username", "user", "User", "userIdentity.userName"),
    "source.ip": ("src_ip", "sourceIPAddress", "client.ip", "ipAddress"),
    "destination.ip": ("dst_ip", "destinationIPAddress"),
    "file.path": ("file_path", "TargetFilename", "ObjectName"),
    "registry.path": ("registry_path", "TargetObject"),
}


@dataclass(slots=True)
class Normalizer:
    aliases: dict[str, tuple[str, ...]] = field(default_factory=lambda: dict(DEFAULT_ALIASES))
    preserve_original: bool = True

    def normalize(self, raw: dict[str, Any], *, index: int = 0, source: str = "unknown") -> Event:
        if not isinstance(raw, dict):
            raise ValidationError("event must be an object")
        fields = dict(raw) if self.preserve_original else {}
        for canonical, candidates in self.aliases.items():
            if _deep_get(raw, canonical) is not None:
                fields[canonical] = _deep_get(raw, canonical)
                continue
            for candidate in candidates:
                value = _deep_get(raw, candidate)
                if value is not None:
                    fields[canonical] = value
                    break
        timestamp_value = fields.get("@timestamp")
        if timestamp_value is None:
            raise ValidationError("event is missing a timestamp")
        timestamp = parse_timestamp(timestamp_value)
        event_id = str(
            raw.get("id")
            or raw.get("event_id")
            or stable_id(source, str(index), timestamp.isoformat())
        )
        label = raw.get("label") or _deep_get(raw, "drl.label")
        if label is not None and label not in {"malicious", "benign"}:
            raise ValidationError("event label must be malicious or benign")
        scenario = raw.get("scenario") or _deep_get(raw, "drl.scenario")
        return Event(
            id=event_id,
            timestamp=timestamp,
            fields=fields,
            source=source,
            label=str(label) if label is not None else None,
            scenario=str(scenario) if scenario is not None else None,
        )


def _deep_get(value: dict[str, Any], path: str) -> Any:
    if path in value:
        return value[path]
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
