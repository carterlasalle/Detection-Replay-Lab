"""Streaming-friendly JSON, NDJSON, CSV, and gzip event loading."""

from __future__ import annotations

import csv
import gzip
import io
import json
from pathlib import Path
from typing import Any, TextIO

from .models import Event, ValidationError
from .normalize import Normalizer


def load_events(paths: list[str | Path], *, normalizer: Normalizer | None = None) -> list[Event]:
    normalizer = normalizer or Normalizer()
    events: list[Event] = []
    identifiers: set[str] = set()
    for path in _expand(paths):
        with _open_text(path) as stream:
            for raw in _read_records(stream, path):
                event = normalizer.normalize(raw, index=len(events), source=path.as_posix())
                if event.id in identifiers:
                    raise ValidationError(f"duplicate event id {event.id!r}")
                identifiers.add(event.id)
                events.append(event)
    return events


def load_event(path: str | Path, *, normalizer: Normalizer | None = None) -> Event:
    events = load_events([path], normalizer=normalizer)
    if len(events) != 1:
        raise ValidationError(f"expected exactly one event in {path}, found {len(events)}")
    return events[0]


def _read_records(stream: TextIO, path: Path) -> list[dict[str, Any]]:
    suffixes = [suffix.casefold() for suffix in path.suffixes]
    effective = (
        suffixes[-2]
        if suffixes and suffixes[-1] == ".gz" and len(suffixes) > 1
        else suffixes[-1]
        if suffixes
        else ""
    )
    try:
        if effective == ".csv":
            return [dict(row) for row in csv.DictReader(stream)]
        if effective == ".json":
            payload = json.load(stream)
            if isinstance(payload, dict):
                if isinstance(payload.get("events"), list):
                    payload = payload["events"]
                else:
                    payload = [payload]
            if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
                raise ValidationError(
                    f"JSON event file {path} must contain an object or array of objects"
                )
            return payload
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValidationError(f"{path}:{line_number} must be a JSON object")
            records.append(item)
        return records
    except (csv.Error, json.JSONDecodeError, UnicodeError) as exc:
        raise ValidationError(f"cannot parse events from {path}: {exc}") from exc


def _open_text(path: Path) -> TextIO:
    try:
        if path.suffix.casefold() == ".gz":
            return gzip.open(path, "rt", encoding="utf-8-sig", newline="")
        return path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise ValidationError(f"cannot open event file {path}: {exc}") from exc


def _expand(paths: list[str | Path]) -> list[Path]:
    supported = {".json", ".jsonl", ".ndjson", ".csv", ".gz"}
    discovered: set[Path] = set()
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            discovered.add(path)
        elif path.is_dir():
            discovered.update(
                item
                for item in path.rglob("*")
                if item.is_file() and item.suffix.casefold() in supported
            )
        else:
            raise ValidationError(f"event path does not exist: {path}")
    return sorted(discovered, key=lambda item: item.as_posix())


def event_from_stdin(content: str, *, filename: str = "<stdin>") -> list[Event]:
    suffix = Path(filename).suffix.casefold()
    synthetic_path = Path(filename if suffix else f"{filename}.ndjson")
    records = _read_records(io.StringIO(content), synthetic_path)
    normalizer = Normalizer()
    return [
        normalizer.normalize(record, index=index, source=filename)
        for index, record in enumerate(records)
    ]
