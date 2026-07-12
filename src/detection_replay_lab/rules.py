"""YAML rule loading and schema validation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from .models import LEVEL_ORDER, Correlation, LogSource, Rule, ValidationError
from .predicates import evaluate_condition


def load_rules(paths: list[str | Path]) -> list[Rule]:
    rules: list[Rule] = []
    identifiers: set[str] = set()
    for path in _expand(paths):
        try:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ValidationError(f"cannot load rule file {path}: {exc}") from exc
        for index, document in enumerate(documents, start=1):
            if document is None:
                continue
            rule = parse_rule(document, source_path=f"{path}:{index}")
            if rule.id in identifiers:
                raise ValidationError(f"duplicate rule id {rule.id!r}")
            identifiers.add(rule.id)
            rules.append(rule)
    return sorted(rules, key=lambda item: (item.title.casefold(), item.id))


def parse_rule(data: Any, *, source_path: str | None = None) -> Rule:
    if not isinstance(data, dict):
        raise ValidationError(f"rule {source_path or '<memory>'} must be an object")
    required = ("id", "title", "detection")
    missing = [key for key in required if key not in data]
    if missing:
        raise ValidationError(f"rule is missing required field(s): {', '.join(missing)}")
    identifier = str(data["id"])
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}", identifier):
        raise ValidationError(f"invalid rule id {identifier!r}")
    detection = data["detection"]
    if not isinstance(detection, dict):
        raise ValidationError("detection must be an object")
    condition = str(detection.get("condition", "selection"))
    selections = {key: value for key, value in detection.items() if key != "condition"}
    if not selections:
        raise ValidationError("detection must define at least one selection")
    evaluate_condition(condition, {name: False for name in selections})
    level = str(data.get("level", "medium")).casefold()
    if level not in LEVEL_ORDER:
        raise ValidationError(f"invalid rule level {level!r}")
    logsource_data = data.get("logsource", {})
    if not isinstance(logsource_data, dict):
        raise ValidationError("logsource must be an object")
    correlation = _parse_correlation(data.get("correlation"), selections)
    return Rule(
        id=identifier,
        title=str(data["title"]),
        level=level,  # type: ignore[arg-type]
        detection=selections,
        condition=condition,
        status=str(data.get("status", "experimental")),
        description=str(data.get("description", "")),
        author=str(data.get("author", "")),
        date=str(data["date"]) if data.get("date") else None,
        modified=str(data["modified"]) if data.get("modified") else None,
        logsource=LogSource(
            product=_optional_string(logsource_data.get("product")),
            category=_optional_string(logsource_data.get("category")),
            service=_optional_string(logsource_data.get("service")),
        ),
        tags=tuple(str(item).casefold() for item in _list(data.get("tags", []), "tags")),
        falsepositives=tuple(
            str(item) for item in _list(data.get("falsepositives", []), "falsepositives")
        ),
        references=tuple(str(item) for item in _list(data.get("references", []), "references")),
        correlation=correlation,
        source_path=source_path,
    )


def _parse_correlation(value: Any, selections: dict[str, Any]) -> Correlation | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValidationError("correlation must be an object")
    kind = str(value.get("type", "threshold")).casefold()
    if kind not in {"threshold", "sequence"}:
        raise ValidationError("correlation.type must be threshold or sequence")
    timespan = _parse_duration(value.get("timespan", "5m"))
    group_by = tuple(str(item) for item in _list(value.get("group_by", []), "correlation.group_by"))
    if kind == "threshold":
        count = int(value.get("count", 1))
        if count < 1:
            raise ValidationError("correlation.count must be positive")
        return Correlation("threshold", group_by, timespan, count)
    ordered = tuple(str(item) for item in _list(value.get("ordered", []), "correlation.ordered"))
    if len(ordered) < 2 or any(item not in selections for item in ordered):
        raise ValidationError("sequence ordered must contain at least two defined selection names")
    return Correlation("sequence", group_by, timespan, len(ordered), ordered)


def _parse_duration(value: Any) -> float:
    if isinstance(value, int | float):
        seconds = float(value)
    elif isinstance(value, str):
        match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhd])\s*", value.casefold())
        if not match:
            raise ValidationError(f"invalid duration {value!r}")
        multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
        seconds = float(match.group(1)) * multiplier
    else:
        raise ValidationError("duration must be seconds or a value such as 5m")
    if not 0 < seconds <= 31_536_000:
        raise ValidationError("duration must be between 0 seconds and 365 days")
    return seconds


def _expand(paths: list[str | Path]) -> list[Path]:
    discovered: set[Path] = set()
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            discovered.add(path)
        elif path.is_dir():
            discovered.update(
                item for item in path.rglob("*") if item.suffix.casefold() in {".yml", ".yaml"}
            )
        else:
            raise ValidationError(f"rule path does not exist: {path}")
    return sorted(discovered, key=lambda item: item.as_posix())


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError(f"{name} must be a list")
    return value


def _optional_string(value: Any) -> str | None:
    return str(value).casefold() if value is not None else None
