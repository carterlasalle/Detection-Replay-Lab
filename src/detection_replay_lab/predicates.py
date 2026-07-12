"""Field predicates and safe boolean condition evaluation."""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from .models import Event, SelectionTrace, ValidationError


def match_selection(name: str, selection: Any, event: Event) -> SelectionTrace:
    if isinstance(selection, list):
        traces = [match_selection(name, item, event) for item in selection]
        matched = any(trace.matched for trace in traces)
        return SelectionTrace(
            name, matched, tuple(check for trace in traces for check in trace.checks)
        )
    if not isinstance(selection, dict):
        raise ValidationError(f"selection {name!r} must be an object or list of objects")
    checks: list[str] = []
    matched = True
    for expression, expected in selection.items():
        if not isinstance(expression, str):
            raise ValidationError(f"selection {name!r} field names must be strings")
        field, modifiers = _parse_field(expression)
        actual = event.get(field)
        outcome = _match_value(actual, expected, modifiers)
        checks.append(
            f"{field}{'|' if modifiers else ''}{'|'.join(modifiers)}: {'match' if outcome else 'miss'}"
        )
        matched = matched and outcome
    return SelectionTrace(name, matched, tuple(checks))


def evaluate_condition(condition: str, matches: dict[str, bool]) -> bool:
    return _ConditionParser(condition, matches).parse()


def _parse_field(expression: str) -> tuple[str, tuple[str, ...]]:
    parts = expression.split("|")
    field = parts[0]
    modifiers = tuple(part.casefold() for part in parts[1:])
    allowed = {
        "contains",
        "startswith",
        "endswith",
        "re",
        "cidr",
        "exists",
        "gt",
        "gte",
        "lt",
        "lte",
        "all",
        "windash",
    }
    unknown = set(modifiers) - allowed
    if unknown:
        raise ValidationError(f"unknown modifier(s) on {field}: {', '.join(sorted(unknown))}")
    return field, modifiers


def _match_value(actual: Any, expected: Any, modifiers: tuple[str, ...]) -> bool:
    if "exists" in modifiers:
        desired = bool(expected)
        return (actual is not None) == desired
    expected_values = expected if isinstance(expected, list) else [expected]

    def matcher(value: Any) -> bool:
        return _match_one(actual, value, modifiers)

    return (
        all(matcher(value) for value in expected_values)
        if "all" in modifiers
        else any(matcher(value) for value in expected_values)
    )


def _match_one(actual: Any, expected: Any, modifiers: tuple[str, ...]) -> bool:
    if isinstance(actual, list):
        return any(_match_one(item, expected, modifiers) for item in actual)
    if actual is None:
        return False
    if any(modifier in modifiers for modifier in ("gt", "gte", "lt", "lte")):
        try:
            left, right = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        if "gt" in modifiers:
            return left > right
        if "gte" in modifiers:
            return left >= right
        if "lt" in modifiers:
            return left < right
        return left <= right
    actual_text = str(actual)
    expected_text = str(expected)
    if "windash" in modifiers:
        actual_text = actual_text.replace("/", "-")
        expected_text = expected_text.replace("/", "-")
    folded_actual, folded_expected = actual_text.casefold(), expected_text.casefold()
    if "contains" in modifiers:
        return folded_expected in folded_actual
    if "startswith" in modifiers:
        return folded_actual.startswith(folded_expected)
    if "endswith" in modifiers:
        return folded_actual.endswith(folded_expected)
    if "re" in modifiers:
        try:
            return re.search(expected_text, actual_text, flags=re.IGNORECASE) is not None
        except re.error as exc:
            raise ValidationError(f"invalid detection regex {expected_text!r}: {exc}") from exc
    if "cidr" in modifiers:
        try:
            return ipaddress.ip_address(actual_text) in ipaddress.ip_network(
                expected_text, strict=False
            )
        except ValueError:
            return False
    if any(char in expected_text for char in "*?"):
        return fnmatch.fnmatch(folded_actual, folded_expected)
    if isinstance(actual, bool) or isinstance(expected, bool):
        return actual is expected
    return folded_actual == folded_expected


@dataclass(slots=True)
class _ConditionParser:
    condition: str
    matches: dict[str, bool]
    tokens: list[str] = field(init=False)
    position: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self.tokens = _tokenize(self.condition)
        self.position = 0

    def parse(self) -> bool:
        if not self.tokens:
            raise ValidationError("condition cannot be empty")
        value = self._or_expression()
        if self.position != len(self.tokens):
            raise ValidationError(f"unexpected condition token {self.tokens[self.position]!r}")
        return value

    def _or_expression(self) -> bool:
        value = self._and_expression()
        while self._peek("or"):
            self.position += 1
            right = self._and_expression()
            value = value or right
        return value

    def _and_expression(self) -> bool:
        value = self._unary()
        while self._peek("and"):
            self.position += 1
            right = self._unary()
            value = value and right
        return value

    def _unary(self) -> bool:
        if self._peek("not"):
            self.position += 1
            return not self._unary()
        return self._primary()

    def _primary(self) -> bool:
        if self._peek("("):
            self.position += 1
            value = self._or_expression()
            self._consume(")")
            return value
        token = self._consume()
        lowered = token.casefold()
        if lowered in {"1", "all"} and self._peek("of"):
            self.position += 1
            pattern = self._consume()
            selected = [
                value for name, value in self.matches.items() if fnmatch.fnmatch(name, pattern)
            ]
            if not selected:
                raise ValidationError(f"condition pattern {pattern!r} matched no selections")
            return any(selected) if lowered == "1" else all(selected)
        if token not in self.matches:
            raise ValidationError(f"condition references unknown selection {token!r}")
        return self.matches[token]

    def _peek(self, value: str) -> bool:
        return self.position < len(self.tokens) and self.tokens[self.position].casefold() == value

    def _consume(self, expected: str | None = None) -> str:
        if self.position >= len(self.tokens):
            raise ValidationError("unexpected end of condition")
        token = self.tokens[self.position]
        if expected is not None and token.casefold() != expected:
            raise ValidationError(f"expected {expected!r}, got {token!r}")
        self.position += 1
        return token


def _tokenize(condition: str) -> list[str]:
    tokens = re.findall(r"\(|\)|[A-Za-z0-9_.*?-]+", condition)
    compact = re.sub(r"\s+", "", condition)
    reconstructed = "".join(tokens).replace("and", "and").replace("or", "or").replace("not", "not")
    if re.sub(r"\s+", "", reconstructed) != compact:
        raise ValidationError("condition contains unsupported characters")
    return tokens
