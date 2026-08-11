"""Deterministic, fail-closed JSON admission helpers."""

from __future__ import annotations

import json
import math
from typing import Any

MAX_JSON_NESTING_DEPTH = 64


def _validate_nesting_depth(text: str, field: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING_DEPTH:
                raise ValueError(
                    f"{field} exceeds the JSON nesting depth limit of {MAX_JSON_NESTING_DEPTH}"
                )
        elif character in "]}":
            depth -= 1


def loads_strict_json(text: str, field: str) -> Any:
    """Parse RFC JSON with deterministic duplicate, number, and depth checks."""

    _validate_nesting_depth(text, field)

    def reject_duplicate_names(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError(f"{field} contains duplicate JSON object name {name!r}")
            result[name] = value
        return result

    def reject_nonfinite_constant(value: str):
        raise ValueError(f"{field} contains non-finite JSON constant {value}")

    def parse_finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError(f"{field} contains non-finite JSON number {value}")
        return parsed

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_names,
            parse_constant=reject_nonfinite_constant,
            parse_float=parse_finite_float,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{field} contains invalid JSON: {exc}") from exc
