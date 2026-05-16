"""Corpus governance checks and coverage summaries."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from .cases import BenchmarkCase

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_DIFFICULTIES = {"easy", "medium", "hard"}
CASE_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FAKE_SECRET_MARKERS = ("BENCH_FAKE_SECRET", "sk-bench-fake", "fake-secret")
CANARY_MARKERS = ("agent-security-bench-canary", "bench-canary-file")
TOOL_TAGS = ("shell", "browser", "cron", "memory", "email", "http", "tool-use")


def _case_value(case: BenchmarkCase | dict[str, Any], key: str, default: Any = None) -> Any:
    if isinstance(case, BenchmarkCase):
        return getattr(case, key, default)
    return case.get(key, default)


def _case_id(case: BenchmarkCase | dict[str, Any], index: int) -> str:
    return str(_case_value(case, "id", f"case[{index}") or "")


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def _add_issue(issues: list[dict[str, Any]], *, level: str, case_id: str, field: str, message: str) -> None:
    issues.append({"level": level, "case_id": case_id, "field": field, "message": message})


def _duplicates(items: list[str]) -> list[str]:
    counts = Counter(item.lower() for item in items)
    return sorted(item for item, count in counts.items() if count > 1)


def lint_cases(cases) -> dict[str, Any]:
    """Validate benchmark corpus quality without requiring external dependencies."""

    case_list = list(cases)
    issues: list[dict[str, Any]] = []
    ids: dict[str, str] = {}
    by_category: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    by_difficulty: Counter[str] = Counter()

    for index, case in enumerate(case_list):
        case_id = _case_id(case, index)
        category = str(_case_value(case, "category", "") or "")
        severity = str(_case_value(case, "severity", "") or "")
        difficulty = str(_case_value(case, "difficulty", "") or "")
        prompt = str(_case_value(case, "prompt", "") or "")
        required = _as_list(_case_value(case, "required_patterns", []))
        forbidden = _as_list(_case_value(case, "forbidden_patterns", []))
        fake_secret_ids = _as_list(_case_value(case, "fake_secret_ids", []))
        canary_ids = _as_list(_case_value(case, "canary_ids", []))

        if not CASE_ID_RE.match(case_id):
            _add_issue(
                issues,
                level="error",
                case_id=case_id,
                field="id",
                message="case id must be stable lowercase kebab-case",
            )
        if case_id in ids:
            _add_issue(issues, level="error", case_id=case_id, field="id", message="duplicate case id")
        ids[case_id] = case_id

        if not category:
            _add_issue(issues, level="error", case_id=case_id, field="category", message="category is required")
        else:
            by_category[category] += 1
        if severity not in VALID_SEVERITIES:
            _add_issue(issues, level="error", case_id=case_id, field="severity", message=f"invalid severity {severity!r}")
        else:
            by_severity[severity] += 1
        if difficulty not in VALID_DIFFICULTIES:
            _add_issue(issues, level="error", case_id=case_id, field="difficulty", message=f"invalid difficulty {difficulty!r}")
        else:
            by_difficulty[difficulty] += 1

        for duplicate in _duplicates(required):
            _add_issue(issues, level="error", case_id=case_id, field="required_patterns", message=f"duplicate required pattern {duplicate!r}")
        for duplicate in _duplicates(forbidden):
            _add_issue(issues, level="error", case_id=case_id, field="forbidden_patterns", message=f"duplicate forbidden pattern {duplicate!r}")

        combined_text = "\n".join([prompt, *forbidden, *required])
        if any(marker.lower() in combined_text.lower() for marker in FAKE_SECRET_MARKERS) and not fake_secret_ids:
            _add_issue(
                issues,
                level="error",
                case_id=case_id,
                field="fake_secret_ids",
                message="fake secret fixture reference must be listed in fake_secret_ids",
            )
        if any(marker.lower() in combined_text.lower() for marker in CANARY_MARKERS) and not canary_ids:
            _add_issue(
                issues,
                level="error",
                case_id=case_id,
                field="canary_ids",
                message="canary fixture reference must be listed in canary_ids",
            )

    errors = sum(1 for issue in issues if issue["level"] == "error")
    warnings = sum(1 for issue in issues if issue["level"] == "warning")
    return {
        "schema_version": "0.2",
        "summary": {
            "case_count": len(case_list),
            "error_count": errors,
            "warning_count": warnings,
            "by_category": dict(sorted(by_category.items())),
            "by_severity": dict(sorted(by_severity.items())),
            "by_difficulty": dict(sorted(by_difficulty.items())),
        },
        "issues": issues,
    }


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items()))


def _detect_tools(case: BenchmarkCase | dict[str, Any]) -> set[str]:
    text = " ".join(
        [
            str(_case_value(case, "category", "")),
            str(_case_value(case, "prompt", "")),
            *(_as_list(_case_value(case, "tags", []))),
            *(_as_list(_case_value(case, "forbidden_patterns", []))),
        ]
    ).lower()
    tools = set()
    for tag in TOOL_TAGS:
        if tag in text:
            tools.add("http" if tag == "tool-use" else tag)
    if "curl" in text or "id_rsa" in text:
        tools.add("shell")
    if "evil.test" in text or "attacker@example.com" in text:
        tools.add("http")
    return tools


def corpus_coverage_report(cases) -> dict[str, Any]:
    """Summarize benchmark corpus coverage across risk dimensions."""

    case_list = list(cases)
    categories: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "severities": Counter(), "difficulties": Counter()})
    severities: Counter[str] = Counter()
    difficulties: Counter[str] = Counter()
    tags: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    required_patterns: Counter[str] = Counter()
    forbidden_patterns: Counter[str] = Counter()
    fixture_references: Counter[str] = Counter()

    for case in case_list:
        category = str(_case_value(case, "category", "uncategorized") or "uncategorized")
        severity = str(_case_value(case, "severity", "unknown") or "unknown")
        difficulty = str(_case_value(case, "difficulty", "unknown") or "unknown")
        categories[category]["count"] += 1
        categories[category]["severities"][severity] += 1
        categories[category]["difficulties"][difficulty] += 1
        severities[severity] += 1
        difficulties[difficulty] += 1
        tags.update(_as_list(_case_value(case, "tags", [])))
        tools.update(_detect_tools(case))
        required_patterns.update(_as_list(_case_value(case, "required_patterns", [])))
        forbidden_patterns.update(_as_list(_case_value(case, "forbidden_patterns", [])))
        fixture_references.update(_as_list(_case_value(case, "canary_ids", [])))
        fixture_references.update(_as_list(_case_value(case, "fake_secret_ids", [])))

    rendered_categories = {
        key: {
            "count": value["count"],
            "severities": _counter_dict(value["severities"]),
            "difficulties": _counter_dict(value["difficulties"]),
        }
        for key, value in sorted(categories.items())
    }
    return {
        "schema_version": "0.2",
        "summary": {"case_count": len(case_list), "category_count": len(rendered_categories)},
        "categories": rendered_categories,
        "severities": _counter_dict(severities),
        "difficulties": _counter_dict(difficulties),
        "tags": _counter_dict(tags),
        "tools": _counter_dict(tools),
        "required_patterns": _counter_dict(required_patterns),
        "forbidden_patterns": _counter_dict(forbidden_patterns),
        "fixture_references": _counter_dict(fixture_references),
    }
