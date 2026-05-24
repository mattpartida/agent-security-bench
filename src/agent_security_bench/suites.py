"""Scenario suite selection for benchmark cases."""

from __future__ import annotations

from typing import Any

from .cases import BenchmarkCase

BUILT_IN_SUITES = ("smoke", "release", "exfiltration", "tool-use", "full")
SMOKE_CASE_IDS = ("direct-ignore-system", "secret-exfiltration", "unsafe-tool-use", "approval-bypass")


def _case_value(case: BenchmarkCase | dict[str, Any], key: str, default: Any = None) -> Any:
    if isinstance(case, BenchmarkCase):
        return getattr(case, key, default)
    return case.get(key, default)


def suite_names() -> tuple[str, ...]:
    return BUILT_IN_SUITES


def case_suites(case: BenchmarkCase | dict[str, Any]) -> tuple[str, ...]:
    """Return deterministic built-in suite memberships for a case."""

    case_id = str(_case_value(case, "id", ""))
    category = str(_case_value(case, "category", ""))
    severity = str(_case_value(case, "severity", ""))
    tags = {str(tag) for tag in (_case_value(case, "tags", ()) or ())}
    memberships: list[str] = []

    if case_id in SMOKE_CASE_IDS:
        memberships.append("smoke")
    if severity in {"critical", "high"}:
        memberships.append("release")
    if category in {"data_exfiltration", "canary_exfiltration"} or "exfiltration" in tags:
        memberships.append("exfiltration")
    if category == "tool_misuse" or "tool-use" in tags:
        memberships.append("tool-use")
    memberships.append("full")
    return tuple(name for name in BUILT_IN_SUITES if name in memberships)


def suite_metadata(name: str, cases: list[BenchmarkCase]) -> dict[str, int | str]:
    return {"name": name, "case_count": len(cases)}


def filter_cases_by_suite(cases, suite: str | None):
    """Filter cases by suite and return (case_list, suite_metadata_or_none)."""

    case_list = list(cases)
    if suite is None:
        return case_list, None
    if suite not in BUILT_IN_SUITES:
        available = ", ".join(BUILT_IN_SUITES)
        raise ValueError(f"unknown suite {suite!r}; available suites: {available}")
    filtered = [case for case in case_list if suite in case_suites(case)]
    return filtered, suite_metadata(suite, filtered)


def case_to_dict_with_suites(case: BenchmarkCase) -> dict[str, Any]:
    data = case.to_dict()
    data["suites"] = list(case_suites(case))
    return data


def attach_result_suites(report: dict[str, Any], cases) -> None:
    """Attach suite memberships to report results in-place."""

    suites_by_id = {str(_case_value(case, "id", "")): list(case_suites(case)) for case in cases}
    for result in report.get("results", []):
        result["suites"] = suites_by_id.get(str(result.get("id", "")), ["full"])


def suite_counts(cases) -> dict[str, int]:
    counts = {name: 0 for name in BUILT_IN_SUITES}
    for case in cases:
        for suite in case_suites(case):
            counts[suite] += 1
    return {name: count for name, count in counts.items() if count}
