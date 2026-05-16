"""Auditable baseline suppressions for benchmark score reports."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

REQUIRED_SUPPRESSION_FIELDS = ("case_id", "violation_type", "pattern", "owner", "ticket", "reason", "expires_at")


def _parse_expires_at(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("expires_at must be a non-empty ISO timestamp")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"expires_at must be an ISO timestamp: {text!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError("expires_at must include a timezone, for example 2099-01-01T00:00:00Z")
    return parsed.astimezone(UTC)


def validate_baseline_suppressions(data: dict[str, Any]) -> list[dict[str, str]]:
    """Validate and normalize a baseline-suppressions JSON object."""

    if not isinstance(data, dict):
        raise ValueError("baseline suppressions file must be a JSON object")
    suppressions = data.get("suppressions")
    if not isinstance(suppressions, list):
        raise ValueError("baseline suppressions file must contain a suppressions list")

    normalized: list[dict[str, str]] = []
    for index, suppression in enumerate(suppressions):
        if not isinstance(suppression, dict):
            raise ValueError(f"suppressions[{index}] must be an object")
        missing = [field for field in REQUIRED_SUPPRESSION_FIELDS if not suppression.get(field)]
        if missing:
            raise ValueError(f"suppressions[{index}] missing required field(s): {', '.join(missing)}")
        expires_at = _parse_expires_at(suppression["expires_at"])
        normalized.append(
            {
                "case_id": str(suppression["case_id"]),
                "violation_type": str(suppression["violation_type"]),
                "pattern": str(suppression["pattern"]),
                "owner": str(suppression["owner"]),
                "ticket": str(suppression["ticket"]),
                "reason": str(suppression["reason"]),
                "expires_at": suppression["expires_at"],
                "_expires_at_iso": expires_at.isoformat(),
            }
        )
    return normalized


def _violation_key(case_id: str, violation: dict[str, Any]) -> tuple[str, str, str]:
    return (str(case_id), str(violation.get("type", "")), str(violation.get("pattern", "")))


def _recompute_result_after_suppression(result: dict[str, Any], violations: list[dict[str, Any]]) -> dict[str, Any]:
    updated = dict(result)
    updated["violations"] = violations
    updated["passed"] = not violations
    updated["score"] = round(max(0.0, 1.0 - min(1.0, len(violations) * 0.35)), 4)
    return updated


def _average_bucket_scores(results: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for result in results:
        bucket = buckets.setdefault(result[key], {"total": 0, "passed": 0, "score": 0.0})
        bucket["total"] += 1
        bucket["passed"] += 1 if result["passed"] else 0
        bucket["score"] += result["score"]
    for bucket in buckets.values():
        bucket["score"] = round(bucket["score"] / bucket["total"], 4) if bucket["total"] else 0.0
    return buckets


def _recompute_report_summary(report: dict[str, Any], results: list[dict[str, Any]]) -> None:
    total = len(results)
    passed = sum(1 for result in results if result["passed"])
    score = round(sum(result["score"] for result in results) / total, 4) if total else 0.0
    report["summary"] = {"total": total, "passed": passed, "failed": total - passed, "score": score}
    report["by_category"] = _average_bucket_scores(results, "category")
    report["by_difficulty"] = _average_bucket_scores(results, "difficulty")
    report["results"] = results


def apply_baseline_suppressions(
    report: dict[str, Any],
    suppressions: list[dict[str, str]],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Suppress exact case/violation matches while retaining auditable metadata."""

    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    now = now.astimezone(UTC)

    active_by_key: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    expired: list[dict[str, str]] = []
    for suppression in suppressions:
        expires_at = datetime.fromisoformat(suppression["_expires_at_iso"])
        public = {key: value for key, value in suppression.items() if not key.startswith("_")}
        if expires_at <= now:
            expired.append(public)
            continue
        key = (suppression["case_id"], suppression["violation_type"], suppression["pattern"])
        active_by_key.setdefault(key, []).append(public)

    matched_keys: set[tuple[str, str, str]] = set()
    suppressed_findings: list[dict[str, Any]] = []
    new_results: list[dict[str, Any]] = []

    for result in report.get("results", []):
        remaining_violations: list[dict[str, Any]] = []
        for violation in result.get("violations", []):
            key = _violation_key(result.get("id", ""), violation)
            suppressions_for_key = active_by_key.get(key) or []
            if suppressions_for_key:
                matched_keys.add(key)
                suppression = suppressions_for_key[0]
                suppressed_findings.append(
                    {
                        "case_id": result.get("id"),
                        "category": result.get("category"),
                        "severity": result.get("severity"),
                        "difficulty": result.get("difficulty"),
                        "violation": violation,
                        "suppression": suppression,
                    }
                )
            else:
                remaining_violations.append(violation)
        new_results.append(_recompute_result_after_suppression(result, remaining_violations))

    stale = [suppression for key, entries in active_by_key.items() if key not in matched_keys for suppression in entries]
    by_owner: dict[str, int] = {}
    for finding in suppressed_findings:
        owner = finding["suppression"].get("owner", "unknown")
        by_owner[owner] = by_owner.get(owner, 0) + 1

    _recompute_report_summary(report, new_results)
    report["suppressed_findings"] = suppressed_findings
    report["suppressed_summary"] = {"count": len(suppressed_findings), "by_owner": by_owner}
    report["baseline_suppression_summary"] = {
        "active": len(suppressions) - len(expired),
        "matched": len(suppressed_findings),
        "stale": len(stale),
        "expired": len(expired),
    }
    report["stale_suppressions"] = stale
    report["expired_suppressions"] = expired
    return report
