"""Evidence bundle helpers for failed benchmark cases."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .cases import BENCHMARK_VERSION, BenchmarkCase


def _case_lookup(cases: list[BenchmarkCase] | tuple[BenchmarkCase, ...]) -> dict[str, BenchmarkCase]:
    return {case.id: case for case in cases}


def _observed_response(result: dict[str, Any]) -> str:
    transcript = result.get("transcript")
    if isinstance(transcript, dict):
        return str(transcript.get("response", ""))
    return str(result.get("response", result.get("observed_response", "")))


def _adapter_metadata(report: dict[str, Any], result: dict[str, Any]) -> dict[str, Any] | None:
    transcript = result.get("transcript")
    if isinstance(transcript, dict) and isinstance(transcript.get("adapter"), dict):
        return dict(transcript["adapter"])
    if isinstance(report.get("adapter"), dict):
        return dict(report["adapter"])
    return None


def build_evidence_bundle(
    report: dict[str, Any],
    cases: list[BenchmarkCase] | tuple[BenchmarkCase, ...],
    *,
    source: str | None = None,
    command: str | None = None,
) -> dict[str, Any]:
    """Build an audit-friendly bundle for failed benchmark cases.

    The bundle intentionally contains only failed active cases so it can be
    attached to CI artifacts without burying reviewers in passing evidence.
    """

    by_id = _case_lookup(cases)
    failures = [result for result in report.get("results", []) if not result.get("passed")]
    evidence_cases: list[dict[str, Any]] = []
    for result in failures:
        case = by_id.get(str(result.get("id")))
        if case is None:
            continue
        evidence: dict[str, Any] = {
            "id": case.id,
            "category": case.category,
            "title": case.title,
            "severity": case.severity,
            "difficulty": case.difficulty,
            "benchmark_version": case.benchmark_version,
            "prompt": case.prompt,
            "expected_behavior": case.expected_behavior,
            "observed_response": _observed_response(result),
            "violations": list(result.get("violations", [])),
            "reproducer": {
                "command": command or "agent-security-bench score <responses.json> --format json",
                "notes": f"Re-run the benchmark and inspect --case {case.id} in the evidence bundle.",
            },
        }
        transcript = result.get("transcript")
        if isinstance(transcript, dict):
            evidence["transcript"] = transcript
        adapter = _adapter_metadata(report, result)
        if adapter is not None:
            evidence["adapter"] = adapter
        evidence_cases.append(evidence)

    return {
        "schema_version": report.get("schema_version", "0.2"),
        "benchmark_version": report.get("benchmark_version", BENCHMARK_VERSION),
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": source,
        "summary": {"failed_cases": len(failures), "included_cases": len(evidence_cases)},
        "cases": evidence_cases,
    }
