"""Report renderers for agent-security-bench."""

from __future__ import annotations

from typing import Any


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Agent Security Benchmark Report",
        "",
        f"**Benchmark version:** {report.get('benchmark_version', 'unknown')}",
        f"**Score:** {summary['score']}",
        f"**Passed:** {summary['passed']} / {summary['total']}",
        f"**Failed:** {summary['failed']}",
        "",
        "## By category",
        "",
    ]
    for category, bucket in sorted(report.get("by_category", {}).items()):
        lines.append(f"- **{category}:** {bucket['passed']}/{bucket['total']} passed, score {bucket['score']}")
    lines.extend(["", "## Results", "", "| Case | Category | Difficulty | Severity | Result | Score | Violations |", "| --- | --- | --- | --- | --- | ---: | --- |"])
    for result in report.get("results", []):
        outcome = "PASS" if result["passed"] else "FAIL"
        violations = ", ".join(f"{item['type']}:{item['pattern']}" for item in result.get("violations", []))
        lines.append(
            "| "
            + " | ".join(
                [
                    result["id"],
                    result["category"],
                    result.get("difficulty", "medium"),
                    result["severity"],
                    outcome,
                    str(result["score"]),
                    violations.replace("|", "\\|") or "-",
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def sarif_level(result: dict[str, Any]) -> str:
    if result.get("passed"):
        return "note"
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(result.get("severity"), "warning")


def render_sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules = []
    results = []
    for item in report.get("results", []):
        rule_id = f"ASB-{item['id']}"
        rules.append(
            {
                "id": rule_id,
                "name": item["id"],
                "shortDescription": {"text": item["title"]},
                "fullDescription": {"text": item["expected_behavior"]},
                "properties": {
                    "category": item["category"],
                    "difficulty": item.get("difficulty", "medium"),
                    "severity": item["severity"],
                    "benchmark_version": item.get("benchmark_version"),
                },
            }
        )
        if not item.get("passed"):
            message = "; ".join(f"{v['type']}:{v['pattern']}" for v in item.get("violations", [])) or item["expected_behavior"]
            results.append(
                {
                    "ruleId": rule_id,
                    "level": sarif_level(item),
                    "message": {"text": message},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "responses"}, "region": {"startLine": 1}}}],
                    "properties": item,
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-security-bench",
                        "informationUri": "https://github.com/mattpartida/agent-security-bench",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
