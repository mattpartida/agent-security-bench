"""Report renderers for agent-security-bench."""

from __future__ import annotations

import json
from html import escape
from typing import Any


def _is_xml_10_character(character: str) -> bool:
    codepoint = ord(character)
    if character in "\t\n\r":
        return True
    in_xml_range = 0x20 <= codepoint <= 0xD7FF or 0xE000 <= codepoint <= 0xFFFD or 0x10000 <= codepoint <= 0x10FFFF
    noncharacter = 0xFDD0 <= codepoint <= 0xFDEF or codepoint & 0xFFFF in {0xFFFE, 0xFFFF}
    return in_xml_range and not noncharacter


def _xml_escape(value: Any, *, quote: bool = True) -> str:
    """Escape text for XML 1.0, replacing illegal Unicode code points."""

    text = str(value)
    cleaned = "".join(ch if _is_xml_10_character(ch) else "\ufffd" for ch in text)
    return escape(cleaned, quote=quote)


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Agent Security Benchmark Report",
        "",
        f"**Benchmark version:** {report.get('benchmark_version', 'unknown')}",
        f"**Score:** {summary['score']}",
        f"**Unweighted score:** {summary['score']}",
        f"**Weighted score:** {summary.get('weighted_score', summary['score'])}",
        f"**Passed:** {summary['passed']} / {summary['total']}",
        f"**Failed:** {summary['failed']}",
        "",
        "## Failures by severity",
        "",
    ]
    for severity, count in summary.get("failures_by_severity", {}).items():
        lines.append(f"- **{severity}:** {count}")
    lines.extend([
        "",
        "## By category",
        "",
    ])
    for category, bucket in sorted(report.get("by_category", {}).items()):
        lines.append(f"- **{category}:** {bucket['passed']}/{bucket['total']} passed, score {bucket['score']}")
    lines.extend([
        "",
        "## Results",
        "",
        "| Case | Category | Difficulty | Severity | Result | Score | Severity weight | Weighted contribution | Violations |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- |",
    ])
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
                    str(result.get("severity_weight", "-")),
                    str(result.get("weighted_score_contribution", "-")),
                    violations.replace("|", "\\|") or "-",
                ]
            )
            + " |"
        )
    manifest = report.get("evaluation_manifest")
    if manifest:
        lines.extend([
            "",
            "## Evaluation manifest",
            "",
            f"**SHA-256:** `{manifest.get('sha256', 'unknown')}`",
            "",
            "**Provenance:**",
            "",
        ])
        lines.extend(f"    {line}" for line in json.dumps(manifest, indent=2, sort_keys=True).splitlines())
    lines.append("")
    return "\n".join(lines)


def render_junit(report: dict[str, Any]) -> str:
    """Render benchmark results as dependency-free JUnit XML.

    The benchmark is not a unit-test runner, but CI systems understand JUnit
    natively. Each benchmark case maps to one testcase and each failed case
    receives one failure element containing deterministic violation details.
    """

    summary = report.get("summary", {})
    tests = int(summary.get("total", 0))
    failures = int(summary.get("failed", 0))
    benchmark_version = _xml_escape(report.get("benchmark_version", "unknown"), quote=True)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites tests="{tests}" failures="{failures}">',
        f'  <testsuite name="agent-security-bench" tests="{tests}" failures="{failures}" benchmark_version="{benchmark_version}">',
    ]
    manifest = report.get("evaluation_manifest")
    if manifest:
        manifest_schema = _xml_escape(manifest.get("schema_version", ""), quote=True)
        manifest_path = _xml_escape(manifest.get("path", ""), quote=True)
        manifest_hash = _xml_escape(manifest.get("sha256", ""), quote=True)
        selected_inputs = _xml_escape(
            json.dumps(manifest.get("selected_inputs", {}), sort_keys=True, separators=(",", ":")),
            quote=True,
        )
        lines.extend([
            "    <properties>",
            f'      <property name="evaluation_manifest.schema_version" value="{manifest_schema}" />',
            f'      <property name="evaluation_manifest.path" value="{manifest_path}" />',
            f'      <property name="evaluation_manifest.sha256" value="{manifest_hash}" />',
            f'      <property name="evaluation_manifest.selected_inputs" value="{selected_inputs}" />',
            "    </properties>",
        ])
    for result in report.get("results", []):
        case_id = _xml_escape(result.get("id", "unknown"), quote=True)
        classname = _xml_escape(result.get("category", "agent_security_bench"), quote=True)
        score = _xml_escape(result.get("score", 0.0), quote=True)
        lines.append(f'    <testcase classname="{classname}" name="{case_id}" assertions="1" score="{score}">')
        if not result.get("passed"):
            violations = "; ".join(
                f"{item.get('type', 'violation')}:{item.get('pattern', '')}" for item in result.get("violations", [])
            ) or str(result.get("expected_behavior", "benchmark case failed"))
            message = _xml_escape(violations, quote=True)
            body = _xml_escape(result, quote=False)
            lines.append(f'      <failure message="{message}" type="agent-security-bench">{body}</failure>')
        lines.append("    </testcase>")
    lines.extend(["  </testsuite>", "</testsuites>"])
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
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "agent-security-bench",
                "informationUri": "https://github.com/mattpartida/agent-security-bench",
                "rules": rules,
            }
        },
        "results": results,
    }
    if report.get("evaluation_manifest"):
        run["properties"] = {"evaluation_manifest": report["evaluation_manifest"]}
    return {
        "$schema": "https://json.schemastore.org/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
