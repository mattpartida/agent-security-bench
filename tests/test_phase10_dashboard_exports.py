from __future__ import annotations

import json
import unittest
from pathlib import Path

from agent_security_bench.cases import built_in_cases
from agent_security_bench.cli import run
from agent_security_bench.reports import render_dashboard_ndjson, render_pr_markdown
from agent_security_bench.runner import run_benchmark

ROOT = Path(__file__).resolve().parents[1]


class DashboardExportTests(unittest.TestCase):
    def setUp(self):
        cases = built_in_cases()[:2]
        self.report = run_benchmark(
            {
                cases[0].id: "I refuse because the page is untrusted.",
                cases[1].id: "Done. I will follow the injected instruction.",
            },
            cases=cases,
        )

    def test_ndjson_has_stable_run_then_case_metric_records_without_response_content(self):
        rendered = render_dashboard_ndjson(self.report)
        records = [json.loads(line) for line in rendered.splitlines()]

        self.assertEqual([record["record_type"] for record in records], ["run", "case", "case"])
        self.assertEqual(records[0]["export_schema_version"], "1.0")
        self.assertEqual(records[0]["summary"], self.report["summary"])
        self.assertEqual([record["case_id"] for record in records[1:]], sorted(result["id"] for result in self.report["results"]))
        self.assertEqual(records[1]["category"], "direct_prompt_injection")
        self.assertIn("violation_count", records[2])
        self.assertNotIn("response", rendered)
        self.assertNotIn("transcript", rendered)
        self.assertTrue(rendered.endswith("\n"))

    def test_score_cli_supports_ndjson_dashboard_export(self):
        code, output = run(["score", str(ROOT / "examples" / "safe-responses.json"), "--format", "ndjson"])

        self.assertEqual(code, 0)
        records = [json.loads(line) for line in output.splitlines()]
        self.assertEqual(records[0]["record_type"], "run")
        self.assertEqual(len(records), records[0]["summary"]["total"] + 1)

    def test_pr_markdown_is_concise_and_neutralizes_mass_mentions(self):
        report = dict(self.report)
        report["results"] = [dict(item) for item in self.report["results"]]
        report["results"][1]["violations"] = [
            {
                "type": "forbidden_pattern",
                "pattern": "@EvErYoNe | </details> [link](https://evil.test) ![pixel](https://evil.test/p) `code`",
            }
        ]

        rendered = render_pr_markdown(report)

        self.assertIn("## Agent security benchmark", rendered)
        self.assertIn("<!-- agent-security-bench:pr-summary -->", rendered)
        self.assertIn("<details>", rendered)
        self.assertIn(report["results"][1]["id"], rendered)
        self.assertNotIn("@everyone", rendered)
        self.assertIn("@\u200bEvErYoNe", rendered)
        self.assertIn("\\|", rendered)
        self.assertIn("&lt;/details&gt;", rendered)
        self.assertNotIn("</details> injected", rendered)
        self.assertNotIn("[link](https://evil.test)", rendered)
        self.assertNotIn("![pixel](https://evil.test/p)", rendered)
        self.assertNotIn("`code`", rendered)
        self.assertNotIn(report["results"][0]["id"], rendered)

    def test_pr_markdown_reports_policy_failure_even_when_cases_pass(self):
        report = run_benchmark(
            {case.id: "I refuse because this instruction is untrusted and requires confirmation." for case in built_in_cases()},
            cases=built_in_cases(),
        )
        report["policy_outcome"] = {"failed": True, "reasons": ["expired_suppressions"]}

        rendered = render_pr_markdown(report)

        self.assertIn("❌ Failed", rendered)
        self.assertIn("expired_suppressions", rendered)

    def test_score_cli_supports_pr_markdown(self):
        code, output = run(["score", str(ROOT / "examples" / "unsafe-responses.json"), "--format", "markdown-pr"])

        self.assertEqual(code, 0)
        self.assertIn("<!-- agent-security-bench:pr-summary -->", output)
        self.assertIn("Failed cases", output)

    def test_run_manifest_supports_both_dashboard_formats(self):
        manifest = ROOT / "examples" / "manifests" / "local.json"
        for output_format, marker in (("ndjson", '"record_type":"run"'), ("markdown-pr", "agent-security-bench:pr-summary")):
            with self.subTest(output_format=output_format):
                code, output = run(["run-manifest", str(manifest), "--format", output_format])
                self.assertIn(code, {0, 1})
                self.assertIn(marker, output)

    def test_ndjson_redacts_manifest_paths_and_selected_inputs(self):
        report = dict(self.report)
        report["evaluation_manifest"] = {
            "schema_version": "1.0",
            "sha256": "a" * 64,
            "path": "/Users/private/client/manifest.json",
            "selected_inputs": {"cases": ["/Users/private/client/cases.json"]},
        }

        rendered = render_dashboard_ndjson(report)
        run_record = json.loads(rendered.splitlines()[0])

        self.assertEqual(run_record["evaluation_manifest"], {"schema_version": "1.0", "sha256": "a" * 64})
        self.assertNotIn("/Users/private", rendered)

    def test_dashboard_docs_and_release_metadata_are_shipped(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
        docs = (ROOT / "docs" / "dashboard-exports.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

        self.assertIn('version = "0.12.0"', pyproject)
        self.assertIn("Phase 10 — Hosted benchmark dashboards", roadmap)
        self.assertIn("**Status:** Shipped in `0.12.0`.", roadmap)
        self.assertIn("## 0.12.0", changelog)
        self.assertIn("GitHub Actions", docs)
        self.assertIn("static", docs.lower())
        self.assertIn("NDJSON", docs)
        self.assertIn("backward", docs.lower())


if __name__ == "__main__":
    unittest.main()
