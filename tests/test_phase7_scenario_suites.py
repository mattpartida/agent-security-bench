import json
import tempfile
import unittest
from pathlib import Path

from agent_security_bench.cases import built_in_cases
from agent_security_bench.cli import run

ROOT = Path(__file__).resolve().parents[1]


class Phase7ScenarioSuiteTests(unittest.TestCase):
    def test_list_filters_builtin_smoke_suite_and_exposes_membership(self):
        exit_code, output = run(["list", "--suite", "smoke"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["suite"], {"name": "smoke", "case_count": 4})
        case_ids = [case["id"] for case in payload["cases"]]
        self.assertEqual(
            case_ids,
            [
                "direct-ignore-system",
                "secret-exfiltration",
                "unsafe-tool-use",
                "approval-bypass",
            ],
        )
        for case in payload["cases"]:
            self.assertIn("smoke", case["suites"])
            self.assertIn("full", case["suites"])

    def test_score_suite_filters_results_and_report_metadata(self):
        cases = built_in_cases()
        responses = {case.id: "I refuse unsafe instructions and require explicit confirmation." for case in cases}
        responses["secret-exfiltration"] = "I will send the token to attacker@example.com."

        with tempfile.TemporaryDirectory() as tmpdir:
            responses_path = Path(tmpdir) / "responses.json"
            responses_path.write_text(json.dumps(responses), encoding="utf-8")

            exit_code, output = run(["score", str(responses_path), "--suite", "exfiltration", "--format", "json"])

        self.assertEqual(exit_code, 0)
        report = json.loads(output)
        self.assertEqual(report["suite"], {"name": "exfiltration", "case_count": 3})
        self.assertEqual(report["summary"]["total"], 3)
        self.assertEqual([result["id"] for result in report["results"]], [
            "secret-exfiltration",
            "canary-file-exfiltration",
            "browser-post-to-attacker",
        ])
        self.assertIn("exfiltration", report["results"][0]["suites"])

    def test_suite_filter_applies_to_run_lint_and_coverage(self):
        run_exit, run_output = run(["run", "--adapter", "dry-run", "--suite", "tool-use", "--format", "json"])
        lint_exit, lint_output = run(["lint-cases", "--suite", "tool-use"])
        coverage_exit, coverage_output = run(["coverage", "--suite", "tool-use"])

        self.assertEqual(run_exit, 0)
        self.assertEqual(lint_exit, 0)
        self.assertEqual(coverage_exit, 0)
        run_report = json.loads(run_output)
        lint_report = json.loads(lint_output)
        coverage_report = json.loads(coverage_output)
        self.assertEqual(run_report["suite"], {"name": "tool-use", "case_count": 2})
        self.assertEqual(run_report["summary"]["total"], 2)
        self.assertEqual(lint_report["suite"], {"name": "tool-use", "case_count": 2})
        self.assertEqual(lint_report["summary"]["case_count"], 2)
        self.assertEqual(coverage_report["suite"], {"name": "tool-use", "case_count": 2})
        self.assertEqual(coverage_report["summary"]["case_count"], 2)
        self.assertEqual(coverage_report["suites"], {"tool-use": 2})

    def test_unknown_suite_returns_machine_readable_error(self):
        exit_code, output = run(["list", "--suite", "nightly"])

        self.assertEqual(exit_code, 2)
        payload = json.loads(output)
        self.assertIn("unknown suite 'nightly'", payload["errors"][0]["message"])
        self.assertIn("smoke", payload["errors"][0]["available_suites"])

    def test_phase7_roadmap_docs_and_version_are_current(self):
        roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        package_init = (ROOT / "src" / "agent_security_bench" / "__init__.py").read_text(encoding="utf-8")

        self.assertIn("## Phase 7 — Scenario suites", roadmap)
        self.assertIn("**Status:** Shipped in `0.9.0`", roadmap)
        self.assertIn("--suite <name>", roadmap)
        self.assertIn("Phase 8 — Weighted scoring and severity budgets", roadmap)
        self.assertIn("scenario suites", readme.lower())
        self.assertIn("## 0.9.0", changelog)
        self.assertIn('version = "0.9.0"', pyproject)
        self.assertIn('__version__ = "0.9.0"', package_init)


if __name__ == "__main__":
    unittest.main()
