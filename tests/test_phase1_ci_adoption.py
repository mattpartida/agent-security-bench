import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from agent_security_bench.cases import built_in_cases
from agent_security_bench.cli import run
from agent_security_bench.runner import run_benchmark

ROOT = Path(__file__).resolve().parents[1]


class Phase1CiAdoptionTests(unittest.TestCase):
    def test_junit_report_renders_passed_and_failed_cases(self):
        report = run_benchmark({})

        from agent_security_bench.reports import render_junit

        xml_text = render_junit(report)
        root = ET.fromstring(xml_text)

        self.assertEqual(root.tag, "testsuites")
        suite = root.find("testsuite")
        self.assertIsNotNone(suite)
        self.assertEqual(suite.attrib["name"], "agent-security-bench")
        self.assertEqual(int(suite.attrib["tests"]), report["summary"]["total"])
        self.assertEqual(int(suite.attrib["failures"]), report["summary"]["failed"])
        failed_case = suite.find("testcase/failure")
        self.assertIsNotNone(failed_case)
        self.assertIn("missing_response", failed_case.attrib["message"])

    def test_cli_supports_junit_min_score_and_fail_on_failures(self):
        responses = {case.id: "I refuse unsafe instructions and require confirmation." for case in built_in_cases()}
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_path = Path(tmpdir) / "safe.json"
            unsafe_path = Path(tmpdir) / "unsafe.json"
            safe_path.write_text(json.dumps(responses), encoding="utf-8")
            unsafe_path.write_text(json.dumps({}), encoding="utf-8")

            junit_code, junit_output = run(["score", str(safe_path), "--format", "junit"])
            min_score_code, min_score_output = run(["score", str(unsafe_path), "--min-score", "0.9"])
            failures_code, failures_output = run(["score", str(unsafe_path), "--fail-on-failures"])

        self.assertEqual(junit_code, 0)
        self.assertEqual(ET.fromstring(junit_output).tag, "testsuites")
        self.assertEqual(min_score_code, 1)
        self.assertIn('"thresholds"', min_score_output)
        self.assertIn('"min_score"', min_score_output)
        self.assertEqual(failures_code, 1)
        self.assertIn('"fail_on_failures"', failures_output)

    def test_combined_regression_and_threshold_failures_preserve_all_metadata(self):
        current = run_benchmark({})
        baseline = {"summary": {"score": 1.0, "passed": current["summary"]["total"], "failed": 0}}
        with tempfile.TemporaryDirectory() as tmpdir:
            current_path = Path(tmpdir) / "current.json"
            baseline_path = Path(tmpdir) / "baseline.json"
            current_path.write_text(json.dumps(current), encoding="utf-8")
            baseline_path.write_text(json.dumps(baseline), encoding="utf-8")

            code, output = run(
                [
                    "score",
                    str(current_path),
                    "--baseline",
                    str(baseline_path),
                    "--fail-on-regression",
                    "--min-score",
                    "0.9",
                    "--fail-on-failures",
                ]
            )

        parsed = json.loads(output)
        self.assertEqual(code, 1)
        self.assertTrue(parsed["regression"]["regressed"])
        self.assertTrue(parsed["thresholds"]["failed"])
        self.assertEqual(parsed["thresholds"]["min_score"], 0.9)
        self.assertEqual(parsed["thresholds"]["failed_cases"], current["summary"]["failed"])

    def test_junit_report_sanitizes_xml_illegal_control_characters(self):
        report = {
            "benchmark_version": "0.3.0",
            "summary": {"total": 1, "passed": 0, "failed": 1, "score": 0.0},
            "results": [
                {
                    "id": "bad\bcase",
                    "category": "data\bexfiltration",
                    "passed": False,
                    "score": 0.0,
                    "violations": [{"type": "forbidden\bpattern", "pattern": "secret\bleak"}],
                }
            ],
        }

        from agent_security_bench.reports import render_junit

        root = ET.fromstring(render_junit(report))
        self.assertEqual(root.tag, "testsuites")

    def test_phase1_roadmap_and_github_actions_example_are_present(self):
        roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
        self.assertIn("# agent-security-bench Roadmap", roadmap)
        self.assertIn("## Phase 1 — CI adoption pack", roadmap)
        self.assertIn("**Status:** Shipped", roadmap)
        self.assertIn("JUnit XML", roadmap)
        self.assertIn("score thresholds", roadmap)

        workflow = (ROOT / "examples" / "github-actions" / "agent-security-bench.yml").read_text(encoding="utf-8")
        self.assertIn("name: Agent Security Bench", workflow)
        self.assertIn("security-events: write", workflow)
        self.assertIn("agent-security-bench score", workflow)
        self.assertIn("--format sarif", workflow)
        self.assertIn("github/codeql-action/upload-sarif@v4", workflow)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", workflow)
        self.assertIn("--format junit", workflow)


if __name__ == "__main__":
    unittest.main()
