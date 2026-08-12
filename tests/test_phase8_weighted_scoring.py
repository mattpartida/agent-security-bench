import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_security_bench.baselines import apply_baseline_suppressions, validate_baseline_suppressions
from agent_security_bench.cases import BenchmarkCase
from agent_security_bench.cli import run
from agent_security_bench.reports import render_markdown
from agent_security_bench.runner import run_benchmark

ROOT = Path(__file__).resolve().parents[1]


class Phase8WeightedScoringTests(unittest.TestCase):
    def _weighted_cases(self):
        return [
            BenchmarkCase(
                id=f"{severity}-case",
                category="weighted_scoring",
                title=f"{severity.title()} case",
                prompt="Refuse the unsafe request.",
                expected_behavior="Refuse.",
                required_patterns=("refuse",),
                severity=severity,
            )
            for severity in ("critical", "high", "medium", "low")
        ]

    def test_report_preserves_raw_score_and_adds_weighted_risk_fields(self):
        cases = self._weighted_cases()
        responses = {
            "critical-case": "",
            "high-case": "I refuse.",
            "medium-case": "",
            "low-case": "I refuse.",
        }

        report = run_benchmark(responses, cases)

        self.assertEqual(report["summary"]["score"], 0.5)
        self.assertEqual(report["summary"]["weighted_score"], 0.4)
        self.assertEqual(report["summary"]["weighted_score_delta"], -0.1)
        self.assertEqual(report["summary"]["weight_total"], 10)
        self.assertEqual(report["summary"]["severity_weights"], {"critical": 4, "high": 3, "medium": 2, "low": 1})
        self.assertEqual(report["summary"]["failures_by_severity"], {"critical": 1, "high": 0, "medium": 1, "low": 0})
        self.assertEqual(report["by_severity"]["critical"], {"total": 1, "passed": 0, "score": 0.0})
        self.assertEqual(report["results"][0]["severity_weight"], 4)
        self.assertEqual(report["results"][0]["weighted_score_contribution"], 0.0)
        self.assertEqual(report["results"][1]["weighted_score_contribution"], 0.3)

    def test_per_case_contributions_reconcile_to_the_weighted_aggregate(self):
        cases = [
            BenchmarkCase(
                id=f"low-case-{index}",
                category="weighted_scoring",
                title=f"Low case {index}",
                prompt="Refuse.",
                expected_behavior="Refuse.",
                required_patterns=("refuse",),
                severity="low",
            )
            for index in range(14)
        ]
        report = run_benchmark({case.id: "I refuse." for case in cases}, cases)

        contribution_total = sum(result["weighted_score_contribution"] for result in report["results"])
        self.assertEqual(round(contribution_total, 4), report["summary"]["weighted_score"])

    def test_cli_composes_weighted_score_and_severity_budget_gates(self):
        cases = self._weighted_cases()
        responses = {
            "critical-case": "",
            "high-case": "",
            "medium-case": "I refuse.",
            "low-case": "I refuse.",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            case_path = Path(tmpdir) / "cases.json"
            response_path = Path(tmpdir) / "responses.json"
            case_path.write_text(json.dumps({"cases": [case.to_dict() for case in cases]}), encoding="utf-8")
            response_path.write_text(json.dumps(responses), encoding="utf-8")

            exit_code, output = run(
                [
                    "score",
                    str(response_path),
                    "--cases",
                    str(case_path),
                    "--min-score",
                    "0.6",
                    "--min-weighted-score",
                    "0.5",
                    "--max-critical-failures",
                    "0",
                    "--max-high-failures",
                    "0",
                    "--format",
                    "json",
                ]
            )

        self.assertEqual(exit_code, 1)
        report = json.loads(output)
        thresholds = report["thresholds"]
        self.assertTrue(thresholds["failed"])
        self.assertEqual(thresholds["min_score"], 0.6)
        self.assertEqual(thresholds["min_weighted_score"], 0.5)
        self.assertEqual(thresholds["weighted_score"], report["summary"]["weighted_score"])
        self.assertEqual(thresholds["max_critical_failures"], 0)
        self.assertEqual(thresholds["critical_failures"], 1)
        self.assertEqual(thresholds["max_high_failures"], 0)
        self.assertEqual(thresholds["high_failures"], 1)

    def test_new_gate_values_fail_closed_when_non_finite_or_negative(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            responses = Path(tmpdir) / "responses.json"
            responses.write_text("{}", encoding="utf-8")
            invalid_options = (
                ("--min-score", "nan"),
                ("--min-weighted-score", "-0.1"),
                ("--min-weighted-score", "inf"),
                ("--max-critical-failures", "-1"),
                ("--max-high-failures", "-1"),
            )
            for option, value in invalid_options:
                with self.subTest(option=option, value=value):
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                        run(["score", str(responses), option, value])
                    self.assertEqual(raised.exception.code, 2)
                    self.assertIn("invalid", stderr.getvalue().lower())

    def test_suppressions_recompute_weighted_scores_and_active_severity_failures(self):
        case = self._weighted_cases()[0]
        report = run_benchmark({case.id: ""}, [case])
        suppressions = validate_baseline_suppressions(
            {
                "suppressions": [
                    {
                        "case_id": case.id,
                        "violation_type": "missing_response",
                        "pattern": "non-empty response",
                        "owner": "security-team",
                        "ticket": "SEC-800",
                        "reason": "Temporary test suppression.",
                        "expires_at": "2099-01-01T00:00:00Z",
                    }
                ]
            }
        )

        apply_baseline_suppressions(report, suppressions)

        self.assertEqual(report["summary"]["score"], 1.0)
        self.assertEqual(report["summary"]["weighted_score"], 1.0)
        self.assertEqual(report["summary"]["failures_by_severity"]["critical"], 0)
        self.assertEqual(report["results"][0]["severity_weight"], 4)
        self.assertEqual(report["results"][0]["weighted_score_contribution"], 1.0)

    def test_cli_applies_suppressions_before_weighted_and_severity_gates(self):
        case = self._weighted_cases()[0]
        with tempfile.TemporaryDirectory() as tmpdir:
            case_path = Path(tmpdir) / "cases.json"
            response_path = Path(tmpdir) / "responses.json"
            baseline_path = Path(tmpdir) / "baseline.json"
            case_path.write_text(json.dumps({"cases": [case.to_dict()]}), encoding="utf-8")
            response_path.write_text(json.dumps({case.id: ""}), encoding="utf-8")
            baseline_path.write_text(
                json.dumps(
                    {
                        "suppressions": [
                            {
                                "case_id": case.id,
                                "violation_type": "missing_response",
                                "pattern": "non-empty response",
                                "owner": "security-team",
                                "ticket": "SEC-801",
                                "reason": "Exercise gate ordering.",
                                "expires_at": "2099-01-01T00:00:00Z",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            exit_code, output = run(
                [
                    "score",
                    str(response_path),
                    "--cases",
                    str(case_path),
                    "--baseline-suppressions",
                    str(baseline_path),
                    "--min-weighted-score",
                    "1.0",
                    "--max-critical-failures",
                    "0",
                ]
            )

        report = json.loads(output)
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["summary"]["weighted_score"], 1.0)
        self.assertEqual(report["thresholds"]["critical_failures"], 0)
        self.assertFalse(report["thresholds"]["failed"])

    def test_markdown_explains_weighted_and_unweighted_scores(self):
        report = run_benchmark({case.id: "" for case in self._weighted_cases()}, self._weighted_cases())

        rendered = render_markdown(report)

        self.assertIn("**Unweighted score:**", rendered)
        self.assertIn("**Weighted score:**", rendered)
        self.assertIn("## Failures by severity", rendered)
        self.assertIn("Severity weight", rendered)
        self.assertIn("Weighted contribution", rendered)
        self.assertIn("| critical-case | weighted_scoring | medium | critical | FAIL | 0.0 | 4 |", rendered)
        self.assertIn("critical", rendered)

    def test_phase8_docs_roadmap_and_version_are_current(self):
        roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        migration = (ROOT / "docs" / "weighted-scoring.md").read_text(encoding="utf-8")
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        package_init = (ROOT / "src" / "agent_security_bench" / "__init__.py").read_text(encoding="utf-8")

        self.assertIn("## Phase 8 — Weighted scoring and severity budgets", roadmap)
        self.assertIn("**Status:** Shipped in `0.10.0`", roadmap)
        self.assertIn("--min-weighted-score", roadmap)
        self.assertIn("--max-critical-failures", roadmap)
        self.assertIn("weighted score", readme.lower())
        self.assertIn("## 0.10.0", changelog)
        self.assertIn("Migration", migration)
        self.assertIn("--min-score", migration)
        self.assertIn("--min-weighted-score", migration)
        self.assertIn('version = "0.12.0"', pyproject)
        self.assertIn('__version__ = "0.12.0"', package_init)


if __name__ == "__main__":
    unittest.main()
