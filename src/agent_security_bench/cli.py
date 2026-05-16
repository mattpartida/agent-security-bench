"""CLI for agent-security-bench."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapters import adapter_names, collect_transcripts, list_adapters
from .baselines import apply_baseline_suppressions, validate_baseline_suppressions
from .cases import built_in_cases, load_cases
from .governance import corpus_coverage_report, lint_cases
from .reports import render_junit, render_markdown, render_sarif
from .runner import compare_to_baseline, run_benchmark


def _json(data):
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _render_report(report, fmt):
    if fmt == "markdown":
        return render_markdown(report) + "\n"
    if fmt == "sarif":
        return _json(render_sarif(report))
    if fmt == "junit":
        return render_junit(report) + "\n"
    return _json(report)


def _apply_thresholds(report, *, min_score=None, fail_on_failures=False):
    """Attach threshold metadata and return whether the report failed policy."""

    threshold = {"failed": False}
    if min_score is not None:
        current_score = float(report.get("summary", {}).get("score", 0.0))
        threshold["min_score"] = float(min_score)
        threshold["score"] = current_score
        if current_score < float(min_score):
            threshold["failed"] = True
    if fail_on_failures:
        failed_cases = int(report.get("summary", {}).get("failed", 0))
        threshold["fail_on_failures"] = True
        threshold["failed_cases"] = failed_cases
        if failed_cases > 0:
            threshold["failed"] = True
    if len(threshold) > 1:
        report["thresholds"] = threshold
    return bool(threshold["failed"])


def run(argv=None):
    parser = argparse.ArgumentParser(description="Benchmark autonomous-agent security behavior")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List benchmark cases")
    list_parser.add_argument("--cases", help="Optional JSON/JSONL/YAML case file")
    list_parser.add_argument("--format", choices=["json"], default="json")

    score_parser = subparsers.add_parser("score", help="Score a JSON mapping of case_id -> response")
    score_parser.add_argument("responses", help="Path to responses JSON")
    score_parser.add_argument("--cases", help="Optional JSON/JSONL/YAML case file")
    score_parser.add_argument("--transcripts", action="store_true", help="treat responses as case_id -> transcript objects")
    score_parser.add_argument("--format", choices=["json", "markdown", "sarif", "junit"], default="json")
    score_parser.add_argument("--baseline", help="Optional baseline report for regression comparison")
    score_parser.add_argument("--fail-on-regression", action="store_true", help="exit non-zero if current score regresses from baseline")
    score_parser.add_argument("--min-score", type=float, help="exit non-zero if the benchmark score is below this value")
    score_parser.add_argument("--fail-on-failures", action="store_true", help="exit non-zero if any benchmark case fails")
    score_parser.add_argument("--baseline-suppressions", help="JSON file of auditable case/violation suppressions")
    score_parser.add_argument(
        "--fail-on-expired-suppressions",
        action="store_true",
        help="exit non-zero when baseline suppressions have expired",
    )
    score_parser.add_argument(
        "--fail-on-stale-suppressions",
        action="store_true",
        help="exit non-zero when baseline suppressions no longer match active failures",
    )

    adapters_parser = subparsers.add_parser("adapters", help="List live-agent adapter specs")
    adapters_parser.add_argument("--format", choices=["json"], default="json")

    lint_parser = subparsers.add_parser("lint-cases", help="Validate benchmark case corpus quality")
    lint_parser.add_argument("--cases", help="Optional JSON/JSONL/YAML case file")
    lint_parser.add_argument("--format", choices=["json"], default="json")

    coverage_parser = subparsers.add_parser("coverage", help="Summarize benchmark corpus coverage")
    coverage_parser.add_argument("--cases", help="Optional JSON/JSONL/YAML case file")
    coverage_parser.add_argument("--format", choices=["json"], default="json")

    run_parser = subparsers.add_parser("run", help="Run cases through a live-agent adapter")
    run_parser.add_argument("--adapter", choices=adapter_names(), default="dry-run")
    run_parser.add_argument("--cases", help="Optional JSON/JSONL/YAML case file")
    run_parser.add_argument("--sandbox", action="store_true", help="confirm adapter execution is sandboxed")
    run_parser.add_argument("--mock-transcripts", help="JSON fixture for the mock transcript adapter")
    run_parser.add_argument("--format", choices=["json", "markdown", "sarif"], default="json")

    regression_parser = subparsers.add_parser("regression", help="Compare a current report against a baseline report")
    regression_parser.add_argument("current", help="Current report JSON")
    regression_parser.add_argument("--baseline", required=True, help="Baseline report JSON")
    regression_parser.add_argument("--fail-on-regression", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "list":
        try:
            cases = load_cases(args.cases) if args.cases else built_in_cases()
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return 2, _json({"schema_version": "0.2", "errors": [{"path": args.cases, "message": str(exc)}]})
        return 0, _json({"schema_version": "0.2", "cases": [case.to_dict() for case in cases]})

    if args.command == "adapters":
        return 0, _json({"schema_version": "0.2", "adapters": [adapter.to_dict() for adapter in list_adapters()]})

    if args.command == "lint-cases":
        try:
            cases = load_cases(args.cases) if args.cases else built_in_cases()
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return 2, _json({"schema_version": "0.2", "errors": [{"path": args.cases, "message": str(exc)}]})
        report = lint_cases(cases)
        return (1 if report["summary"]["error_count"] else 0), _json(report)

    if args.command == "coverage":
        try:
            cases = load_cases(args.cases) if args.cases else built_in_cases()
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return 2, _json({"schema_version": "0.2", "errors": [{"path": args.cases, "message": str(exc)}]})
        return 0, _json(corpus_coverage_report(cases))

    if args.command == "run":
        try:
            cases = load_cases(args.cases) if args.cases else built_in_cases()
            mock_data = _load_json(args.mock_transcripts) if args.mock_transcripts else None
            transcripts = collect_transcripts(args.adapter, cases, sandbox=args.sandbox, mock_data=mock_data)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return 2, _json({"schema_version": "0.2", "errors": [{"path": args.cases or args.mock_transcripts, "message": str(exc)}]})
        report = run_benchmark(transcripts, cases, transcript_mode=True)
        report["adapter"] = {"name": args.adapter, "sandboxed": bool(args.sandbox or args.adapter == "dry-run")}
        return 0, _render_report(report, args.format)

    if args.command == "score":
        try:
            cases = load_cases(args.cases) if args.cases else built_in_cases()
            responses = _load_json(args.responses)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return 2, _json({"schema_version": "0.2", "errors": [{"path": args.responses, "message": str(exc)}]})
        if not isinstance(responses, dict):
            return 2, _json({"schema_version": "0.2", "errors": [{"path": args.responses, "message": "responses JSON must be an object"}]})
        report = run_benchmark(responses, cases, transcript_mode=args.transcripts)
        baseline_suppression_failed = False
        if args.baseline_suppressions:
            try:
                baseline_suppression_data = _load_json(args.baseline_suppressions)
                baseline_suppressions = validate_baseline_suppressions(baseline_suppression_data)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                return 2, _json({"schema_version": "0.2", "errors": [{"path": args.baseline_suppressions, "message": str(exc)}]})
            apply_baseline_suppressions(report, baseline_suppressions)
            suppression_summary = report.get("baseline_suppression_summary", {})
            baseline_suppression_failed = bool(
                (args.fail_on_expired_suppressions and suppression_summary.get("expired", 0) > 0)
                or (args.fail_on_stale_suppressions and suppression_summary.get("stale", 0) > 0)
            )
        regression_failed = False
        if args.baseline:
            try:
                baseline = _load_json(args.baseline)
            except (OSError, json.JSONDecodeError) as exc:
                return 2, _json({"schema_version": "0.2", "errors": [{"path": args.baseline, "message": str(exc)}]})
            report["regression"] = compare_to_baseline(report, baseline)
            regression_failed = bool(args.fail_on_regression and report["regression"]["regressed"])
        threshold_failed = _apply_thresholds(report, min_score=args.min_score, fail_on_failures=args.fail_on_failures)
        return (1 if regression_failed or threshold_failed or baseline_suppression_failed else 0), _render_report(report, args.format)

    if args.command == "regression":
        try:
            current = _load_json(args.current)
            baseline = _load_json(args.baseline)
        except (OSError, json.JSONDecodeError) as exc:
            return 2, _json({"schema_version": "0.2", "errors": [{"message": str(exc)}]})
        comparison = compare_to_baseline(current, baseline)
        return (1 if args.fail_on_regression and comparison["regressed"] else 0), _json(comparison)

    return 2, _json({"schema_version": "0.2", "errors": [{"message": "unknown command"}]})


def main(argv=None):
    exit_code, output = run(argv)
    stream = sys.stderr if exit_code not in {0, 1} else sys.stdout
    stream.write(output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
