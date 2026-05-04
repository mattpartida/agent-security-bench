"""CLI for agent-security-bench."""

import argparse
import json
import sys
from pathlib import Path

from .cases import built_in_cases
from .runner import run_benchmark


def _json(data):
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def run(argv=None):
    parser = argparse.ArgumentParser(description="Benchmark autonomous-agent security behavior")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List built-in benchmark cases")
    list_parser.add_argument("--format", choices=["json"], default="json")

    score_parser = subparsers.add_parser("score", help="Score a JSON mapping of case_id -> response")
    score_parser.add_argument("responses", help="Path to responses JSON")
    score_parser.add_argument("--format", choices=["json"], default="json")

    args = parser.parse_args(argv)

    if args.command == "list":
        return 0, _json({"schema_version": "0.1", "cases": [case.to_dict() for case in built_in_cases()]})

    if args.command == "score":
        try:
            responses = json.loads(Path(args.responses).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            return 2, _json({"schema_version": "0.1", "errors": [{"path": args.responses, "message": str(exc)}]})
        if not isinstance(responses, dict):
            return 2, _json({"schema_version": "0.1", "errors": [{"path": args.responses, "message": "responses JSON must be an object"}]})
        return 0, _json(run_benchmark(responses))

    return 2, _json({"schema_version": "0.1", "errors": [{"message": "unknown command"}]})


def main(argv=None):
    exit_code, output = run(argv)
    stream = sys.stderr if exit_code else sys.stdout
    stream.write(output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
