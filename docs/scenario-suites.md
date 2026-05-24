# Scenario suites

Scenario suites group benchmark cases into named subsets so teams can run quick PR checks, stricter release gates, and full nightly regressions without maintaining custom case lists.

## Built-in suites

| Suite | Intended use | Contents |
| --- | --- | --- |
| `smoke` | Fast PR checks and local sanity checks | A small cross-section of direct injection, secret exfiltration, tool misuse, and approval-bypass cases. |
| `release` | Release gates for high-risk behavior | Cases with `high` or `critical` severity. |
| `exfiltration` | Focused data-leak prevention checks | Data exfiltration, canary exfiltration, and cases tagged `exfiltration`. |
| `tool-use` | Tool-safety checks | Cases in the `tool_misuse` category or tagged `tool-use`. |
| `full` | Nightly or pre-release regressions | Every selected case. |

## CLI usage

All commands that load cases accept `--suite <name>`:

```bash
PYTHONPATH=src python -m agent_security_bench.cli list --suite smoke --format json
PYTHONPATH=src python -m agent_security_bench.cli score examples/safe-responses.json --suite release --fail-on-failures
PYTHONPATH=src python -m agent_security_bench.cli run --adapter dry-run --suite tool-use --format json
PYTHONPATH=src python -m agent_security_bench.cli lint-cases --suite full --format json
PYTHONPATH=src python -m agent_security_bench.cli coverage --suite exfiltration --format json
```

Unknown suite names fail closed with a machine-readable error and the list of available suites.

## Report metadata

When `--suite` is used, JSON outputs include a top-level `suite` object:

```json
{
  "suite": {
    "name": "smoke",
    "case_count": 4
  }
}
```

`list`, `score`, and `run` also include each case/result's `suites` membership. `coverage` includes aggregate suite counts so reviewers can see whether a filtered corpus still spans the expected scenario groups.

## CI guidance

- Use `smoke` on every pull request when benchmark runtime must stay short.
- Use `release` with `--fail-on-failures` and score thresholds for merge or release candidates.
- Use `exfiltration` and `tool-use` for targeted remediation branches.
- Use `full` for nightly checks and before publishing benchmark releases.
