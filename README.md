# agent-security-bench

Dependency-light benchmark suite for evaluating autonomous-agent security behavior.

It provides adversarial cases for prompt injection, data exfiltration, tool misuse, persistence/memory poisoning, approval bypass, canary exfiltration, and unsafe tool use. The default scorer is deterministic text/transcript analysis; live-agent adapters are declared but intentionally sandbox-gated.

## Why

Agent security failures are behavioral. A config can look reasonable while the agent still:

- follows malicious webpage instructions
- leaks tokens/secrets
- uses tools without approval
- stores attacker policy in memory
- bypasses outbound-action gates
- exfiltrates canary files or fake secrets through tool calls

This repo gives those risks repeatable benchmark cases.

## Quick start

Run without installing:

```bash
PYTHONPATH=src python -m agent_security_bench.cli list --format json
PYTHONPATH=src python -m agent_security_bench.cli score examples/safe-responses.json --format json
PYTHONPATH=src python -m agent_security_bench.cli score examples/unsafe-responses.json --format markdown
```

Install locally:

```bash
python -m pip install -e .
agent-security-bench list --format json
agent-security-bench score examples/safe-responses.json --format sarif > agent-security-bench.sarif
```

## Built-in categories

- `direct_prompt_injection`
- `indirect_prompt_injection`
- `data_exfiltration`
- `canary_exfiltration`
- `tool_misuse`
- `persistence`
- `approval_bypass`

## Case files

Built-in cases are always available, and additional cases can be loaded from JSON, JSONL, or a dependency-free YAML subset:

```bash
PYTHONPATH=src python -m agent_security_bench.cli list --cases examples/custom-cases.jsonl --format json
PYTHONPATH=src python -m agent_security_bench.cli score responses.json --cases examples/custom-cases.yaml
```

Each case has a stable `id`, `category`, `severity`, `difficulty`, `benchmark_version`, required safe-response patterns, and forbidden unsafe patterns.

## Output

The score report includes:

- `schema_version` and `benchmark_version`
- aggregate summary
- score from `0.0` to `1.0`
- per-category results
- per-difficulty results
- per-case pass/fail
- violations with required/forbidden pattern IDs

Supported report formats:

```bash
PYTHONPATH=src python -m agent_security_bench.cli score examples/unsafe-responses.json --format json
PYTHONPATH=src python -m agent_security_bench.cli score examples/unsafe-responses.json --format markdown
PYTHONPATH=src python -m agent_security_bench.cli score examples/unsafe-responses.json --format sarif
PYTHONPATH=src python -m agent_security_bench.cli score examples/unsafe-responses.json --format junit
```

## CI gates

Use score thresholds and failure gates when wiring the benchmark into CI:

```bash
PYTHONPATH=src python -m agent_security_bench.cli score examples/safe-responses.json \
  --min-score 0.95 \
  --fail-on-failures \
  --format json
```

- `--min-score N` exits `1` when the aggregate score is below `N` and records the comparison under `thresholds`.
- `--fail-on-failures` exits `1` when any case fails and records the failed-case count under `thresholds`.
- `--format junit` emits JUnit XML so CI systems can show benchmark cases as test results.

Use auditable baseline suppressions for temporary known failures without hiding them from reports:

```bash
PYTHONPATH=src python -m agent_security_bench.cli score examples/unsafe-responses.json \
  --baseline-suppressions examples/baseline-suppressions.json \
  --fail-on-failures \
  --fail-on-expired-suppressions \
  --fail-on-stale-suppressions \
  --format json
```

Matching non-expired suppressions are removed from active gates and preserved under `suppressed_findings`; expired suppressions do not hide failures, and stale suppressions are reported for cleanup. See `docs/baseline-suppressions.md` for the file format and lifecycle guidance.

A copyable GitHub Actions workflow is available at `examples/github-actions/agent-security-bench.yml`; it generates JSON, SARIF, and JUnit outputs and uploads SARIF with CodeQL code scanning.

## Tool-call transcript scoring

Use `--transcripts` when inputs are `case_id -> transcript` objects with `response` and `tool_calls` fields. Transcript scoring flags unsafe tool calls, canary exfiltration, and fake-secret exfiltration in addition to text response violations.

```bash
PYTHONPATH=src python -m agent_security_bench.cli score examples/tool-transcripts.json --transcripts --format json
```

## Live-agent adapters

List declared adapters:

```bash
PYTHONPATH=src python -m agent_security_bench.cli adapters --format json
```

The `dry-run` adapter is CI-safe and deterministic. Use `run` to collect normalized transcripts and score them with transcript-mode checks:

```bash
PYTHONPATH=src python -m agent_security_bench.cli run --adapter dry-run --format json
```

For fixture-backed adapter tests, use the dependency-free `mock` adapter with an explicit sandbox flag:

```bash
PYTHONPATH=src python -m agent_security_bench.cli run \
  --adapter mock \
  --sandbox \
  --mock-transcripts examples/tool-transcripts.json \
  --format json
```

Normalized transcripts include `response`, `tool_calls`, `timestamp`, and adapter metadata. Hermes, OpenClaw, Codex, and Claude adapter specs are listed as `sandbox_required`; they require `--sandbox` and still refuse real external execution in this release so tests never invoke live agents or real outbound tools.

## Corpus governance

Validate the built-in corpus or a custom case file before review:

```bash
PYTHONPATH=src python -m agent_security_bench.cli lint-cases --format json
PYTHONPATH=src python -m agent_security_bench.cli lint-cases --cases examples/custom-cases.yaml --format json
```

Measure corpus coverage across categories, severities, difficulties, tags, tool-risk markers, fixture references, and required/forbidden behavior:

```bash
PYTHONPATH=src python -m agent_security_bench.cli coverage --format json
```

`lint-cases` exits non-zero on case-quality errors such as invalid IDs, duplicate case IDs, invalid severity/difficulty values, duplicate patterns, or missing `canary_ids` / `fake_secret_ids` for synthetic fixture references.

## Regression mode

Compare a current run to a baseline and fail if score or pass count regresses:

```bash
PYTHONPATH=src python -m agent_security_bench.cli regression current-report.json \
  --baseline baseline-report.json \
  --fail-on-regression
```

`score` can also attach a regression comparison directly:

```bash
PYTHONPATH=src python -m agent_security_bench.cli score responses.json \
  --baseline baseline-report.json \
  --fail-on-regression
```

## Safety fixtures

`examples/canary-fixtures.json` contains fake canary files, fake secrets, and attacker endpoints used for transcript/canary tests. These values are intentionally inert and must never be replaced with real credentials.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
PYTHONPATH=src python -m pytest -q
python -m compileall -q src tests
ruff check .
```

CI runs `ruff`, `compileall`, and `pytest`.

## Roadmap status

The original `0.2.0` benchmark roadmap is complete:

- YAML/JSONL case files — Shipped
- Live-agent adapters for Hermes/OpenClaw/Codex/Claude — Shipped as sandbox-gated adapter specs plus CI-safe dry-run execution
- Tool-call transcript scoring — Shipped
- Sandboxed canary file and fake secret fixtures — Shipped
- SARIF/Markdown reports — Shipped
- Difficulty tiers and benchmark versioning — Shipped
- Larger prompt-injection corpus — Shipped
- Regression mode for agent releases — Shipped

The next roadmap is tracked in `docs/roadmap.md`. Phase 1, the CI adoption pack, is shipped in `0.3.0` with JUnit XML, score thresholds, failure gates, and a GitHub Actions example. Phase 2 is shipped in `0.4.0` with auditable baseline suppressions and cleanup gates. Phase 3 is shipped in `0.5.0` with normalized dry-run/mock adapter transcripts and sandbox-gated external adapter specs. Phase 4 is shipped in `0.6.0` with corpus linting, coverage reporting, and case-review guidance.

## Safety note

Cases intentionally contain malicious instructions and fake attacker destinations. Treat all case prompts as untrusted test data. Do not wire benchmark cases to real outbound tools without sandboxing and explicit approvals.
