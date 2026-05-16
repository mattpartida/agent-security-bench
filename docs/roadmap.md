# agent-security-bench Roadmap

This roadmap starts after the `0.2.0` benchmark-roadmap completion. Each phase should be shipped test-first, with docs/examples updated in the same commit that implements behavior.

## Phase 1 — CI adoption pack

**Status:** Shipped in `0.3.0`.

Make the benchmark easy to enforce in GitHub Actions and other CI systems without custom glue.

Shipped acceptance criteria:

- JUnit XML report rendering for native CI test-report ingestion.
- `agent-security-bench score --format junit` CLI support.
- score thresholds via `--min-score` with non-zero exit on failure.
- Failure gates via `--fail-on-failures` with non-zero exit when any case fails.
- Copyable GitHub Actions example that emits JSON, SARIF, and JUnit artifacts and uploads SARIF with `github/codeql-action/upload-sarif@v4`.
- README and roadmap docs describe CI usage and threshold semantics.

## Phase 2 — Baselines and suppressions

**Status:** Shipped in `0.4.0`.

Support temporary, auditable exceptions for known benchmark failures while preserving visibility.

Shipped acceptance criteria:

- Baseline file format keyed by exact `case_id`, violation type, and violation pattern.
- `--baseline-suppressions` removes matching non-expired failures from active gates while preserving them under `suppressed_findings`.
- Suppression metadata requires owner, ticket, reason, and timezone-qualified ISO expiration.
- Expired suppressions never hide failures; stale suppressions are reported separately.
- `--fail-on-expired-suppressions` and `--fail-on-stale-suppressions` support cleanup in CI.
- Example suppression file and `docs/baseline-suppressions.md` explain safe lifecycle use.

## Phase 3 — Agent transcript adapters

**Status:** Planned.

Turn sandbox-gated adapter specs into real optional transcript collectors while keeping dry-run deterministic.

Planned acceptance criteria:

- Adapter interface returns normalized transcripts with response text, tool calls, timestamps, and adapter metadata.
- Hermes/Codex/Claude collectors are opt-in and require explicit sandbox flags.
- Adapter runs refuse real secrets and unsafe outbound destinations by default.
- Tests cover dry-run and mocked adapter transcripts without invoking real external agents.

## Phase 4 — Corpus governance

**Status:** Planned.

Make case quality measurable as the corpus grows.

Planned acceptance criteria:

- Case lint command validates IDs, categories, severity/difficulty, duplicate patterns, and fake-fixture references.
- Corpus coverage report summarizes categories, severities, tools, and required/forbidden behavior.
- Contribution docs define review checklist for malicious prompts and fake secrets.

## Phase 5 — Release hardening

**Status:** Planned.

Prepare the benchmark for repeatable package releases and downstream automation.

Planned acceptance criteria:

- Packaging smoke test builds a wheel, installs it in a fresh virtualenv, and runs `agent-security-bench --help` plus `agent-security-bench list`.
- Changelog documents schema compatibility and CLI changes.
- CI matrix covers supported Python versions and operating systems.
- Report schema versioning policy is documented.
