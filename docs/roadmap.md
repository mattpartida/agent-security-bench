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

**Status:** Shipped in `0.5.0`.

Turn sandbox-gated adapter specs into real optional transcript collectors while keeping dry-run deterministic.

Shipped acceptance criteria:

- Adapter interface returns normalized transcripts with response text, tool calls, timestamps, and adapter metadata.
- Dry-run and mock transcript collectors are deterministic and dependency-free for CI.
- Hermes/Codex/Claude/OpenClaw collectors are opt-in and require explicit `--sandbox` before any external execution wiring.
- Adapter runs refuse real external execution and unsafe live-agent invocation by default.
- Tests cover dry-run and mocked adapter transcripts without invoking real external agents.

## Phase 4 — Corpus governance

**Status:** Shipped in `0.6.0`.

Make case quality measurable as the corpus grows.

Shipped acceptance criteria:

- `agent-security-bench lint-cases` validates IDs, categories, severity/difficulty, duplicate patterns, and fake-fixture references.
- `agent-security-bench coverage` summarizes categories, severities, difficulties, tools, tags, fixture references, and required/forbidden behavior.
- Contribution docs define a review checklist for malicious prompts, duplicate patterns, synthetic canaries, and fake secrets.

## Phase 5 — Release hardening

**Status:** Shipped in `0.7.0`.

Prepare the benchmark for repeatable package releases and downstream automation.

Shipped acceptance criteria:

- Packaging smoke test builds a wheel, installs it in a fresh virtualenv, and runs `agent-security-bench --help` plus `agent-security-bench list`.
- Changelog documents schema compatibility and CLI changes.
- CI matrix covers supported Python versions and operating systems.
- Report schema versioning policy is documented.

## Phase 6 — Evidence bundles

**Status:** Shipped in `0.8.0`.

Make CI failures easy to review by packaging failed-case evidence, prompts, observed responses, transcript/tool-call context, and reproducer commands into a compact JSON artifact.

Shipped acceptance criteria:

- `agent-security-bench score --evidence-bundle <path>` writes a JSON evidence bundle for active failed cases.
- `agent-security-bench run --evidence-bundle <path>` preserves transcript tool calls and adapter metadata for failed adapter runs.
- Evidence bundles include prompt, expected behavior, observed response, violations, severity/difficulty, source, and a copyable reproducer command.
- Passing cases are omitted from evidence bundles by default so CI artifacts stay reviewable.
- README, changelog, and `docs/evidence-bundles.md` document the workflow and schema.

## Phase 7 — Scenario suites

**Status:** Planned.

Group cases into named suites for quick smoke checks, high-risk release gates, and slower full regressions.

Planned scope:

- Built-in `smoke`, `release`, `exfiltration`, `tool-use`, and `full` suites.
- `--suite <name>` filtering for `list`, `score`, `run`, `lint-cases`, and `coverage`.
- Suite membership exposed in JSON reports and coverage output.
- Docs showing which suites are safe for PR checks versus nightly checks.

## Phase 8 — Weighted scoring and severity budgets

**Status:** Planned.

Let teams fail builds based on weighted risk, not only raw pass counts.

Planned scope:

- Severity-weighted score aggregation.
- CLI gates for maximum critical/high failures and minimum weighted score.
- Report fields that show how weighted and unweighted scores differ.
- Migration docs for users moving from raw thresholds.

## Phase 9 — Evaluation manifests

**Status:** Planned.

Make benchmark runs reproducible across agents, corpora, adapters, and CI environments.

Planned scope:

- Manifest file format that pins case files, suite filters, adapter, sandbox mode, threshold gates, and baseline suppressions.
- `agent-security-bench run-manifest <manifest>` command.
- Manifest validation and example manifests for local, CI, and nightly modes.
- Report provenance that records manifest hash and selected inputs.

## Phase 10 — Hosted benchmark dashboards

**Status:** Planned.

Prepare outputs for trend dashboards without requiring a hosted service in the CLI.

Planned scope:

- Stable NDJSON export for per-run and per-case metrics.
- Optional Markdown summary optimized for pull-request comments.
- Dashboard ingestion docs for GitHub Actions artifacts and static-site publishing.
- Backward-compatible schema notes for long-lived trend storage.
