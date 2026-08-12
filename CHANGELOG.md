# Changelog

All notable changes to `agent-security-bench` are documented here. The report schema follows the compatibility policy in `docs/report-schema.md`.

## 0.12.0

Dashboard-ready exports without adding a hosted service to the CLI.

### Added

- Stable NDJSON run and case metric records via `--format ndjson` for `score`, `run`, and `run-manifest`.
- Concise pull-request summaries via `--format markdown-pr`, with table escaping and mass-mention neutralization.
- `docs/dashboard-exports.md` covering GitHub Actions artifacts, static-site publishing, privacy boundaries, and long-lived schema compatibility.

### Security

- Dashboard metric exports omit response, transcript/tool-call content, and local provenance paths by design.
- Pull-request Markdown treats copied report text as untrusted data and reports threshold, regression, and suppression-cleanup policy outcomes.

## 0.11.0

Content-pinned evaluation manifests for reproducible benchmark runs.

### Added

- `run-manifest` command with strict manifest validation and JSON, Markdown, SARIF, and JUnit output.
- SHA-256 pins for external case files, mock transcript fixtures, and baseline-suppression files.
- Additive manifest-digest and selected-input provenance in JSON, Markdown, SARIF, and JUnit reports.
- Local, CI, and nightly example manifests plus `docs/evaluation-manifests.md`.

### Changed

- Manifest-driven runs compose baseline cleanup, raw/weighted score, failure, and severity-budget gates after suppressions.

## 0.10.0

Severity-weighted scoring and explicit critical/high failure budgets.

### Added

- Additive weighted-score metadata, fixed severity weights, per-severity failure counts, and per-case weighted contributions.
- `--min-weighted-score`, `--max-critical-failures`, and `--max-high-failures` CI gates.
- Weighted score and severity summaries in Markdown reports.
- `docs/weighted-scoring.md` with scoring, gate-composition, suppression, and migration guidance.

### Changed

- Baseline suppression recomputation now refreshes weighted aggregates and severity budgets before threshold evaluation.
- Score thresholds reject non-finite/out-of-range values, and severity budgets reject negative values instead of allowing ambiguous CI policies.

## 0.9.0

Scenario suites for focused CI and release gates.

### Added

- Built-in `smoke`, `release`, `exfiltration`, `tool-use`, and `full` scenario suites.
- `--suite <name>` filtering for `list`, `score`, `run`, `lint-cases`, and `coverage`.
- Suite metadata in JSON list, score, run, lint, and coverage outputs.
- `docs/scenario-suites.md` with PR, release, and nightly usage guidance.

## 0.8.0

Evidence bundles for CI failure review.

### Added

- `--evidence-bundle <path>` for `score` and `run` commands.
- Evidence bundle JSON artifacts with failed-case prompts, expected behavior, observed responses, transcript/tool-call context, violations, adapter metadata, and reproducer commands.
- `docs/evidence-bundles.md` with schema and CI artifact guidance.

### Changed

- Roadmap now tracks the next phases: scenario suites, weighted scoring, evaluation manifests, and dashboard exports.

## 0.7.0

Release hardening for repeatable packaging and downstream automation.

### Added

- Packaging smoke script that builds a wheel, installs it into a fresh virtual environment, and runs `agent-security-bench --help` plus `agent-security-bench list`.
- GitHub Actions matrix across Python 3.11/3.12 and Ubuntu, macOS, and Windows.
- Report schema compatibility policy in `docs/report-schema.md`.

### Changed

- CI now runs the packaging smoke test after lint, compile, and unit tests.

## 0.6.0

Corpus governance.

### Added

- `agent-security-bench lint-cases` for case-quality validation.
- `agent-security-bench coverage` for corpus coverage summaries.
- Case-authoring review checklist for malicious prompts, duplicate patterns, synthetic canaries, and fake secrets.

## 0.5.0

Agent transcript adapters.

### Added

- Normalized dry-run and mock transcript collectors.
- Sandbox-gated external adapter specs for Hermes, OpenClaw, Codex, and Claude.

## 0.4.0

Baselines and suppressions.

### Added

- Auditable baseline suppressions with owner, ticket, reason, and expiration metadata.
- Cleanup gates for expired and stale suppressions.

## 0.3.0

CI adoption pack.

### Added

- JUnit XML output, score thresholds, failure gates, and copyable GitHub Actions examples.
