# Changelog

All notable changes to `agent-security-bench` are documented here. The report schema follows the compatibility policy in `docs/report-schema.md`.

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
