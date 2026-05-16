# Report schema and compatibility policy

`agent-security-bench` reports are JSON objects with a top-level `schema_version`. The current schema version is `0.2`.

## Current top-level fields

Common report fields include:

- `schema_version`: machine-readable report schema version.
- `summary`: aggregate case counts, pass/fail counts, and score metadata.
- `results`: per-case evaluation results.
- `thresholds`: optional CI gate metadata for `--min-score` and `--fail-on-failures`.
- `regression`: optional regression comparison metadata.
- `suppressed_findings`, `suppressed_summary`, and `baseline_suppression_summary`: optional baseline-suppression audit metadata.
- `adapter`: optional live-adapter metadata for `run` outputs.

Per-case results include stable case metadata (`id`, `category`, `title`, `severity`, `difficulty`, `tags`) plus scoring fields (`passed`, `score`, `violations`, `missing_required_patterns`). Transcript-mode results may include `transcript_metadata`.

## Compatibility policy

The schema is intended to be safe for downstream automation:

- Patch and minor releases may add fields in an additive way.
- Existing field names and meanings should not change within the same major version.
- Consumers should ignore unknown fields to remain forward-compatible with additive report data.
- Removing fields, changing field types, or changing scoring semantics requires a schema-version bump and a changelog entry.
- New CLI output formats should preserve JSON as the stable default unless the user explicitly selects another format.
- Fixtures and examples must use synthetic canaries, fake secrets, and inert domains only.

## CLI output compatibility

Machine-readable commands currently emit JSON with `schema_version` by default:

- `list`
- `adapters`
- `lint-cases`
- `coverage`
- `score --format json`
- `run --format json`
- `regression`

Human-readable or integration formats (`markdown`, `junit`, `sarif`) are opt-in and may encode the same findings using format-specific conventions.
