# Evaluation manifests

Evaluation manifests make benchmark runs repeatable by keeping the case corpus, scenario suite, adapter mode, suppression baseline, and CI policy in one reviewed JSON file.

Run one with:

```bash
agent-security-bench run-manifest examples/manifests/ci.json --format json
```

## Format

The manifest schema version is `1.0`:

```json
{
  "schema_version": "1.0",
  "case_files": [
    {
      "path": "../custom-cases.jsonl",
      "sha256": "<64-character lowercase SHA-256>"
    }
  ],
  "suite": "release",
  "adapter": "dry-run",
  "sandbox": false,
  "thresholds": {
    "min_score": 0.95,
    "min_weighted_score": 0.98,
    "max_critical_failures": 0,
    "max_high_failures": 0,
    "fail_on_failures": true,
    "fail_on_expired_suppressions": true,
    "fail_on_stale_suppressions": true
  }
}
```

`case_files` may be empty to select the built-in corpus. Multiple pinned case files are loaded in order; duplicate case IDs are rejected. `suite` may be `smoke`, `release`, `exfiltration`, `tool-use`, `full`, or `null`.

All referenced paths must be relative paths and are resolved relative to the manifest, not the caller's current working directory. POSIX absolute paths plus Windows absolute, rooted, UNC, and drive-relative forms are rejected so the same manifest cannot silently select a different file on another OS. Each external case file, mock transcript file, and baseline-suppression file must include its expected SHA-256 digest. The command reads the bytes and fails before evaluation when the digest differs. This is a content-integrity pin, not a signature; review who controls the file and manifest.

Generate a digest with:

```bash
sha256sum path/to/file
# macOS: shasum -a 256 path/to/file
```

## Mock transcripts and suppressions

The `mock` adapter requires both an explicit sandbox and a pinned transcript fixture:

```json
{
  "adapter": "mock",
  "sandbox": true,
  "mock_transcripts": {
    "path": "../tool-transcripts.json",
    "sha256": "<fixture digest>"
  }
}
```

A suppression baseline is also pinned:

```json
{
  "baseline_suppressions": {
    "path": "../baseline-suppressions.json",
    "sha256": "<baseline digest>"
  }
}
```

Suppressions are applied before score and severity-budget gates. Expired and stale cleanup gates compose with score gates; all requested gate metadata remains in the report. Cleanup gates are rejected unless `baseline_suppressions` is present, so a misspelled or omitted baseline cannot silently disable cleanup enforcement.

## Provenance

Every report format preserves manifest provenance. JSON uses the top-level `evaluation_manifest` object, Markdown includes an Evaluation manifest section, SARIF stores it under `runs[0].properties`, and JUnit emits suite properties. The provenance contains:

- the manifest schema version, source path, and SHA-256 digest;
- selected case-file paths and verified digests, or `case_source: built_in` with a deterministic `built_in_cases_sha256` for the selected built-in suite;
- benchmark version, suite, adapter, sandbox mode, and thresholds;
- verified mock-transcript and baseline-suppression inputs when present.

The provenance records exactly what the CLI selected. Store the manifest and report together if another system needs to reproduce or audit a run.

## Validation and safety

Validation is strict and fail-closed. Unknown or duplicate JSON object names, non-finite JSON constants or exponent-overflowing numbers, JSON nesting deeper than 64 containers, unsupported schema versions, malformed case rows, uppercase or malformed digests, invalid score thresholds, negative failure budgets, hash mismatches, non-regular inputs, manifest or pinned-input files larger than 16 MiB, duplicate case IDs, and selections that resolve to zero cases return exit code `2`. A valid run that violates policy returns exit code `1`.

External live-agent adapters remain sandbox-gated placeholders. A manifest cannot bypass their execution refusal. Case prompts and transcript fixtures are untrusted test data; manifests do not grant tool or network authority.

## Examples

- `examples/manifests/local.json`: full built-in corpus with deterministic dry-run transcripts and no CI gate.
- `examples/manifests/ci.json`: small smoke suite with strict pass/score gates.
- `examples/manifests/nightly.json`: full built-in corpus with weighted score and severity budgets.
