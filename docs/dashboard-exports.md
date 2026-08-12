# Dashboard exports

Phase 10 keeps hosting outside the CLI while providing stable artifacts for trend dashboards and pull-request review.

## NDJSON trend export

Use `--format ndjson` with `score`, `run`, or `run-manifest`:

```bash
PYTHONPATH=src python -m agent_security_bench.cli run-manifest \
  examples/manifests/ci.json \
  --format ndjson > agent-security-bench.ndjson
```

The first line is a `run` record with aggregate metrics and optional suite, adapter, threshold, policy-outcome, and redacted manifest provenance. Manifest provenance is allowlisted to schema version and SHA-256 only; local manifest and selected-input paths are omitted. The run record is followed by one deterministic `case` record per case, sorted by stable case ID. Metric records intentionally omit response text and transcript/tool-call content; retain evidence bundles separately when detailed failure review is needed.

Each record carries `export_schema_version: "1.0"`, the source `report_schema_version`, and the benchmark version. Consumers should:

- key runs using their own immutable CI metadata, such as repository, workflow run ID, commit SHA, and timestamp;
- ignore unknown additive fields for forward and backward-compatible readers;
- reject unsupported `export_schema_version` major versions;
- store raw artifacts before transforming them into a warehouse or static-site dataset;
- treat case IDs and category names as dimensions, not executable content.

## Pull-request Markdown

Use `--format markdown-pr` for a concise comment body:

```bash
PYTHONPATH=src python -m agent_security_bench.cli score responses.json \
  --format markdown-pr > agent-security-bench-comment.md
```

The output has a stable HTML marker, one-line score and complete policy status, and a collapsed table containing failed cases only. Untrusted report text is encoded as inert table text, HTML-sensitive characters are escaped, and case-insensitive mass mentions are neutralized before rendering.

## GitHub Actions artifact ingestion

A minimal artifact step can preserve NDJSON for a later dashboard job:

```yaml
- name: Export benchmark metrics
  run: |
    PYTHONPATH=src python -m agent_security_bench.cli run-manifest \
      examples/manifests/ci.json \
      --format ndjson > agent-security-bench.ndjson

- uses: actions/upload-artifact@v4
  with:
    name: agent-security-bench-metrics
    path: agent-security-bench.ndjson
```

A separate trusted workflow can download successful artifacts, append CI metadata, and publish a static dashboard dataset to GitHub Pages or another static host. Do not run scripts copied from benchmark prompts, responses, violations, or artifacts. Keep publishing credentials in the trusted publishing workflow and grant only the permissions it needs.

## Static-site publishing model

A dependency-light static dashboard can periodically:

1. download immutable NDJSON artifacts from trusted benchmark workflows;
2. validate the export schema major version and JSON shape;
3. enrich run records with trusted CI metadata;
4. deduplicate by repository and workflow run ID;
5. build static JSON/HTML charts;
6. publish only metrics, not responses, transcripts, secrets, or raw evidence.

The CLI does not upload artifacts, post PR comments, fetch historical runs, or host a service. Those outbound actions remain explicit responsibilities of the surrounding CI workflow.
