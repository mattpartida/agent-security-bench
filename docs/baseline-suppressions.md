# Baseline suppressions

Baseline suppressions let existing agent evaluations adopt `agent-security-bench` in CI without hiding known failures permanently. Suppressions are exact and auditable: they match a single `case_id`, `violation_type`, and `pattern` tuple. Matching failures are removed from active gates but preserved under `suppressed_findings`.

## Usage

```bash
PYTHONPATH=src python -m agent_security_bench.cli score examples/unsafe-responses.json \
  --baseline-suppressions examples/baseline-suppressions.json \
  --fail-on-failures \
  --fail-on-expired-suppressions \
  --fail-on-stale-suppressions \
  --format json
```

## File format

```json
{
  "version": 1,
  "suppressions": [
    {
      "case_id": "secret-exfiltration",
      "violation_type": "forbidden_pattern",
      "pattern": "token",
      "owner": "security-team",
      "ticket": "SEC-123",
      "reason": "Known fake-token leak in legacy test agent while migration completes.",
      "expires_at": "2099-01-01T00:00:00Z"
    }
  ]
}
```

Every suppression must include:

- `case_id` — exact benchmark case ID.
- `violation_type` — exact violation type, such as `forbidden_pattern` or `missing_required_pattern`.
- `pattern` — exact violation pattern value emitted by the report.
- `owner` — accountable team or person.
- `ticket` — cleanup or risk-acceptance tracking ticket.
- `reason` — human-readable justification.
- `expires_at` — timezone-qualified ISO timestamp. Expired suppressions never hide current failures.

## Output fields

When `--baseline-suppressions` is used, JSON reports include:

- `suppressed_findings` — suppressed case/violation records with suppression metadata.
- `suppressed_summary` — total suppressed count and counts grouped by owner.
- `baseline_suppression_summary` — active, matched, stale, and expired suppression counts.
- `stale_suppressions` — unexpired suppressions that no longer match active failures.
- `expired_suppressions` — suppressions past `expires_at`.

Active `summary`, category/difficulty summaries, thresholds, and `--fail-on-failures` are recomputed after valid non-expired suppressions are applied. This lets teams gate on unsuppressed failures while still reviewing adoption debt.

## Lifecycle guidance

Use suppressions only as temporary adoption debt:

1. Add the narrowest possible exact case/violation/pattern tuple.
2. Assign a real owner and ticket.
3. Set a short expiration.
4. Enable `--fail-on-expired-suppressions` so expired exceptions cannot silently continue.
5. Enable `--fail-on-stale-suppressions` so fixed failures force baseline cleanup.
6. Remove stale suppressions as soon as the underlying issue is fixed.

Do not use baseline suppressions for real secrets or live credentials. Benchmark examples must stay fake and inert.
