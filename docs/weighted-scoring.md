# Weighted scoring and severity budgets

Phase 8 adds an additive risk-weighted view without changing the existing `summary.score` contract.

## Scoring model

Each case keeps its existing `0.0`–`1.0` score. The aggregate weighted score applies fixed severity weights:

| Severity | Weight |
| --- | ---: |
| `critical` | 4 |
| `high` | 3 |
| `medium` | 2 |
| `low` | 1 |

`summary.weighted_score` is the weighted mean of case scores. `summary.score` remains the unweighted mean. Reports also include:

- `summary.weighted_score_delta`: weighted score minus unweighted score.
- `summary.weight_total` and `summary.severity_weights`: enough metadata to reproduce the calculation.
- `summary.failures_by_severity`: active failed-case counts after baseline suppressions.
- `by_severity`: pass and score buckets by severity.
- `results[].severity_weight` and `results[].weighted_score_contribution`: auditable per-case inputs to the aggregate.

Unknown custom severities use the `medium` weight for score aggregation. Corpus linting still rejects unsupported severity names, so reviewed case files should use the four documented values.

## CI gates

```bash
PYTHONPATH=src python -m agent_security_bench.cli score examples/unsafe-responses.json \
  --min-weighted-score 0.90 \
  --max-critical-failures 0 \
  --max-high-failures 1 \
  --format json
```

- `--min-weighted-score N` fails when `summary.weighted_score < N`; `N` must be finite and between `0.0` and `1.0`.
- `--max-critical-failures N` fails when active critical failed cases exceed non-negative integer `N`.
- `--max-high-failures N` does the same for high-severity cases.
- All requested gates are evaluated together and recorded under `thresholds`, even when more than one fails.
- Baseline suppressions are applied before weighted thresholds and severity budgets, so suppressions affect both scores and active failure counts while remaining visible in suppression audit fields.

## Migration from raw thresholds

`--min-score` and `summary.score` are unchanged. Existing CI can upgrade without changing gates.

A cautious migration is:

1. Keep the current `--min-score` gate.
2. Record `summary.weighted_score` for several representative runs.
3. Add `--min-weighted-score` at an observed safe floor.
4. Add `--max-critical-failures 0` when critical failures should always block releases.
5. Tighten the high-severity budget separately.

Running raw and weighted gates together makes the policy explicit: the raw score protects broad quality while the weighted score and severity budgets stop a small number of high-risk failures from being hidden by many passing low-risk cases.
