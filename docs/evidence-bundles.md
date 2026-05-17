# Evidence bundles

Evidence bundles are compact JSON artifacts for reviewing failed benchmark cases in CI. They are intentionally separate from the normal score report: the score report keeps aggregate/pass-fail state, while the evidence bundle keeps the exact prompt, expected behavior, observed response, transcript/tool-call context, violations, and a copyable reproducer command for each active failed case.

## Generate from scored responses

```bash
PYTHONPATH=src python -m agent_security_bench.cli score examples/unsafe-responses.json \
  --evidence-bundle agent-security-bench-evidence.json \
  --format json
```

The bundle contains failed active cases only. Passing cases are omitted by default so reviewers can attach the artifact to pull requests without burying the signal.

## Generate from adapter runs

```bash
PYTHONPATH=src python -m agent_security_bench.cli run \
  --adapter mock \
  --sandbox \
  --mock-transcripts examples/tool-transcripts.json \
  --evidence-bundle agent-security-bench-evidence.json \
  --format json
```

Transcript evidence preserves `tool_calls` and adapter metadata so reviewers can distinguish final-answer failures from unsafe tool-use behavior.

## Schema

Evidence bundles are additive and use the same `schema_version` as score reports:

```json
{
  "schema_version": "0.2",
  "benchmark_version": "0.2",
  "generated_at": "2026-01-01T00:00:00Z",
  "source": "examples/unsafe-responses.json",
  "summary": {
    "failed_cases": 1,
    "included_cases": 1
  },
  "cases": [
    {
      "id": "secret-exfiltration",
      "category": "data_exfiltration",
      "title": "Secret exfiltration request",
      "severity": "critical",
      "difficulty": "easy",
      "benchmark_version": "0.2",
      "prompt": "...",
      "expected_behavior": "...",
      "observed_response": "...",
      "violations": [
        {"type": "forbidden_pattern", "pattern": "attacker@example.com"}
      ],
      "reproducer": {
        "command": "agent-security-bench score examples/unsafe-responses.json --format json",
        "notes": "Re-run the benchmark and inspect --case secret-exfiltration in the evidence bundle."
      }
    }
  ]
}
```

When transcript scoring is used, each failed case may also include:

- `transcript` — normalized response, tool calls, timestamp, and adapter metadata from the adapter collector.
- `adapter` — adapter-level metadata such as name and sandbox state.

## CI guidance

Keep the normal JSON/JUnit/SARIF reports as CI outputs, and upload the evidence bundle as a separate artifact. Treat prompts and transcripts as untrusted test data; never put real credentials into benchmark fixtures or evidence bundles.
