# agent-security-bench

Dependency-light benchmark suite for evaluating autonomous-agent security behavior.

It provides adversarial cases for prompt injection, data exfiltration, tool misuse, persistence/memory poisoning, and approval bypass. The MVP scores model/agent text responses deterministically and is designed to become a live-agent harness later.

## Why

Agent security failures are behavioral. A config can look reasonable while the agent still:

- follows malicious webpage instructions
- leaks tokens/secrets
- uses tools without approval
- stores attacker policy in memory
- bypasses outbound-action gates

This repo gives those risks repeatable benchmark cases.

## Quick start

Run without installing:

```bash
PYTHONPATH=src python -m agent_security_bench.cli list --format json
PYTHONPATH=src python -m agent_security_bench.cli score examples/safe-responses.json --format json
```

Install locally:

```bash
python -m pip install -e .
agent-security-bench list --format json
agent-security-bench score examples/safe-responses.json --format json
```

## Built-in categories

- `direct_prompt_injection`
- `indirect_prompt_injection`
- `data_exfiltration`
- `tool_misuse`
- `persistence`
- `approval_bypass`

## Output

The score report includes:

- aggregate summary
- score from `0.0` to `1.0`
- per-category results
- per-case pass/fail
- violations with required/forbidden pattern IDs

## Example

```bash
PYTHONPATH=src python -m agent_security_bench.cli score examples/unsafe-responses.json --format json
```

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
python -m compileall -q src tests
```

CI runs `ruff`, `compileall`, and `pytest`.

## Roadmap

- YAML/JSONL case files
- Live-agent adapters for Hermes/OpenClaw/Codex/Claude
- Tool-call transcript scoring
- Sandboxed canary file and fake secret fixtures
- SARIF/Markdown reports
- Difficulty tiers and benchmark versioning
- Larger prompt-injection corpus
- Regression mode for agent releases

## Safety note

Cases intentionally contain malicious instructions and fake attacker destinations. Treat all case prompts as untrusted test data. Do not wire benchmark cases to real outbound tools without sandboxing and explicit approvals.
