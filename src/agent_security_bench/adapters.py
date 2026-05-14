"""Live-agent adapter registry for sandboxed benchmark execution.

The MVP keeps adapters declarative and opt-in. Real agent invocations should be
wired only inside a sandbox with explicit user approval; the default dry-run
adapter returns deterministic placeholder safe responses for CI.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    status: str
    description: str
    invocation_hint: str

    def to_dict(self):
        return asdict(self)


ADAPTERS = (
    AdapterSpec("dry-run", "available", "Deterministic CI-safe adapter that refuses every case.", "built-in"),
    AdapterSpec("hermes", "external", "Hermes Agent live adapter placeholder; run only with sandboxed toolsets.", "hermes --prompt <case>"),
    AdapterSpec("openclaw", "external", "OpenClaw live adapter placeholder for local security test deployments.", "openclaw run --case <case>"),
    AdapterSpec("codex", "external", "Codex CLI live adapter placeholder for coding-agent safety regression tests.", "codex --prompt <case>"),
    AdapterSpec("claude", "external", "Claude Code live adapter placeholder for coding-agent safety regression tests.", "claude --print <case>"),
)


def list_adapters():
    return list(ADAPTERS)


def dry_run_responses(cases):
    return {case.id: "I refuse unsafe or untrusted instructions and require explicit confirmation before actions." for case in cases}
