"""Live-agent adapter registry for sandboxed benchmark execution.

Real external adapters are deliberately sandbox-gated. The built-in dry-run and
mock collectors are deterministic and dependency-free so CI can exercise the
transcript pipeline without invoking real agents.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any


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
    AdapterSpec("mock", "available", "CI-safe transcript adapter backed by a local JSON fixture.", "--mock-transcripts <path> --sandbox"),
    AdapterSpec("hermes", "sandbox_required", "Hermes Agent live adapter placeholder; run only with sandboxed toolsets.", "hermes --prompt <case> --sandbox"),
    AdapterSpec("openclaw", "sandbox_required", "OpenClaw live adapter placeholder for local security test deployments.", "openclaw run --case <case> --sandbox"),
    AdapterSpec("codex", "sandbox_required", "Codex CLI live adapter placeholder for coding-agent safety regression tests.", "codex --prompt <case> --sandbox"),
    AdapterSpec("claude", "sandbox_required", "Claude Code live adapter placeholder for coding-agent safety regression tests.", "claude --print <case> --sandbox"),
)


EXTERNAL_ADAPTERS = {"hermes", "openclaw", "codex", "claude"}


def list_adapters():
    return list(ADAPTERS)


def adapter_names() -> list[str]:
    return [adapter.name for adapter in list_adapters()]


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_transcript(
    case_id: str,
    transcript: dict[str, Any] | str | None,
    *,
    adapter_name: str,
    sandboxed: bool,
    external: bool,
) -> dict[str, Any]:
    """Normalize adapter output into the benchmark transcript schema."""

    if isinstance(transcript, dict):
        response = transcript.get("response", "")
        tool_calls = transcript.get("tool_calls", [])
        timestamp = transcript.get("timestamp") or _timestamp()
    else:
        response = "" if transcript is None else str(transcript)
        tool_calls = []
        timestamp = _timestamp()
    if not isinstance(tool_calls, list):
        tool_calls = [{"tool": "invalid", "args": {"value": tool_calls}}]
    return {
        "case_id": str(case_id),
        "response": "" if response is None else str(response),
        "tool_calls": tool_calls,
        "timestamp": str(timestamp),
        "adapter": {"name": adapter_name, "sandboxed": bool(sandboxed), "external": bool(external)},
    }


def dry_run_responses(cases):
    return {case.id: "I refuse unsafe or untrusted instructions and require explicit confirmation before actions." for case in cases}


def dry_run_transcripts(cases):
    return {
        case.id: normalize_transcript(
            case.id,
            {"response": "I refuse unsafe or untrusted instructions and require explicit confirmation before actions.", "tool_calls": []},
            adapter_name="dry-run",
            sandboxed=True,
            external=False,
        )
        for case in cases
    }


def mock_transcripts(cases, raw_transcripts: dict[str, Any], *, sandbox: bool) -> dict[str, dict[str, Any]]:
    if not sandbox:
        raise ValueError("mock adapter requires --sandbox so transcript fixtures cannot be confused with live execution")
    return {
        case.id: normalize_transcript(
            case.id,
            raw_transcripts.get(case.id, {"response": "", "tool_calls": []}),
            adapter_name="mock",
            sandboxed=True,
            external=False,
        )
        for case in cases
    }


def collect_transcripts(
    adapter_name: str,
    cases,
    *,
    sandbox: bool = False,
    mock_data: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Collect normalized transcripts for an adapter.

    External adapters are intentionally not invoked yet. They return a clear
    sandbox-gating error until a future phase wires real process execution inside
    hardened sandboxes.
    """

    names = set(adapter_names())
    if adapter_name not in names:
        raise ValueError(f"unknown adapter {adapter_name!r}")
    if adapter_name == "dry-run":
        return dry_run_transcripts(cases)
    if adapter_name == "mock":
        return mock_transcripts(cases, mock_data or {}, sandbox=sandbox)
    if adapter_name in EXTERNAL_ADAPTERS:
        if not sandbox:
            raise ValueError(f"adapter {adapter_name!r} requires --sandbox before collecting transcripts")
        raise ValueError(f"adapter {adapter_name!r} is sandbox-gated and not wired to execute real agents in this release")
    raise ValueError(f"adapter {adapter_name!r} is not available")
