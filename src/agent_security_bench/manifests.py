"""Validated, content-pinned evaluation manifests."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any

from .adapters import adapter_names
from .baselines import validate_baseline_suppressions
from .cases import BENCHMARK_VERSION, built_in_cases, load_cases_bytes
from .suites import filter_cases_by_suite
from .strict_json import loads_strict_json

MANIFEST_SCHEMA_VERSION = "1.0"
MAX_PINNED_FILE_BYTES = 16_777_216
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_FIELDS = {
    "schema_version",
    "case_files",
    "suite",
    "adapter",
    "sandbox",
    "mock_transcripts",
    "baseline_suppressions",
    "thresholds",
}
_ALLOWED_THRESHOLDS = {
    "min_score",
    "min_weighted_score",
    "max_critical_failures",
    "max_high_failures",
    "fail_on_failures",
    "fail_on_expired_suppressions",
    "fail_on_stale_suppressions",
}


@dataclass(frozen=True)
class LoadedEvaluationManifest:
    manifest: dict[str, Any]
    cases: list[Any]
    suite: dict[str, Any] | None
    mock_data: dict[str, Any] | None
    baseline_suppressions: list[dict[str, str]] | None
    provenance: dict[str, Any]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bounded_regular_file(path: Path, field: str) -> bytes:
    if not path.is_file():
        raise ValueError(f"{field}.path must reference a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{field}.path must reference a regular file")
        if metadata.st_size > MAX_PINNED_FILE_BYTES:
            raise ValueError(f"{field}.path exceeds the {MAX_PINNED_FILE_BYTES}-byte size limit")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read(MAX_PINNED_FILE_BYTES + 1)
        if len(data) > MAX_PINNED_FILE_BYTES:
            raise ValueError(f"{field}.path exceeds the {MAX_PINNED_FILE_BYTES}-byte size limit")
        return data
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_pinned_file(root: Path, value: Any, field: str) -> tuple[Path, dict[str, str], bytes]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object with path and sha256")
    unknown = sorted(set(value) - {"path", "sha256"})
    if unknown:
        raise ValueError(f"{field} contains unknown field(s): {', '.join(unknown)}")
    declared_path = value.get("path")
    expected_hash = value.get("sha256")
    if not isinstance(declared_path, str) or not declared_path.strip():
        raise ValueError(f"{field}.path must be a non-empty string")
    if not isinstance(expected_hash, str) or not _SHA256_RE.fullmatch(expected_hash):
        raise ValueError(f"{field}.sha256 must be a 64-character lowercase hexadecimal SHA-256 digest")
    candidate = Path(declared_path)
    windows_candidate = PureWindowsPath(declared_path)
    if candidate.is_absolute() or windows_candidate.is_absolute() or windows_candidate.drive or windows_candidate.root:
        raise ValueError(f"{field}.path must be relative to the manifest")
    path = root / candidate
    data = _read_bounded_regular_file(path, field)
    actual_hash = _sha256_bytes(data)
    if actual_hash != expected_hash:
        raise ValueError(f"{field} SHA-256 mismatch for {declared_path!r}: expected {expected_hash}, got {actual_hash}")
    return path, {"path": candidate.as_posix(), "sha256": actual_hash}, data


def _validate_thresholds(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("thresholds must be an object")
    unknown = sorted(set(value) - _ALLOWED_THRESHOLDS)
    if unknown:
        raise ValueError(f"thresholds contains unknown field(s): {', '.join(unknown)}")
    normalized: dict[str, Any] = {}
    for name, raw in value.items():
        if name in {"min_score", "min_weighted_score"}:
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise ValueError(f"thresholds.{name} must be a finite number from 0.0 to 1.0")
            number = float(raw)
            if not math.isfinite(number) or not 0.0 <= number <= 1.0:
                raise ValueError(f"thresholds.{name} must be a finite number from 0.0 to 1.0")
            normalized[name] = number
        elif name in {"max_critical_failures", "max_high_failures"}:
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
                raise ValueError(f"thresholds.{name} must be a non-negative integer")
            normalized[name] = raw
        else:
            if not isinstance(raw, bool):
                raise ValueError(f"thresholds.{name} must be a boolean")
            normalized[name] = raw
    return normalized


def _load_json_bytes(data: bytes, field: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{field} contains invalid JSON: {exc}") from exc
    return loads_strict_json(text, field)


def load_evaluation_manifest(path: str | Path) -> LoadedEvaluationManifest:
    """Load and validate a manifest, verifying every referenced file digest."""

    manifest_path = Path(path)
    manifest_bytes = _read_bounded_regular_file(manifest_path, "manifest")
    manifest_hash = _sha256_bytes(manifest_bytes)
    manifest = _load_json_bytes(manifest_bytes, "manifest")
    if not isinstance(manifest, dict):
        raise ValueError("evaluation manifest must be a JSON object")
    unknown = sorted(set(manifest) - _ALLOWED_FIELDS)
    if unknown:
        raise ValueError(f"manifest contains unknown field(s): {', '.join(unknown)}")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {MANIFEST_SCHEMA_VERSION!r}")

    adapter = manifest.get("adapter")
    if adapter not in adapter_names():
        raise ValueError(f"adapter must be one of: {', '.join(adapter_names())}")
    sandbox = manifest.get("sandbox")
    if not isinstance(sandbox, bool):
        raise ValueError("sandbox must be a boolean")
    thresholds = _validate_thresholds(manifest.get("thresholds"))

    root = manifest_path.parent
    case_entries = manifest.get("case_files", [])
    if not isinstance(case_entries, list):
        raise ValueError("case_files must be a list")
    cases = []
    selected_case_files = []
    for index, entry in enumerate(case_entries):
        case_path, selected, case_bytes = _read_pinned_file(root, entry, f"case_files[{index}]")
        try:
            cases.extend(load_cases_bytes(case_bytes, suffix=case_path.suffix))
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"case_files[{index}] is invalid: {exc}") from exc
        selected_case_files.append(selected)
    if not case_entries:
        cases = built_in_cases()

    case_ids = [case.id for case in cases]
    duplicates = sorted(case_id for case_id, count in Counter(case_ids).items() if count > 1)
    if duplicates:
        raise ValueError(f"case_files contain duplicate case id(s): {', '.join(duplicates)}")

    suite_name = manifest.get("suite")
    if suite_name is not None and not isinstance(suite_name, str):
        raise ValueError("suite must be a string or null")
    cases, suite = filter_cases_by_suite(cases, suite_name)
    if not cases:
        raise ValueError("evaluation manifest selects zero cases")

    mock_entry = manifest.get("mock_transcripts")
    mock_data = None
    selected_mock = None
    if adapter == "mock" and mock_entry is None:
        raise ValueError("mock adapter requires mock_transcripts")
    if adapter != "mock" and mock_entry is not None:
        raise ValueError("mock_transcripts is only valid with the mock adapter")
    if mock_entry is not None:
        _, selected_mock, mock_bytes = _read_pinned_file(root, mock_entry, "mock_transcripts")
        mock_data = _load_json_bytes(mock_bytes, "mock_transcripts")
        if not isinstance(mock_data, dict):
            raise ValueError("mock_transcripts must contain a JSON object keyed by case id")

    baseline_entry = manifest.get("baseline_suppressions")
    cleanup_gates = ("fail_on_expired_suppressions", "fail_on_stale_suppressions")
    if baseline_entry is None and any(thresholds.get(name, False) for name in cleanup_gates):
        raise ValueError("suppression cleanup thresholds require baseline_suppressions")
    baseline_suppressions = None
    selected_baseline = None
    if baseline_entry is not None:
        _, selected_baseline, baseline_bytes = _read_pinned_file(root, baseline_entry, "baseline_suppressions")
        baseline_data = _load_json_bytes(baseline_bytes, "baseline_suppressions")
        baseline_suppressions = validate_baseline_suppressions(baseline_data)

    normalized_manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "case_files": case_entries,
        "suite": suite_name,
        "adapter": adapter,
        "sandbox": sandbox,
        "thresholds": thresholds,
    }
    if mock_entry is not None:
        normalized_manifest["mock_transcripts"] = mock_entry
    if baseline_entry is not None:
        normalized_manifest["baseline_suppressions"] = baseline_entry

    selected_inputs: dict[str, Any] = {
        "case_files": selected_case_files,
        "case_source": "pinned_files" if selected_case_files else "built_in",
        "benchmark_version": BENCHMARK_VERSION,
        "suite": suite_name,
        "adapter": adapter,
        "sandbox": sandbox,
        "thresholds": thresholds,
    }
    if not selected_case_files:
        built_in_payload = json.dumps(
            [case.to_dict() for case in cases],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        selected_inputs["built_in_cases_sha256"] = _sha256_bytes(built_in_payload)
    if selected_mock is not None:
        selected_inputs["mock_transcripts"] = selected_mock
    if selected_baseline is not None:
        selected_inputs["baseline_suppressions"] = selected_baseline

    provenance = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "path": manifest_path.as_posix(),
        "sha256": manifest_hash,
        "selected_inputs": selected_inputs,
    }
    return LoadedEvaluationManifest(
        manifest=normalized_manifest,
        cases=cases,
        suite=suite,
        mock_data=mock_data,
        baseline_suppressions=baseline_suppressions,
        provenance=provenance,
    )
