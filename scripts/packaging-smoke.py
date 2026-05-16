#!/usr/bin/env python3
"""Build and install a wheel in fresh virtual environments, then smoke-test the CLI."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import venv
from pathlib import Path


def _bin_dir(env: Path) -> Path:
    return env / ("Scripts" if os.name == "nt" else "bin")


def _python(env: Path) -> Path:
    return _bin_dir(env) / ("python.exe" if os.name == "nt" else "python")


def _cli(env: Path) -> Path:
    return _bin_dir(env) / ("agent-security-bench.exe" if os.name == "nt" else "agent-security-bench")


def _run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_smoke(repo: Path, tmpdir: Path) -> dict[str, object]:
    repo = repo.resolve()
    tmpdir.mkdir(parents=True, exist_ok=True)
    build_env = tmpdir / "build-env"
    install_env = tmpdir / "install-env"
    wheelhouse = tmpdir / "wheelhouse"
    wheelhouse.mkdir(exist_ok=True)

    venv.EnvBuilder(with_pip=True).create(build_env)
    build_python = _python(build_env)
    _run([str(build_python), "-m", "pip", "install", "--upgrade", "pip", "setuptools>=68", "wheel"], timeout=240)
    _run(
        [str(build_python), "-m", "pip", "wheel", str(repo), "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheelhouse)],
        timeout=240,
    )
    wheels = sorted(wheelhouse.glob("agent_security_bench-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one wheel, found {[wheel.name for wheel in wheels]}")

    venv.EnvBuilder(with_pip=True).create(install_env)
    install_python = _python(install_env)
    _run([str(install_python), "-m", "pip", "install", "--no-deps", str(wheels[0])], timeout=180)
    help_run = _run([str(_cli(install_env)), "--help"], timeout=60)
    list_run = _run([str(_cli(install_env)), "list"], timeout=60)
    list_payload = json.loads(list_run.stdout)
    return {
        "wheel": wheels[0].name,
        "help_contains_description": "Benchmark autonomous-agent security behavior" in help_run.stdout,
        "case_count": len(list_payload.get("cases", [])),
        "schema_version": list_payload.get("schema_version"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run packaging smoke test for agent-security-bench")
    parser.add_argument("--repo", default=".", help="Repository root to package")
    parser.add_argument("--tmpdir", help="Optional temp directory to use")
    args = parser.parse_args(argv)

    if args.tmpdir:
        result = run_smoke(Path(args.repo), Path(args.tmpdir))
    else:
        with tempfile.TemporaryDirectory() as tmp:
            result = run_smoke(Path(args.repo), Path(tmp))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
