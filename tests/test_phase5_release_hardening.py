import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Phase5ReleaseHardeningTests(unittest.TestCase):
    def test_packaging_smoke_builds_wheel_installs_fresh_venv_and_runs_cli(self):
        script = ROOT / "scripts" / "packaging-smoke.py"
        with tempfile.TemporaryDirectory() as tmpdir:
            completed = subprocess.run(
                [sys.executable, str(script), "--repo", str(ROOT), "--tmpdir", tmpdir],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
                timeout=240,
            )
        result = json.loads(completed.stdout)
        self.assertIn("0.9.0", result["wheel"])
        self.assertTrue(result["help_contains_description"])
        self.assertGreaterEqual(result["case_count"], 10)
        self.assertEqual(result["schema_version"], "0.2")

    def test_packaging_smoke_script_is_copyable_for_ci(self):
        script = ROOT / "scripts" / "packaging-smoke.py"
        self.assertTrue(script.exists())
        text = script.read_text(encoding="utf-8")
        self.assertIn("pip", text)
        self.assertIn("wheel", text)
        self.assertIn("agent-security-bench", text)
        self.assertIn("--help", text)
        self.assertIn("list", text)

    def test_ci_matrix_covers_supported_python_versions_and_operating_systems(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("strategy:", workflow)
        self.assertIn("matrix:", workflow)
        self.assertIn("python-version: [\"3.11\", \"3.12\"]", workflow)
        self.assertIn("os: [ubuntu-latest, macos-latest, windows-latest]", workflow)
        self.assertIn("python -m compileall -q src tests", workflow)
        self.assertIn("python scripts/packaging-smoke.py", workflow)
        self.assertIn("PYTHONPATH", workflow)

    def test_changelog_and_schema_policy_document_cli_and_report_compatibility(self):
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        schema = (ROOT / "docs" / "report-schema.md").read_text(encoding="utf-8")
        roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        package_init = (ROOT / "src" / "agent_security_bench" / "__init__.py").read_text(encoding="utf-8")

        self.assertIn("## 0.7.0", changelog)
        self.assertIn("release hardening", changelog.lower())
        self.assertIn("lint-cases", changelog)
        self.assertIn("coverage", changelog)
        self.assertIn("schema_version", schema)
        self.assertIn("Compatibility policy", schema)
        self.assertIn("additive", schema.lower())
        self.assertIn("**Status:** Shipped in `0.7.0`", roadmap)
        self.assertIn("Release hardening", readme)
        self.assertIn('version = "0.9.0"', pyproject)
        self.assertIn('__version__ = "0.9.0"', package_init)


if __name__ == "__main__":
    unittest.main()
