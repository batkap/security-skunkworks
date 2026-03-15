from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def fake_scanner_bin(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text(body.lstrip(), encoding="utf-8")
    path.chmod(0o755)


class CliTests(unittest.TestCase):
    def test_run_creates_read_only_workspace_without_canonical_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "fixture"
            shutil.copytree(FIXTURES / "js-api", repo)
            result = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "run", "--repo", str(repo), "--no-branch"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((repo / ".security-skunkworks").exists())
            self.assertFalse((repo / "SECURITY.md").exists())
            self.assertFalse((repo / "AGENTS.md").exists())
            ledger_path = next((repo / ".security-skunkworks" / "runs").iterdir()) / "ledger.json"
            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
            self.assertEqual(ledger["mode"], "read-only")
            self.assertEqual(ledger["status"], "blocked")
            self.assertEqual(ledger["allowed_write_scopes"], [".security-skunkworks"])
            self.assertEqual(ledger["coverage_status"], "partial")

    def test_run_can_reach_report_ready_with_fake_scanners(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "fixture"
            shutil.copytree(FIXTURES / "js-api-safe", repo)
            fake_bin = Path(tmpdir) / "bin"
            fake_bin.mkdir()
            fake_scanner_bin(
                fake_bin,
                "semgrep",
                textwrap.dedent(
                    """\
                    #!/bin/sh
                    while [ "$#" -gt 0 ]; do
                      if [ "$1" = "--output" ]; then
                        shift
                        printf '{"results":[]}\n' > "$1"
                      fi
                      shift
                    done
                    exit 0
                    """
                ),
            )
            fake_scanner_bin(
                fake_bin,
                "gitleaks",
                textwrap.dedent(
                    """\
                    #!/bin/sh
                    while [ "$#" -gt 0 ]; do
                      if [ "$1" = "--report-path" ]; then
                        shift
                        printf '[]\n' > "$1"
                      fi
                      shift
                    done
                    exit 0
                    """
                ),
            )
            fake_scanner_bin(
                fake_bin,
                "npm",
                textwrap.dedent(
                    """\
                    #!/bin/sh
                    if [ "$1" = "audit" ]; then
                      printf '{"auditReportVersion":2,"vulnerabilities":{}}\n'
                      exit 0
                    fi
                    if [ "$1" = "test" ]; then
                      exit 0
                    fi
                    exit 0
                    """
                ),
            )
            env = dict(os.environ)
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            result = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "run", "--repo", str(repo), "--no-branch"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            run_dir = next((repo / ".security-skunkworks" / "runs").iterdir())
            ledger = json.loads((run_dir / "ledger.json").read_text(encoding="utf-8"))
            self.assertEqual(ledger["status"], "report_ready")
            self.assertEqual(ledger["coverage_status"], "full")
            verify = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "verify", "--repo", str(repo), "--run", run_dir.name],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

    def test_verify_fails_for_blocked_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "fixture"
            shutil.copytree(FIXTURES / "js-api", repo)
            run = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "run", "--repo", str(repo), "--no-branch"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            run_id = next((repo / ".security-skunkworks" / "runs").iterdir()).name
            verify = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "verify", "--repo", str(repo), "--run", run_id],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(verify.returncode, 0)
            self.assertIn("report_ready", verify.stdout)


if __name__ == "__main__":
    unittest.main()
