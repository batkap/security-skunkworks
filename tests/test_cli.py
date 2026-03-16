from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from support import initialize_git_repo, install_fake_scanners


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


class CliTests(unittest.TestCase):
    def test_run_default_path_does_not_create_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "fixture"
            shutil.copytree(FIXTURES / "js-api", repo)
            initialize_git_repo(repo)
            before = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=repo,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            result = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "run", "--repo", str(repo)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            after = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=repo,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            branches = subprocess.run(
                ["git", "branch", "--list", "security-skunkworks/*"],
                cwd=repo,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            self.assertEqual(before, "main")
            self.assertEqual(after, "main")
            self.assertEqual(branches, "")
            self.assertTrue((repo / ".security-skunkworks").exists())
            self.assertFalse((repo / "SECURITY.md").exists())
            self.assertFalse((repo / "AGENTS.md").exists())

    def test_init_target_can_create_branch_when_explicitly_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "fixture"
            shutil.copytree(FIXTURES / "js-api-safe", repo)
            initialize_git_repo(repo)
            result = subprocess.run(
                [
                    "python3",
                    "-m",
                    "scripts.security_workflow",
                    "init-target",
                    "--repo",
                    str(repo),
                    "--mode",
                    "docs-only",
                    "--create-branch",
                    "--run",
                    "branch-run",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            current = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=repo,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            self.assertEqual(current, "security-skunkworks/branch-run")

    def test_run_can_reach_report_ready_with_fake_npm_scanners(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "fixture"
            shutil.copytree(FIXTURES / "js-api-safe", repo)
            fake_bin = Path(tmpdir) / "bin"
            fake_bin.mkdir()
            env = install_fake_scanners(fake_bin, package_manager="npm")
            result = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "run", "--repo", str(repo), "--run", "fixture-run"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            run_dir = repo / ".security-skunkworks" / "runs" / "fixture-run"
            ledger = json.loads((run_dir / "ledger.json").read_text(encoding="utf-8"))
            self.assertEqual(ledger["status"], "report_ready")
            self.assertEqual(ledger["coverage_status"], "full")
            verify = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "verify", "--repo", str(repo), "--run", "fixture-run"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

    def test_run_can_reach_report_ready_with_fake_pnpm_scanners(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "fixture"
            shutil.copytree(FIXTURES / "js-api-pnpm", repo)
            fake_bin = Path(tmpdir) / "bin"
            fake_bin.mkdir()
            env = install_fake_scanners(fake_bin, package_manager="pnpm")
            result = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "run", "--repo", str(repo), "--run", "fixture-pnpm"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            run_dir = repo / ".security-skunkworks" / "runs" / "fixture-pnpm"
            ledger = json.loads((run_dir / "ledger.json").read_text(encoding="utf-8"))
            self.assertEqual(ledger["status"], "report_ready")
            self.assertEqual(ledger["coverage_status"], "full")
            self.assertIn("pnpm-audit", ledger["scanners"])

    def test_verify_fails_for_blocked_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "fixture"
            shutil.copytree(FIXTURES / "js-api", repo)
            run = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "run", "--repo", str(repo)],
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

    def test_mixed_flutter_repo_can_reach_report_ready_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "fixture"
            shutil.copytree(FIXTURES / "flutter-firebase-pnpm-safe", repo)
            fake_bin = Path(tmpdir) / "bin"
            fake_bin.mkdir()
            env = install_fake_scanners(fake_bin, package_manager="pnpm")
            result = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "run", "--repo", str(repo), "--run", "flutter-run"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            run_dir = repo / ".security-skunkworks" / "runs" / "flutter-run"
            ledger = json.loads((run_dir / "ledger.json").read_text(encoding="utf-8"))
            self.assertEqual(ledger["status"], "report_ready")
            self.assertEqual(ledger["coverage_status"], "full")
            self.assertEqual(sorted(ledger["scanners"]), ["gitleaks", "osv-scanner", "pnpm-audit", "semgrep"])
            self.assertIn("packages/cache", ledger["supported_roots"])
            self.assertIn("android", ledger["excluded_host_paths"])
            verify = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "verify", "--repo", str(repo), "--run", "flutter-run"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)


if __name__ == "__main__":
    unittest.main()
