from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from support import install_fake_scanners


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
GOLDEN = ROOT / "tests" / "golden"


def normalize_payload(value, repo: Path, run_dir: Path):
    if isinstance(value, dict):
        return {key: normalize_payload(item, repo, run_dir) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_payload(item, repo, run_dir) for item in value]
    if isinstance(value, str):
        normalized = value
        for original, token in (
            (str(repo), "<REPO_PATH>"),
            (str(repo.resolve()), "<REPO_PATH>"),
            (str(run_dir), "<RUN_DIR>"),
            (str(run_dir.resolve()), "<RUN_DIR>"),
        ):
            normalized = normalized.replace(original, token)
        normalized = normalized.replace("/private<REPO_PATH>", "<REPO_PATH>")
        normalized = normalized.replace("/private<RUN_DIR>", "<RUN_DIR>")
        normalized = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", "<TIMESTAMP>", normalized)
        return normalized
    return value


class GoldenOutputTests(unittest.TestCase):
    def test_read_only_run_matches_golden_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "fixture"
            shutil.copytree(FIXTURES / "js-api-safe", repo)
            fake_bin = Path(tmpdir) / "bin"
            fake_bin.mkdir()
            env = install_fake_scanners(fake_bin, package_manager="npm")
            result = subprocess.run(
                ["python3", "-m", "scripts.security_workflow", "run", "--repo", str(repo), "--run", "golden-run"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            run_dir = repo / ".security-skunkworks" / "runs" / "golden-run"
            for json_name in ("run-manifest.json", "ledger.json"):
                payload = json.loads((run_dir / json_name).read_text(encoding="utf-8"))
                normalized = normalize_payload(payload, repo, run_dir)
                expected = json.loads((GOLDEN / json_name).read_text(encoding="utf-8"))
                self.assertEqual(normalized, expected)
            for relative_name in (
                "reports/final-report.md",
                "plans/fixation-plan.md",
                "reports/traceability-matrix.md",
                "reports/compliance-matrix.md",
            ):
                actual = (run_dir / relative_name).read_text(encoding="utf-8").rstrip("\n")
                expected = (GOLDEN / relative_name).read_text(encoding="utf-8").rstrip("\n")
                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
