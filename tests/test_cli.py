from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


class CliTests(unittest.TestCase):
    def test_run_creates_workspace(self) -> None:
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
            self.assertTrue((repo / "SECURITY.md").exists())


if __name__ == "__main__":
    unittest.main()

