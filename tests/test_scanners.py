from __future__ import annotations

from pathlib import Path
import unittest

from scripts.analyzer import build_repo_profile
from scripts.configuration import DEFAULT_CONFIG
from scripts.scanners import required_scanner_names


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class ScannerTests(unittest.TestCase):
    def test_js_container_repo_requires_expected_scanners(self) -> None:
        profile = build_repo_profile(FIXTURES / "js-api")
        scanners = required_scanner_names(profile, DEFAULT_CONFIG)
        self.assertEqual(scanners, ["semgrep", "gitleaks", "npm-audit", "trivy"])

    def test_pnpm_repo_requires_pnpm_audit(self) -> None:
        profile = build_repo_profile(FIXTURES / "js-api-pnpm")
        scanners = required_scanner_names(profile, DEFAULT_CONFIG)
        self.assertEqual(scanners, ["semgrep", "gitleaks", "pnpm-audit"])

    def test_python_repo_requires_expected_scanners(self) -> None:
        profile = build_repo_profile(FIXTURES / "python-api")
        scanners = required_scanner_names(profile, DEFAULT_CONFIG)
        self.assertEqual(scanners, ["semgrep", "gitleaks", "pip-audit"])


if __name__ == "__main__":
    unittest.main()
