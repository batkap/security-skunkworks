from __future__ import annotations

from pathlib import Path
import json
import os
import tempfile
import unittest

from scripts.analyzer import build_repo_profile
from scripts.configuration import DEFAULT_CONFIG
from scripts.scanners import required_scanner_names, run_scanners
from support import install_fake_scanners


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

    def test_mixed_flutter_repo_requires_osv_and_pnpm(self) -> None:
        profile = build_repo_profile(FIXTURES / "flutter-firebase-pnpm-safe")
        scanners = required_scanner_names(profile, DEFAULT_CONFIG)
        self.assertEqual(scanners, ["semgrep", "gitleaks", "osv-scanner", "pnpm-audit"])

    def test_osv_scanner_vulnerabilities_are_normalized_as_dependency_findings(self) -> None:
        profile = build_repo_profile(FIXTURES / "flutter-firebase-pnpm-safe")
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_bin = Path(tmpdir) / "bin"
            fake_bin.mkdir()
            env = install_fake_scanners(fake_bin, package_manager="pnpm")
            output_dir = Path(tmpdir) / "output"
            previous_path = os.environ.get("PATH", "")
            previous_mode = os.environ.get("OSV_SCANNER_MODE")
            previous_exit = os.environ.get("OSV_SCANNER_EXIT_CODE")
            os.environ["PATH"] = env["PATH"]
            os.environ["OSV_SCANNER_MODE"] = "vuln"
            os.environ["OSV_SCANNER_EXIT_CODE"] = "1"
            try:
                results = run_scanners(FIXTURES / "flutter-firebase-pnpm-safe", profile, DEFAULT_CONFIG, output_dir, "scanner-run")
            finally:
                os.environ["PATH"] = previous_path
                if previous_mode is None:
                    os.environ.pop("OSV_SCANNER_MODE", None)
                else:
                    os.environ["OSV_SCANNER_MODE"] = previous_mode
                if previous_exit is None:
                    os.environ.pop("OSV_SCANNER_EXIT_CODE", None)
                else:
                    os.environ["OSV_SCANNER_EXIT_CODE"] = previous_exit
            osv_result = results["osv-scanner"]
            self.assertTrue(osv_result.executed)
            self.assertTrue(osv_result.success)
            self.assertEqual(len(osv_result.findings), 1)
            finding = osv_result.findings[0]
            self.assertEqual(finding["category"], "dependency-audit")
            self.assertEqual(finding["source"], "osv-scanner")
            self.assertEqual(finding["severity"], "high")


if __name__ == "__main__":
    unittest.main()
