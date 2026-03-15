from pathlib import Path
import unittest

from scripts.analyzer import build_repo_profile, findings_for_repo


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class AnalyzerTests(unittest.TestCase):
    def test_js_fixture_detects_secret(self) -> None:
        repo = FIXTURES / "js-api"
        findings = findings_for_repo(repo)
        self.assertTrue(any(finding.category in {"private_key_block", "service_account_key"} for finding in findings))

    def test_python_fixture_detects_python_framework(self) -> None:
        profile = build_repo_profile(FIXTURES / "python-api")
        self.assertIn("fastapi", profile.frameworks)
        self.assertIn("backend", profile.surfaces)
        self.assertIn("setuptools", profile.package_managers)
        self.assertTrue(profile.supported)

    def test_poetry_fixture_is_marked_unsupported_for_first_trusted_release(self) -> None:
        profile = build_repo_profile(FIXTURES / "python-api-poetry")
        self.assertFalse(profile.supported)
        self.assertTrue(profile.unsupported_items)


if __name__ == "__main__":
    unittest.main()
