import unittest

from scripts.models import ThreatInput
from scripts.requirements_engine import ComplianceMapper, RequirementExtractor


class RequirementEngineTests(unittest.TestCase):
    def test_extracts_requirements(self) -> None:
        extractor = RequirementExtractor()
        threats = [
            ThreatInput(
                id="T-001",
                category="INFORMATION_DISCLOSURE",
                title="Tracked key",
                description="A private key is committed",
                target="config/service-account.json",
                impact="CRITICAL",
                likelihood="HIGH",
            )
        ]
        result = extractor.extract_requirements(threats, "fixture")
        self.assertEqual(len(result.requirements), 3)
        self.assertTrue(result.requirements[0].acceptance_criteria)

    def test_generates_compliance_matrix(self) -> None:
        extractor = RequirementExtractor()
        threats = [
            ThreatInput(
                id="T-001",
                category="ELEVATION_OF_PRIVILEGE",
                title="Open authz",
                description="Broad access rules",
                target="firestore.rules",
                impact="HIGH",
                likelihood="HIGH",
            )
        ]
        reqs = extractor.extract_requirements(threats, "fixture")
        matrix = ComplianceMapper().generate_matrix(reqs, [])
        self.assertEqual(matrix.controls, {})


if __name__ == "__main__":
    unittest.main()

