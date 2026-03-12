from __future__ import annotations

from typing import Dict, List

from .models import (
    ComplianceFramework,
    ComplianceMatrix,
    Priority,
    RequirementSet,
    RequirementType,
    SecurityDomain,
    SecurityRequirement,
    ThreatInput,
)


class RequirementExtractor:
    STRIDE_MAPPINGS = {
        "SPOOFING": {
            "domains": [SecurityDomain.AUTHENTICATION, SecurityDomain.SESSION_MANAGEMENT],
            "patterns": [
                ("Implement strong authentication for {target}", "Ensure {target} authenticates all users before granting access"),
                ("Validate identity tokens for {target}", "All authentication tokens used by {target} are cryptographically verified"),
                ("Implement session management for {target}", "Sessions related to {target} expire safely and cannot be replayed"),
            ],
        },
        "TAMPERING": {
            "domains": [SecurityDomain.INPUT_VALIDATION, SecurityDomain.DATA_PROTECTION],
            "patterns": [
                ("Validate all input to {target}", "All input to {target} is validated against expected types and formats"),
                ("Implement integrity checks for {target}", "Critical data handled by {target} is protected against unauthorized modification"),
                ("Protect {target} from unsafe pipeline changes", "Delivery changes affecting {target} are checked by repeatable security verification"),
            ],
        },
        "REPUDIATION": {
            "domains": [SecurityDomain.AUDIT_LOGGING, SecurityDomain.ERROR_HANDLING],
            "patterns": [
                ("Log security-relevant actions for {target}", "Security-relevant events affecting {target} are captured with enough detail for forensics"),
                ("Document the operational contract for {target}", "Operators and agents must have a current, durable operating contract for {target}"),
                ("Protect the reporting trail for {target}", "The audit and reporting trail for {target} is durable and reviewable"),
            ],
        },
        "INFORMATION_DISCLOSURE": {
            "domains": [SecurityDomain.DATA_PROTECTION, SecurityDomain.CRYPTOGRAPHY],
            "patterns": [
                ("Eliminate secret exposure in {target}", "Sensitive data in {target} is never stored in tracked source files"),
                ("Encrypt and control access to secrets related to {target}", "Secrets affecting {target} are protected in transit and at rest with managed access"),
                ("Reduce error and log leakage from {target}", "Logs and errors from {target} do not expose sensitive values or implementation detail"),
            ],
        },
        "DENIAL_OF_SERVICE": {
            "domains": [SecurityDomain.AVAILABILITY, SecurityDomain.INPUT_VALIDATION],
            "patterns": [
                ("Rate-limit requests for {target}", "Requests targeting {target} are bounded to prevent resource exhaustion"),
                ("Protect availability of {target}", "Service behavior for {target} degrades safely under load"),
                ("Set resource quotas for {target}", "The resource envelope for {target} is explicit and monitored"),
            ],
        },
        "ELEVATION_OF_PRIVILEGE": {
            "domains": [SecurityDomain.AUTHORIZATION, SecurityDomain.DATA_PROTECTION],
            "patterns": [
                ("Enforce authorization for {target}", "All operations affecting {target} enforce least-privilege authorization on the server side"),
                ("Constrain access scope for {target}", "Data and control paths behind {target} are limited to approved roles and identities"),
                ("Test authorization rules for {target}", "Authorization behavior for {target} is covered by automated abuse-case tests"),
            ],
        },
    }

    def extract_requirements(self, threats: List[ThreatInput], project_name: str) -> RequirementSet:
        req_set = RequirementSet(name=f"{project_name} Security Requirements", version="1.0")
        next_id = 1
        for threat in threats:
            for requirement in self._threat_to_requirements(threat, next_id):
                req_set.add(requirement)
            next_id += 3
        return req_set

    def _threat_to_requirements(self, threat: ThreatInput, start_id: int) -> List[SecurityRequirement]:
        mapping = self.STRIDE_MAPPINGS.get(threat.category, self.STRIDE_MAPPINGS["TAMPERING"])
        domains = mapping["domains"]
        patterns = mapping["patterns"]
        priority = self._calculate_priority(threat.impact, threat.likelihood)
        requirements: List[SecurityRequirement] = []
        for index, (title_pattern, desc_pattern) in enumerate(patterns):
            requirement = SecurityRequirement(
                id=f"SR-{start_id + index:03d}",
                title=title_pattern.format(target=threat.target),
                description=desc_pattern.format(target=threat.target),
                req_type=RequirementType.FUNCTIONAL if index == 0 else RequirementType.NON_FUNCTIONAL if index == 1 else RequirementType.CONSTRAINT,
                domain=domains[index % len(domains)],
                priority=priority,
                rationale=f"Mitigates threat: {threat.title}",
                threat_refs=[threat.id],
                acceptance_criteria=self._acceptance_criteria(threat.category, threat.target),
                test_cases=self._test_cases(threat.category, threat.target),
            )
            requirements.append(requirement)
        return requirements

    def _calculate_priority(self, impact: str, likelihood: str) -> Priority:
        score_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        combined = score_map.get(impact.upper(), 2) * score_map.get(likelihood.upper(), 2)
        if combined >= 12:
            return Priority.CRITICAL
        if combined >= 6:
            return Priority.HIGH
        if combined >= 3:
            return Priority.MEDIUM
        return Priority.LOW

    def _acceptance_criteria(self, category: str, target: str) -> List[str]:
        templates = {
            "SPOOFING": [
                f"Users authenticate before accessing {target}",
                "Authentication failures are logged and monitored",
                "Sensitive operations support stronger identity assurance",
            ],
            "TAMPERING": [
                f"All input to {target} is validated",
                "Pipeline and data integrity changes are detectable",
                "Unsafe modifications trigger review or rollback",
            ],
            "REPUDIATION": [
                f"Actions affecting {target} are traceable",
                "Run history captures timestamps and owners",
                "Security reports are durable and reviewable",
            ],
            "INFORMATION_DISCLOSURE": [
                f"Sensitive material affecting {target} is not tracked in source control",
                "Sensitive access is logged or otherwise traceable",
                "Logs and errors are sanitized",
            ],
            "DENIAL_OF_SERVICE": [
                f"Requests for {target} are bounded",
                "Availability behavior is tested under stress",
                "Resource limits are explicit",
            ],
            "ELEVATION_OF_PRIVILEGE": [
                f"Authorization is checked for operations affecting {target}",
                "Least-privilege access is enforced",
                "Privilege-abuse tests are automated",
            ],
        }
        return templates.get(category, templates["TAMPERING"])

    def _test_cases(self, category: str, target: str) -> List[str]:
        templates = {
            "SPOOFING": [
                f"Unauthenticated access to {target} is denied",
                "Invalid identity artifacts are rejected",
                "Replay and forged token attempts fail",
            ],
            "TAMPERING": [
                f"Malformed input to {target} is rejected",
                "Unsafe delivery changes are detectable",
                "Integrity regressions are surfaced by automated checks",
            ],
            "REPUDIATION": [
                "Run history includes actor and timestamp fields",
                "Agent task packs cannot be marked complete without status updates",
                "Reports contain a durable work log",
            ],
            "INFORMATION_DISCLOSURE": [
                f"Tracked secrets related to {target} are flagged",
                "Sensitive strings do not appear in generated logs or docs",
                "Protected material is referenced through configuration, not source",
            ],
            "DENIAL_OF_SERVICE": [
                f"Resource-heavy access to {target} is bounded",
                "Service behavior remains predictable under load",
                "Resource exhaustion scenarios are called out",
            ],
            "ELEVATION_OF_PRIVILEGE": [
                f"Unauthorized access to {target} is denied",
                "Privilege escalation paths are blocked",
                "Authorization rules have regression tests",
            ],
        }
        return templates.get(category, templates["TAMPERING"])


class ComplianceMapper:
    FRAMEWORK_CONTROLS = {
        ComplianceFramework.OWASP: {
            SecurityDomain.AUTHENTICATION: ["V2.1", "V2.2", "V2.3"],
            SecurityDomain.AUTHORIZATION: ["V4.1", "V4.2"],
            SecurityDomain.DATA_PROTECTION: ["V8.1", "V8.2", "V8.3"],
            SecurityDomain.INPUT_VALIDATION: ["V5.1", "V5.2", "V5.3"],
            SecurityDomain.CRYPTOGRAPHY: ["V6.1", "V6.2"],
            SecurityDomain.AUDIT_LOGGING: ["V7.1", "V7.2"],
        },
        ComplianceFramework.ASVS: {
            SecurityDomain.AUTHENTICATION: ["2.1.1", "2.1.7"],
            SecurityDomain.AUTHORIZATION: ["4.1.3", "4.2.1"],
            SecurityDomain.DATA_PROTECTION: ["8.2.1", "8.3.4"],
            SecurityDomain.INPUT_VALIDATION: ["5.1.3", "5.3.2"],
        },
        ComplianceFramework.CWE: {
            SecurityDomain.AUTHORIZATION: ["CWE-284", "CWE-285"],
            SecurityDomain.DATA_PROTECTION: ["CWE-200", "CWE-522"],
            SecurityDomain.INPUT_VALIDATION: ["CWE-20", "CWE-79", "CWE-89"],
            SecurityDomain.AVAILABILITY: ["CWE-400"],
        },
        ComplianceFramework.GDPR: {
            SecurityDomain.DATA_PROTECTION: ["Art. 25", "Art. 32"],
            SecurityDomain.AUDIT_LOGGING: ["Art. 30"],
        },
        ComplianceFramework.PCI_DSS: {
            SecurityDomain.AUTHENTICATION: ["8.1", "8.3"],
            SecurityDomain.DATA_PROTECTION: ["3.4", "4.1"],
            SecurityDomain.AUDIT_LOGGING: ["10.1", "10.2"],
        },
        ComplianceFramework.HIPAA: {
            SecurityDomain.AUTHENTICATION: ["164.312(d)"],
            SecurityDomain.AUTHORIZATION: ["164.312(a)(1)"],
            SecurityDomain.DATA_PROTECTION: ["164.312(e)(2)(ii)"],
        },
        ComplianceFramework.NIST_CSF: {
            SecurityDomain.AUTHENTICATION: ["PR.AC-1", "PR.AC-6"],
            SecurityDomain.DATA_PROTECTION: ["PR.DS-1", "PR.DS-5"],
            SecurityDomain.AUDIT_LOGGING: ["DE.AE-3"],
        },
        ComplianceFramework.ISO_27001: {
            SecurityDomain.AUTHENTICATION: ["A.9.2", "A.9.4"],
            SecurityDomain.DATA_PROTECTION: ["A.8.2", "A.10.1"],
            SecurityDomain.AUDIT_LOGGING: ["A.12.4"],
        },
        ComplianceFramework.SOC2: {
            SecurityDomain.AUTHENTICATION: ["CC6.1", "CC6.2"],
            SecurityDomain.AUTHORIZATION: ["CC6.3"],
            SecurityDomain.DATA_PROTECTION: ["CC6.7", "CC8.1"],
        },
    }

    def generate_matrix(self, requirement_set: RequirementSet, frameworks: List[ComplianceFramework]) -> ComplianceMatrix:
        controls: Dict[str, Dict[str, List[str]]] = {}
        gaps: Dict[str, Dict[str, List[str]]] = {}
        for framework in frameworks:
            controls[framework.value] = {}
            gaps[framework.value] = {"missing_controls": [], "weak_coverage": []}
            for domain, domain_controls in self.FRAMEWORK_CONTROLS.get(framework, {}).items():
                requirements = requirement_set.get_by_domain(domain)
                if requirements:
                    for control in domain_controls:
                        controls[framework.value][control] = [req.id for req in requirements]
                        if len(requirements) < 2:
                            gaps[framework.value]["weak_coverage"].append(control)
                else:
                    gaps[framework.value]["missing_controls"].extend(domain_controls)
        return ComplianceMatrix(
            frameworks=[framework.value for framework in frameworks],
            controls=controls,
            gaps=gaps,
        )

