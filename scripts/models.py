from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class RequirementType(str, Enum):
    FUNCTIONAL = "functional"
    NON_FUNCTIONAL = "non_functional"
    CONSTRAINT = "constraint"


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SecurityDomain(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_PROTECTION = "data_protection"
    AUDIT_LOGGING = "audit_logging"
    INPUT_VALIDATION = "input_validation"
    ERROR_HANDLING = "error_handling"
    SESSION_MANAGEMENT = "session_management"
    CRYPTOGRAPHY = "cryptography"
    NETWORK_SECURITY = "network_security"
    AVAILABILITY = "availability"
    DEVEX = "devex"


class ComplianceFramework(str, Enum):
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    SOC2 = "soc2"
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    OWASP = "owasp"
    CWE = "cwe"
    ASVS = "asvs"


class RunMode(str, Enum):
    READ_ONLY = "read-only"
    DOCS_ONLY = "docs-only"
    LOW_RISK = "low-risk"


class RunStatus(str, Enum):
    INITIALIZED = "initialized"
    INVENTORY_COMPLETE = "inventory_complete"
    ANALYSIS_COMPLETE = "analysis_complete"
    REPORT_READY = "report_ready"
    BLOCKED = "blocked"
    VERIFIED = "verified"
    FAILED = "failed"


class AgentStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class CoverageStatus(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


@dataclass
class RepoProfile:
    repo_name: str
    repo_path: str
    languages: List[str]
    frameworks: List[str]
    surfaces: List[str]
    ci_providers: List[str]
    security_artifacts: List[str]
    evidence: List[str]
    maturity: str
    mode: str
    package_managers: List[str] = field(default_factory=list)
    supported: bool = True
    unsupported_items: List[str] = field(default_factory=list)
    supported_roots: List[str] = field(default_factory=list)
    excluded_host_paths: List[str] = field(default_factory=list)
    support_reason: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: float
    category: str
    description: str
    evidence_path: str
    gate: str
    recommendation: str
    source: str = "builtin"
    rule_id: str = ""
    surface: str = "repo"
    dedupe_key: str = ""
    coverage: str = CoverageStatus.FULL.value

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class ThreatInput:
    id: str
    category: str
    title: str
    description: str
    target: str
    impact: str
    likelihood: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class ThreatModel:
    repo_name: str
    summary: List[str]
    threats: List[ThreatInput] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "repo_name": self.repo_name,
            "summary": self.summary,
            "threats": [threat.to_dict() for threat in self.threats],
        }


@dataclass
class SecurityRequirement:
    id: str
    title: str
    description: str
    req_type: RequirementType
    domain: SecurityDomain
    priority: Priority
    rationale: str = ""
    acceptance_criteria: List[str] = field(default_factory=list)
    test_cases: List[str] = field(default_factory=list)
    threat_refs: List[str] = field(default_factory=list)
    compliance_refs: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    status: str = "draft"
    owner: str = ""
    created_date: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["req_type"] = self.req_type.value
        data["domain"] = self.domain.value
        data["priority"] = self.priority.value
        return data

    def to_user_story(self) -> str:
        lines = [
            f"## {self.id}: {self.title}",
            "",
            "**User Story:**",
            "As a security-conscious system,",
            f"I want the system to {self.description.lower()},",
            f"So that {self.rationale.lower()}.",
            "",
            f"**Priority:** {self.priority.value}",
            f"**Type:** {self.req_type.value}",
            f"**Domain:** {self.domain.value}",
            "",
            "**Acceptance Criteria:**",
        ]
        lines.extend(f"- [ ] {item}" for item in self.acceptance_criteria or ["TBD"])
        lines.extend(["", "**Security Test Cases:**"])
        lines.extend(f"- {item}" for item in self.test_cases or ["TBD"])
        lines.extend(
            [
                "",
                "**Traceability:**",
                f"- Threats: {', '.join(self.threat_refs) or 'N/A'}",
                f"- Compliance: {', '.join(self.compliance_refs) or 'N/A'}",
            ]
        )
        return "\n".join(lines)


@dataclass
class RequirementSet:
    name: str
    version: str
    requirements: List[SecurityRequirement] = field(default_factory=list)

    def add(self, req: SecurityRequirement) -> None:
        self.requirements.append(req)

    def get_by_domain(self, domain: SecurityDomain) -> List[SecurityRequirement]:
        return [req for req in self.requirements if req.domain == domain]

    def get_by_priority(self, priority: Priority) -> List[SecurityRequirement]:
        return [req for req in self.requirements if req.priority == priority]

    def get_by_threat(self, threat_id: str) -> List[SecurityRequirement]:
        return [req for req in self.requirements if threat_id in req.threat_refs]

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "requirements": [requirement.to_dict() for requirement in self.requirements],
        }

    def export_markdown(self) -> str:
        lines = [f"# Security Requirements: {self.name}", "", f"Version: {self.version}"]
        for domain in SecurityDomain:
            domain_reqs = self.get_by_domain(domain)
            if not domain_reqs:
                continue
            lines.extend(["", f"## {domain.value.replace('_', ' ').title()}"])
            for req in domain_reqs:
                lines.extend(["", req.to_user_story()])
        return "\n".join(lines)

    def traceability_matrix(self) -> Dict[str, List[str]]:
        matrix: Dict[str, List[str]] = {}
        for req in self.requirements:
            for threat_id in req.threat_refs:
                matrix.setdefault(threat_id, []).append(req.id)
        return matrix


@dataclass
class ComplianceMatrix:
    frameworks: List[str]
    controls: Dict[str, Dict[str, List[str]]]
    gaps: Dict[str, Dict[str, List[str]]]

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class AgentTask:
    role: str
    title: str
    summary: str
    dependencies: List[str]
    owned_paths: List[str]
    commands: List[str]
    status: AgentStatus = AgentStatus.PENDING
    owner: str = "unassigned"
    started_at: str = ""
    updated_at: str = ""
    completed_at: str = ""

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class FixationPlan:
    low_risk: List[str]
    gated: List[str]
    follow_up: List[str]

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class ScannerResult:
    name: str
    required: bool
    available: bool
    executed: bool = False
    success: bool = False
    command: List[str] = field(default_factory=list)
    output_path: str = ""
    coverage_gap: str = ""
    error: str = ""
    findings: List[Dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class RunLedger:
    run_id: str
    repo_path: str
    status: RunStatus
    mode: RunMode
    branch: str
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    findings: List[Dict[str, object]] = field(default_factory=list)
    agent_tasks: Dict[str, Dict[str, object]] = field(default_factory=dict)
    gated_findings: List[str] = field(default_factory=list)
    coverage_status: CoverageStatus = CoverageStatus.PARTIAL
    scanners: Dict[str, Dict[str, object]] = field(default_factory=dict)
    allowed_write_scopes: List[str] = field(default_factory=list)
    unsupported_items: List[str] = field(default_factory=list)
    supported_roots: List[str] = field(default_factory=list)
    excluded_host_paths: List[str] = field(default_factory=list)
    support_reason: str = ""
    coverage_summary: List[str] = field(default_factory=list)
    effective_config: Dict[str, object] = field(default_factory=dict)

    def touch(self) -> None:
        self.updated_at = utc_now()

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["status"] = self.status.value
        data["mode"] = self.mode.value
        data["coverage_status"] = self.coverage_status.value
        return data
