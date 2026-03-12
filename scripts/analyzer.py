from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from .models import Finding, RepoProfile, Severity, ThreatInput, ThreatModel

TEXT_SUFFIXES = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".py",
    ".dart",
    ".json",
    ".yaml",
    ".yml",
    ".md",
    ".txt",
    ".env",
    ".rules",
    ".conf",
    ".ini",
    ".cfg",
    ".toml",
}

IGNORED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".dart_tool",
    ".next",
    ".idea",
}

SECRET_PATTERNS: Sequence[Tuple[str, str, Severity, str]] = (
    ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", Severity.CRITICAL, "Rotate the leaked key material and replace tracked secrets with fixtures or environment references."),
    ("service_account_key", r'"private_key"\s*:\s*"-----BEGIN [A-Z ]*PRIVATE KEY-----', Severity.CRITICAL, "Replace tracked service-account style secrets with synthetic fixtures and rotate any real credentials."),
    ("hardcoded_secret", r"(?i)(secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"']{12,}[\"']", Severity.HIGH, "Move hardcoded secrets into runtime configuration or secret management."),
)


def list_files(repo: Path) -> Iterable[Path]:
    for root, dirs, files in os.walk(repo):
        dirs[:] = [item for item in dirs if item not in IGNORED_DIRS]
        for name in files:
            yield Path(root) / name


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def detect_languages(files: Iterable[Path]) -> List[str]:
    counts: Dict[str, int] = {}
    mapping = {
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".py": "python",
        ".dart": "dart",
        ".java": "java",
        ".kt": "kotlin",
        ".go": "go",
        ".rb": "ruby",
    }
    for path in files:
        language = mapping.get(path.suffix.lower())
        if language:
            counts[language] = counts.get(language, 0) + 1
    return sorted(counts, key=counts.get, reverse=True)


def detect_frameworks(repo: Path) -> List[str]:
    frameworks: List[str] = []
    package_json = repo / "package.json"
    if package_json.exists():
        data = json.loads(read_text(package_json))
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        names = set(deps)
        if "next" in names:
            frameworks.append("nextjs")
        if "react" in names:
            frameworks.append("react")
        if "express" in names:
            frameworks.append("express")
        if "@nestjs/core" in names:
            frameworks.append("nestjs")
        if "fastify" in names:
            frameworks.append("fastify")
        if "vue" in names:
            frameworks.append("vue")
        if "@angular/core" in names:
            frameworks.append("angular")
    pyproject = repo / "pyproject.toml"
    if pyproject.exists():
        content = read_text(pyproject)
        for token, framework in (
            ("fastapi", "fastapi"),
            ("django", "django"),
            ("flask", "flask"),
            ("starlette", "starlette"),
        ):
            if token in content.lower():
                frameworks.append(framework)
    requirements = repo / "requirements.txt"
    if requirements.exists():
        content = read_text(requirements).lower()
        for token, framework in (
            ("fastapi", "fastapi"),
            ("django", "django"),
            ("flask", "flask"),
        ):
            if token in content:
                frameworks.append(framework)
    if (repo / "firebase.json").exists():
        frameworks.append("firebase")
    if (repo / "pubspec.yaml").exists():
        frameworks.append("flutter")
    return sorted(set(frameworks))


def detect_ci(repo: Path) -> List[str]:
    ci = []
    if (repo / ".github" / "workflows").exists():
        ci.append("github-actions")
    if (repo / "codemagic.yaml").exists():
        ci.append("codemagic")
    if (repo / ".gitlab-ci.yml").exists():
        ci.append("gitlab")
    if (repo / ".circleci" / "config.yml").exists():
        ci.append("circleci")
    return ci


def detect_security_artifacts(repo: Path) -> List[str]:
    artifact_paths = [
        "AGENTS.md",
        "SECURITY.md",
        "docs/security",
        "firebase.json",
        "firestore.rules",
        "functions/firestore.rules",
        "Dockerfile",
        "docker-compose.yml",
        ".github/workflows",
        "codemagic.yaml",
    ]
    return [item for item in artifact_paths if (repo / item).exists()]


def detect_surfaces(frameworks: Sequence[str], repo: Path) -> List[str]:
    surfaces = []
    if any(item in frameworks for item in ("react", "vue", "angular", "nextjs", "flutter")):
        surfaces.append("frontend")
    if any(item in frameworks for item in ("express", "nestjs", "fastify", "fastapi", "django", "flask", "firebase")):
        surfaces.append("backend")
    if (repo / "Dockerfile").exists() or (repo / "docker-compose.yml").exists():
        surfaces.append("containers")
    if detect_ci(repo):
        surfaces.append("ci")
    return sorted(set(surfaces))


def determine_maturity(repo: Path, security_artifacts: Sequence[str], findings: Sequence[Finding]) -> str:
    doc_count = sum(1 for item in ("AGENTS.md", "SECURITY.md", "docs/security") if (repo / item).exists())
    high_signal = any(item in security_artifacts for item in ("firebase.json", "functions/firestore.rules", ".github/workflows", "codemagic.yaml"))
    criticals = [finding for finding in findings if finding.severity == Severity.CRITICAL]
    if doc_count == 0 and not high_signal:
        return "none"
    if criticals and doc_count < 2:
        return "partial"
    return "established"


def relative(path: Path, base: Path) -> str:
    return str(path.relative_to(base))


def detect_findings(repo: Path) -> Tuple[List[Finding], List[str]]:
    findings: List[Finding] = []
    evidence: List[str] = []
    files = list(list_files(repo))
    for path in files:
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"Dockerfile", "AGENTS.md", "SECURITY.md", "README.md"}:
            continue
        content = read_text(path)
        rel = relative(path, repo)
        lowered = content.lower()
        if "firebase_app_check" in lowered or "appcheck" in lowered:
            evidence.append(f"app-check:{rel}")
        if "authorization" in lowered or "request.auth" in lowered or "firebaseauth" in lowered:
            evidence.append(f"auth-signal:{rel}")
        if path.name == "package.json" and any(token in lowered for token in ("eslint", "jest", "vitest", "mocha")):
            evidence.append(f"test-tooling:{rel}")
        for index, (category, pattern, severity, recommendation) in enumerate(SECRET_PATTERNS, start=1):
            if re.search(pattern, content):
                findings.append(
                    Finding(
                        id=f"F-{len(findings) + 1:03d}",
                        title=f"Tracked secret material in {rel}",
                        severity=severity,
                        confidence=0.95,
                        category=category,
                        description=f"Potential secret material was detected in {rel}.",
                        evidence_path=rel,
                        gate="gated" if severity == Severity.CRITICAL else "low-risk",
                        recommendation=recommendation,
                    )
                )
                break
        if rel.endswith("firestore.rules") and re.search(r"allow\s+read,\s*write:\s*if\s+request\.auth\s*!=\s*null\s*;", content):
            findings.append(
                Finding(
                    id=f"F-{len(findings) + 1:03d}",
                    title="Broad authenticated access in Firestore rules",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    category="authorization",
                    description="Catch-all Firestore rules allow any authenticated user to read and write broadly.",
                    evidence_path=rel,
                    gate="gated",
                    recommendation="Narrow Firestore rules to collection- and role-specific permissions backed by explicit tests.",
                )
            )
        if rel.endswith("codemagic.yaml") or rel.startswith(".github/workflows/"):
            if not any(token in lowered for token in ("gitleaks", "trivy", "semgrep", "npm audit", "pnpm audit", "pip-audit", "safety")):
                findings.append(
                    Finding(
                        id=f"F-{len(findings) + 1:03d}",
                        title="CI pipeline lacks explicit security checks",
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        category="ci-security",
                        description=f"{rel} exists but does not appear to run explicit security scanning commands.",
                        evidence_path=rel,
                        gate="low-risk",
                        recommendation="Add additive CI steps for secret scanning, dependency auditing, and static analysis.",
                    )
                )
    if not (repo / "SECURITY.md").exists():
        findings.append(
            Finding(
                id=f"F-{len(findings) + 1:03d}",
                title="Missing SECURITY.md",
                severity=Severity.MEDIUM,
                confidence=0.9,
                category="security-docs",
                description="The repository does not define a SECURITY.md disclosure and security posture document.",
                evidence_path="SECURITY.md",
                gate="low-risk",
                recommendation="Create SECURITY.md with disclosure, support, and security posture guidance.",
            )
        )
    if not (repo / "AGENTS.md").exists():
        findings.append(
            Finding(
                id=f"F-{len(findings) + 1:03d}",
                title="Missing AGENTS.md security operating contract",
                severity=Severity.LOW,
                confidence=0.85,
                category="agent-contract",
                description="The repository does not define agent operating rules for resumable security runs.",
                evidence_path="AGENTS.md",
                gate="low-risk",
                recommendation="Create AGENTS.md with run-state, gating, and update requirements for specialist agents.",
            )
        )
    return findings, sorted(set(evidence))


def build_repo_profile(repo: Path) -> RepoProfile:
    files = list(list_files(repo))
    findings, evidence = detect_findings(repo)
    languages = detect_languages(files)
    frameworks = detect_frameworks(repo)
    ci = detect_ci(repo)
    security_artifacts = detect_security_artifacts(repo)
    maturity = determine_maturity(repo, security_artifacts, findings)
    mode = "bootstrap" if maturity == "none" else "improve"
    return RepoProfile(
        repo_name=repo.name,
        repo_path=str(repo),
        languages=languages,
        frameworks=frameworks,
        surfaces=detect_surfaces(frameworks, repo),
        ci_providers=ci,
        security_artifacts=security_artifacts,
        evidence=evidence,
        maturity=maturity,
        mode=mode,
    )


def findings_for_repo(repo: Path) -> List[Finding]:
    findings, _ = detect_findings(repo)
    return findings


def findings_to_threats(findings: Sequence[Finding], repo_name: str) -> ThreatModel:
    threats: List[ThreatInput] = []
    category_map = {
        "private_key_block": "INFORMATION_DISCLOSURE",
        "service_account_key": "INFORMATION_DISCLOSURE",
        "hardcoded_secret": "INFORMATION_DISCLOSURE",
        "authorization": "ELEVATION_OF_PRIVILEGE",
        "ci-security": "TAMPERING",
        "security-docs": "REPUDIATION",
        "agent-contract": "REPUDIATION",
    }
    for finding in findings:
        impact = "CRITICAL" if finding.severity == Severity.CRITICAL else "HIGH" if finding.severity == Severity.HIGH else "MEDIUM"
        likelihood = "HIGH" if finding.confidence >= 0.85 else "MEDIUM"
        threats.append(
            ThreatInput(
                id=f"T-{finding.id.split('-')[-1]}",
                category=category_map.get(finding.category, "TAMPERING"),
                title=finding.title,
                description=finding.description,
                target=finding.evidence_path,
                impact=impact,
                likelihood=likelihood,
                evidence=[finding.evidence_path],
            )
        )
    summary = [
        f"Repository: {repo_name}",
        f"Threat count: {len(threats)}",
        "Threats are derived from repo evidence and finding severity.",
    ]
    return ThreatModel(repo_name=repo_name, summary=summary, threats=threats)
