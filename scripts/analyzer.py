from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from .configuration import DEFAULT_CONFIG, path_is_in_scope
from .models import CoverageStatus, Finding, RepoProfile, Severity, ThreatInput, ThreatModel

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
    ".dockerfile",
}

IGNORED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    ".fvm",
    "__pycache__",
    "dist",
    "build",
    ".dart_tool",
    ".next",
    ".idea",
}

SUPPORT_EXCLUDED_HOST_DIRS = {"android", "ios", "macos", "windows", "linux"}
GENERATED_FILENAMES = {"GeneratedPluginRegistrant.java", "GeneratedPluginRegistrant.m", "GeneratedPluginRegistrant.h"}
SUPPORTED_PACKAGE_MANAGERS = {"npm", "pnpm", "pip", "setuptools", "pub"}
SUPPORTED_LANGUAGES = {"javascript", "typescript", "python", "dart"}
PROJECT_MARKERS = {
    "package.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lockb",
    "pyproject.toml",
    "requirements.txt",
    "pubspec.yaml",
    "firebase.json",
    "firestore.rules",
    "codemagic.yaml",
}

SECRET_PATTERNS: Sequence[Tuple[str, str, Severity, str]] = (
    ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", Severity.CRITICAL, "Rotate the leaked key material and replace tracked secrets with fixtures or environment references."),
    ("service_account_key", r'"private_key"\s*:\s*"-----BEGIN [A-Z ]*PRIVATE KEY-----', Severity.CRITICAL, "Replace tracked service-account style secrets with synthetic fixtures and rotate any real credentials."),
    ("hardcoded_secret", r"(?i)(secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"']{12,}[\"']", Severity.HIGH, "Move hardcoded secrets into runtime configuration or secret management."),
)


def list_files(repo: Path, config: Dict[str, Any] | None = None) -> Iterable[Path]:
    effective = config or DEFAULT_CONFIG
    for root, dirs, files in os.walk(repo):
        dirs[:] = [item for item in dirs if item not in IGNORED_DIRS and path_is_in_scope(str(Path(root, item).relative_to(repo)), effective)]
        for name in files:
            candidate = Path(root) / name
            if path_is_in_scope(str(candidate.relative_to(repo)), effective):
                yield candidate


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def relative(path: Path, base: Path) -> str:
    return str(path.relative_to(base))


def _normalized_include_paths(config: Dict[str, Any]) -> List[str]:
    return [str(item).strip("./") for item in config.get("include_paths") or []]


def _host_path_explicitly_included(host_dir: str, config: Dict[str, Any]) -> bool:
    for item in _normalized_include_paths(config):
        if item == host_dir or item.startswith(f"{host_dir}/"):
            return True
    return False


def is_generated_support_path(relative_path: str) -> bool:
    normalized = relative_path.strip("./")
    path = Path(normalized)
    parts = path.parts
    if path.name in GENERATED_FILENAMES:
        return True
    if len(parts) >= 3 and tuple(parts[:3]) == ("ios", "Flutter", "ephemeral"):
        return True
    return False


def is_support_boundary_path(relative_path: str, config: Dict[str, Any] | None = None) -> bool:
    effective = config or DEFAULT_CONFIG
    normalized = relative_path.strip("./")
    if is_generated_support_path(normalized):
        return False
    parts = Path(normalized).parts
    if parts and parts[0] in SUPPORT_EXCLUDED_HOST_DIRS and not _host_path_explicitly_included(parts[0], effective):
        return False
    return True


def trusted_files(repo: Path, config: Dict[str, Any] | None = None) -> List[Path]:
    effective = config or DEFAULT_CONFIG
    return [path for path in list_files(repo, effective) if is_support_boundary_path(relative(path, repo), effective)]


def discover_project_dirs(repo: Path, config: Dict[str, Any] | None = None) -> List[Path]:
    found = set()
    trusted = trusted_files(repo, config)
    for path in trusted:
        if path.name in PROJECT_MARKERS:
            found.add(path.parent)
    if not found and trusted:
        found.add(repo)
    return sorted(found, key=lambda item: str(item.relative_to(repo)) or ".")


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


def detect_frameworks(project_dirs: Sequence[Path]) -> List[str]:
    frameworks: List[str] = []
    for project_dir in project_dirs:
        package_json = project_dir / "package.json"
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
        pyproject = project_dir / "pyproject.toml"
        if pyproject.exists():
            content = read_text(pyproject).lower()
            for token, framework in (
                ("fastapi", "fastapi"),
                ("django", "django"),
                ("flask", "flask"),
                ("starlette", "starlette"),
            ):
                if token in content:
                    frameworks.append(framework)
        requirements = project_dir / "requirements.txt"
        if requirements.exists():
            content = read_text(requirements).lower()
            for token, framework in (("fastapi", "fastapi"), ("django", "django"), ("flask", "flask")):
                if token in content:
                    frameworks.append(framework)
        if (project_dir / "firebase.json").exists():
            frameworks.append("firebase")
        if (project_dir / "pubspec.yaml").exists():
            frameworks.append("flutter")
    return sorted(set(frameworks))


def detect_package_managers(project_dirs: Sequence[Path]) -> List[str]:
    package_managers: List[str] = []
    for project_dir in project_dirs:
        if (project_dir / "pnpm-lock.yaml").exists():
            package_managers.append("pnpm")
        elif (project_dir / "yarn.lock").exists():
            package_managers.append("yarn")
        elif (project_dir / "bun.lockb").exists():
            package_managers.append("bun")
        elif (project_dir / "package.json").exists():
            package_managers.append("npm")
        if (project_dir / "pubspec.yaml").exists():
            package_managers.append("pub")
        pyproject = project_dir / "pyproject.toml"
        if pyproject.exists():
            lowered = read_text(pyproject).lower()
            if "[tool.poetry]" in lowered:
                package_managers.append("poetry")
            else:
                package_managers.append("setuptools")
        elif (project_dir / "requirements.txt").exists():
            package_managers.append("pip")
    return sorted(set(package_managers))


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


def support_status(languages: Sequence[str], package_managers: Sequence[str]) -> Tuple[bool, List[str]]:
    unsupported: List[str] = []
    if not any(language in SUPPORTED_LANGUAGES for language in languages):
        unsupported.append("No first-class supported JS/TS, Dart, or Python source files were detected inside the trusted boundary.")
    for language in languages:
        if language not in SUPPORTED_LANGUAGES:
            unsupported.append(f"Language '{language}' is outside the first trusted release support matrix.")
    for manager in package_managers:
        if manager not in SUPPORTED_PACKAGE_MANAGERS:
            unsupported.append(f"Package manager '{manager}' is not supported in the first trusted release.")
    return not unsupported, unsupported


def detect_excluded_host_paths(repo: Path, config: Dict[str, Any] | None = None) -> List[str]:
    effective = config or DEFAULT_CONFIG
    excluded = []
    for host_dir in sorted(SUPPORT_EXCLUDED_HOST_DIRS):
        if (repo / host_dir).exists() and not _host_path_explicitly_included(host_dir, effective):
            excluded.append(host_dir)
    return excluded


def support_reason(supported: bool, supported_roots: Sequence[str], excluded_host_paths: Sequence[str], unsupported_items: Sequence[str]) -> str:
    if supported:
        roots = ", ".join(supported_roots) or "."
        reason = f"Trusted boundary covers: {roots}"
        if not reason.endswith("."):
            reason += "."
        if excluded_host_paths:
            reason += f" Standard native host paths are excluded from trusted verification: {', '.join(excluded_host_paths)}."
        return reason
    details = "; ".join(unsupported_items) or "unsupported stack elements were detected."
    return f"Coverage is reduced because {details}"


def build_repo_profile(repo: Path, config: Dict[str, Any] | None = None) -> RepoProfile:
    trusted = trusted_files(repo, config)
    project_dirs = discover_project_dirs(repo, config)
    languages = detect_languages(trusted)
    frameworks = detect_frameworks(project_dirs)
    package_managers = detect_package_managers(project_dirs)
    supported, unsupported_items = support_status(languages, package_managers)
    findings, evidence = detect_findings(repo, config=config, include_repo_contract_findings=False)
    ci = detect_ci(repo)
    security_artifacts = detect_security_artifacts(repo)
    maturity = determine_maturity(repo, security_artifacts, findings)
    mode = "bootstrap" if maturity == "none" else "improve"
    supported_roots = [str(path.relative_to(repo)) or "." for path in project_dirs]
    excluded_host_paths = detect_excluded_host_paths(repo, config)
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
        package_managers=package_managers,
        supported=supported,
        unsupported_items=unsupported_items,
        supported_roots=supported_roots,
        excluded_host_paths=excluded_host_paths,
        support_reason=support_reason(supported, supported_roots, excluded_host_paths, unsupported_items),
    )


def _make_finding(
    findings: List[Finding],
    *,
    title: str,
    severity: Severity,
    category: str,
    description: str,
    evidence_path: str,
    gate: str,
    recommendation: str,
    source: str = "builtin",
    rule_id: str,
    surface: str,
    dedupe_key: str,
    confidence: float = 0.85,
    coverage: str = CoverageStatus.FULL.value,
) -> None:
    if any(item.dedupe_key == dedupe_key for item in findings):
        return
    findings.append(
        Finding(
            id=f"F-{len(findings) + 1:03d}",
            title=title,
            severity=severity,
            confidence=confidence,
            category=category,
            description=description,
            evidence_path=evidence_path,
            gate=gate,
            recommendation=recommendation,
            source=source,
            rule_id=rule_id,
            surface=surface,
            dedupe_key=dedupe_key,
            coverage=coverage,
        )
    )


def _signal_from_content(rel: str, content: str, evidence: List[str]) -> None:
    lowered = content.lower()
    if "firebase_app_check" in lowered or "appcheck" in lowered:
        evidence.append(f"app-check:{rel}")
    if "authorization" in lowered or "request.auth" in lowered or "firebaseauth" in lowered:
        evidence.append(f"auth-signal:{rel}")
    if "cors(" in lowered or "allow_origins" in lowered:
        evidence.append(f"cors-signal:{rel}")


def detect_findings(
    repo: Path,
    *,
    config: Dict[str, Any] | None = None,
    include_repo_contract_findings: bool = True,
) -> Tuple[List[Finding], List[str]]:
    effective = config or DEFAULT_CONFIG
    findings: List[Finding] = []
    evidence: List[str] = []
    files = list(list_files(repo, effective))
    flutter_entrypoints: List[Tuple[str, str]] = []
    for path in files:
        rel = relative(path, repo)
        trusted_path = is_support_boundary_path(rel, effective)
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"Dockerfile", "AGENTS.md", "SECURITY.md", "README.md"}:
            continue
        content = read_text(path)
        lowered = content.lower()
        _signal_from_content(rel, content, evidence)
        for category, pattern, severity, recommendation in SECRET_PATTERNS:
            if re.search(pattern, content):
                _make_finding(
                    findings,
                    title=f"Tracked secret material in {rel}",
                    severity=severity,
                    category=category,
                    description=f"Potential secret material was detected in {rel}.",
                    evidence_path=rel,
                    gate="gated" if severity == Severity.CRITICAL else "low-risk",
                    recommendation=recommendation,
                    rule_id=f"secret.{category}",
                    surface="repo",
                    dedupe_key=f"secret:{category}:{rel}",
                    confidence=0.95,
                )
                break
        if trusted_path and rel.endswith("firestore.rules") and re.search(r"allow\s+read,\s*write:\s*if\s+request\.auth\s*!=\s*null\s*;", content):
            _make_finding(
                findings,
                title="Broad authenticated access in Firestore rules",
                severity=Severity.HIGH,
                category="authorization",
                description="Catch-all Firestore rules allow any authenticated user to read and write broadly.",
                evidence_path=rel,
                gate="gated",
                recommendation="Narrow Firestore rules to collection- and role-specific permissions backed by explicit tests.",
                rule_id="firebase.firestore.catch_all_auth",
                surface="backend",
                dedupe_key=f"firestore:broad-auth:{rel}",
                confidence=0.9,
            )
        if path.name == "Dockerfile":
            if "user root" in lowered or "user 0" in lowered:
                _make_finding(
                    findings,
                    title="Container runs explicitly as root",
                    severity=Severity.HIGH,
                    category="container-hardening",
                    description="The Dockerfile sets the runtime user to root.",
                    evidence_path=rel,
                    gate="low-risk",
                    recommendation="Run the container as a dedicated non-root user.",
                    rule_id="docker.user_root",
                    surface="containers",
                    dedupe_key=f"docker:user-root:{rel}",
                )
            elif "user " not in lowered:
                _make_finding(
                    findings,
                    title="Container image does not declare a non-root runtime user",
                    severity=Severity.MEDIUM,
                    category="container-hardening",
                    description="The Dockerfile does not declare a runtime USER.",
                    evidence_path=rel,
                    gate="low-risk",
                    recommendation="Declare a non-root runtime user in the Dockerfile.",
                    rule_id="docker.user_missing",
                    surface="containers",
                    dedupe_key=f"docker:user-missing:{rel}",
                )
        if trusted_path and rel.endswith((".js", ".ts", ".jsx", ".tsx")) and "dangerouslysetinnerhtml" in lowered:
            _make_finding(
                findings,
                title="dangerouslySetInnerHTML usage detected",
                severity=Severity.MEDIUM,
                category="xss",
                description="Frontend code uses dangerouslySetInnerHTML, which increases XSS exposure.",
                evidence_path=rel,
                gate="low-risk",
                recommendation="Sanitize untrusted HTML or remove direct HTML injection paths.",
                rule_id="frontend.xss.dangerously_set_inner_html",
                surface="frontend",
                dedupe_key=f"frontend:xss:{rel}",
            )
        if trusted_path and rel.endswith((".js", ".ts", ".jsx", ".tsx")) and re.search(r"(localStorage|sessionStorage)\.setItem\([^)]*(token|auth|jwt)", content, re.IGNORECASE):
            _make_finding(
                findings,
                title="Token-like material stored in browser storage",
                severity=Severity.HIGH,
                category="session-management",
                description="Frontend code appears to store token-like material in localStorage or sessionStorage.",
                evidence_path=rel,
                gate="gated",
                recommendation="Prefer secure server-managed sessions or tighter storage controls for browser tokens.",
                rule_id="frontend.session.browser_storage",
                surface="frontend",
                dedupe_key=f"frontend:storage-token:{rel}",
            )
        if trusted_path and rel.endswith((".js", ".ts")) and re.search(r"origin\s*:\s*[\"']\*[\"']", content):
            _make_finding(
                findings,
                title="Wildcard CORS origin in JS server config",
                severity=Severity.HIGH,
                category="network-security",
                description="Server-side JS config appears to allow wildcard CORS origins.",
                evidence_path=rel,
                gate="gated",
                recommendation="Restrict CORS origins to known callers and document the allowlist.",
                rule_id="backend.cors.wildcard_js",
                surface="backend",
                dedupe_key=f"backend:cors-js:{rel}",
            )
        if trusted_path and rel.endswith(".py") and re.search(r"allow_origins\s*=\s*\[[^\]]*[\"']\*[\"']", content):
            _make_finding(
                findings,
                title="Wildcard CORS origin in Python server config",
                severity=Severity.HIGH,
                category="network-security",
                description="Python server config appears to allow wildcard CORS origins.",
                evidence_path=rel,
                gate="gated",
                recommendation="Restrict CORS origins to explicit trusted clients.",
                rule_id="backend.cors.wildcard_python",
                surface="backend",
                dedupe_key=f"backend:cors-python:{rel}",
            )
        if trusted_path and rel.endswith(".py") and re.search(r"debug\s*=\s*true", lowered):
            _make_finding(
                findings,
                title="Python debug mode enabled",
                severity=Severity.MEDIUM,
                category="error-handling",
                description="Python application code appears to enable debug mode.",
                evidence_path=rel,
                gate="low-risk",
                recommendation="Disable debug mode outside local development and guard it with environment-specific config.",
                rule_id="python.debug.enabled",
                surface="backend",
                dedupe_key=f"python:debug:{rel}",
            )
        if trusted_path and rel.endswith(".dart"):
            if path.name.startswith("main"):
                flutter_entrypoints.append((rel, lowered))
            if "fluttersecurestorage(" in lowered and "encryptedsharedpreferences: true" not in lowered:
                _make_finding(
                    findings,
                    title="Flutter secure storage is missing encrypted shared preferences",
                    severity=Severity.MEDIUM,
                    category="session-management",
                    description="FlutterSecureStorage is used without encryptedSharedPreferences enabled on Android.",
                    evidence_path=rel,
                    gate="low-risk",
                    recommendation="Enable encryptedSharedPreferences for FlutterSecureStorage Android options or use a stronger platform-backed storage configuration.",
                    rule_id="flutter.secure_storage.android_options",
                    surface="frontend",
                    dedupe_key=f"flutter:secure-storage:{rel}",
                )
            if "sharedpreferences" in lowered and re.search(r"\.(setstring|setstringlist)\(\s*[\"'][^\"']*(token|auth|jwt)[^\"']*[\"']", lowered):
                _make_finding(
                    findings,
                    title="Token-like material stored in SharedPreferences",
                    severity=Severity.HIGH,
                    category="session-management",
                    description="Dart code appears to store token-like material in SharedPreferences.",
                    evidence_path=rel,
                    gate="gated",
                    recommendation="Move token-like material to secure storage or a server-managed session mechanism.",
                    rule_id="flutter.session.shared_preferences",
                    surface="frontend",
                    dedupe_key=f"flutter:shared-preferences-token:{rel}",
                )
            if "badcertificatecallback" in lowered:
                _make_finding(
                    findings,
                    title="Permissive TLS certificate override in Dart client",
                    severity=Severity.HIGH,
                    category="network-security",
                    description="Dart client code overrides certificate validation, which can disable TLS protections.",
                    evidence_path=rel,
                    gate="gated",
                    recommendation="Remove permissive TLS overrides and rely on default platform certificate validation.",
                    rule_id="flutter.network.bad_certificate_callback",
                    surface="frontend",
                    dedupe_key=f"flutter:bad-certificate:{rel}",
                )
        if rel.endswith("codemagic.yaml") or rel.startswith(".github/workflows/"):
            if not any(token in lowered for token in ("gitleaks", "trivy", "semgrep", "npm audit", "pnpm audit", "pip-audit", "osv-scanner", "safety")):
                _make_finding(
                    findings,
                    title="CI pipeline lacks explicit security checks",
                    severity=Severity.MEDIUM,
                    category="ci-security",
                    description=f"{rel} exists but does not appear to run explicit security scanning commands.",
                    evidence_path=rel,
                    gate="low-risk",
                    recommendation="Add additive CI steps for secret scanning, dependency auditing, and static analysis.",
                    rule_id="ci.security_checks.missing",
                    surface="ci",
                    dedupe_key=f"ci:missing-scans:{rel}",
                    confidence=0.8,
                )
    for rel, lowered in flutter_entrypoints:
        if "firebaseappcheck.instance.activate" not in lowered:
            _make_finding(
                findings,
                title="Flutter entrypoint does not activate Firebase App Check",
                severity=Severity.MEDIUM,
                category="client-integrity",
                description="A Flutter entrypoint does not appear to activate Firebase App Check.",
                evidence_path=rel,
                gate="low-risk",
                recommendation="Activate Firebase App Check in each production-bound Flutter entrypoint.",
                rule_id="flutter.app_check.missing",
                surface="frontend",
                dedupe_key=f"flutter:app-check:{rel}",
            )
    if include_repo_contract_findings:
        if not (repo / "SECURITY.md").exists():
            _make_finding(
                findings,
                title="Missing SECURITY.md",
                severity=Severity.MEDIUM,
                category="security-docs",
                description="The repository does not define a SECURITY.md disclosure and security posture document.",
                evidence_path="SECURITY.md",
                gate="low-risk",
                recommendation="Create SECURITY.md with disclosure, support, and security posture guidance.",
                rule_id="docs.security_md.missing",
                surface="repo",
                dedupe_key="docs:security-md",
                confidence=0.9,
            )
        if not (repo / "AGENTS.md").exists():
            _make_finding(
                findings,
                title="Missing AGENTS.md security operating contract",
                severity=Severity.LOW,
                category="agent-contract",
                description="The repository does not define agent operating rules for resumable security runs.",
                evidence_path="AGENTS.md",
                gate="low-risk",
                recommendation="Create AGENTS.md with run-state, gating, and update requirements for specialist agents.",
                rule_id="docs.agents_md.missing",
                surface="repo",
                dedupe_key="docs:agents-md",
            )
    return findings, sorted(set(evidence))


def findings_for_repo(repo: Path, config: Dict[str, Any] | None = None) -> List[Finding]:
    findings, _ = detect_findings(repo, config=config)
    return findings


def findings_to_threats(findings: Sequence[Finding], repo_name: str, unsupported_items: Sequence[str] | None = None) -> ThreatModel:
    threats: List[ThreatInput] = []
    category_map = {
        "private_key_block": "INFORMATION_DISCLOSURE",
        "service_account_key": "INFORMATION_DISCLOSURE",
        "hardcoded_secret": "INFORMATION_DISCLOSURE",
        "secret-scanner": "INFORMATION_DISCLOSURE",
        "authorization": "ELEVATION_OF_PRIVILEGE",
        "session-management": "SPOOFING",
        "network-security": "TAMPERING",
        "ci-security": "TAMPERING",
        "container-hardening": "TAMPERING",
        "security-docs": "REPUDIATION",
        "agent-contract": "REPUDIATION",
        "dependency-audit": "TAMPERING",
        "container-audit": "TAMPERING",
        "client-integrity": "TAMPERING",
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
        "Threats are derived from repo evidence, normalized rule results, and finding severity.",
    ]
    if unsupported_items:
        summary.append(f"Coverage limits: {'; '.join(unsupported_items)}")
    return ThreatModel(repo_name=repo_name, summary=summary, threats=threats)
