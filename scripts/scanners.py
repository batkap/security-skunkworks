from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from .models import Finding, RepoProfile, ScannerResult, Severity


IGNORED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".dart_tool",
}


def _severity_from_text(value: str) -> Severity:
    normalized = value.lower()
    if normalized in {"error", "critical", "high"}:
        return Severity.HIGH if normalized == "error" else Severity(normalized)
    if normalized in {"warning", "medium"}:
        return Severity.MEDIUM
    return Severity.LOW


def _project_dirs(repo: Path, markers: Sequence[str]) -> List[Path]:
    found: List[Path] = []
    for marker in markers:
        if (repo / marker).exists():
            found.append(repo)
            break
    for path in repo.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if not path.is_dir():
            continue
        if any((path / marker).exists() for marker in markers):
            found.append(path)
    unique: List[Path] = []
    seen = set()
    for item in found:
        value = str(item)
        if value in seen:
            continue
        seen.add(value)
        unique.append(item)
    return unique


def required_scanner_names(profile: RepoProfile, config: Dict[str, Any]) -> List[str]:
    required: List[str] = []
    configured = config.get("required_scanners", {})
    for language in profile.languages:
        required.extend(configured.get(language, []))
    for surface in profile.surfaces:
        required.extend(configured.get(surface, []))
    deduped: List[str] = []
    seen = set()
    for name in required:
        if name == "npm-audit" and "pnpm" in profile.package_managers and "npm" not in profile.package_managers:
            name = "pnpm-audit"
        if name in seen:
            continue
        deduped.append(name)
        seen.add(name)
    return deduped


def _scanner_binary(name: str) -> List[str]:
    if name == "npm-audit":
        return ["npm"]
    if name == "pnpm-audit":
        return ["pnpm"]
    if name == "pip-audit":
        if shutil.which("pip-audit"):
            return ["pip-audit"]
        return ["python3", "-m", "pip_audit"]
    return [name]


def _scanner_available(command: Sequence[str]) -> bool:
    binary = command[0]
    if binary == "python3" and len(command) > 2 and command[1] == "-m":
        return shutil.which(binary) is not None
    return shutil.which(binary) is not None


def _run_json_command(command: List[str], cwd: Path, output_path: Path | None = None) -> tuple[bool, str]:
    try:
        completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    except OSError as exc:
        return False, str(exc)
    output = (completed.stdout + "\n" + completed.stderr).strip()
    if output_path is not None and completed.stdout.strip():
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(completed.stdout, encoding="utf-8")
    return completed.returncode == 0, output


def _parse_semgrep(path: Path, prefix: str) -> List[Finding]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: List[Finding] = []
    for index, item in enumerate(payload.get("results", []), start=1):
        rel = str(item.get("path", ""))
        message = item.get("extra", {}).get("message", item.get("check_id", "Semgrep finding"))
        severity = _severity_from_text(str(item.get("extra", {}).get("severity", "medium")))
        findings.append(
            Finding(
                id=f"{prefix}-SEM-{index:03d}",
                title=message,
                severity=severity,
                confidence=0.8,
                category="static-analysis",
                description=message,
                evidence_path=rel,
                gate="low-risk" if severity in {Severity.LOW, Severity.MEDIUM} else "gated",
                recommendation="Review the Semgrep result and add the smallest safe remediation or suppression.",
                source="semgrep",
                rule_id=str(item.get("check_id", "semgrep")),
                surface="code",
                dedupe_key=f"semgrep:{item.get('check_id')}:{rel}",
            )
        )
    return findings


def _parse_gitleaks(path: Path, prefix: str) -> List[Finding]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: List[Finding] = []
    for index, item in enumerate(payload if isinstance(payload, list) else [], start=1):
        rel = str(item.get("File", ""))
        title = str(item.get("Description") or item.get("RuleID") or "Secret material reported by gitleaks")
        findings.append(
            Finding(
                id=f"{prefix}-GL-{index:03d}",
                title=title,
                severity=Severity.CRITICAL,
                confidence=0.95,
                category="secret-scanner",
                description=title,
                evidence_path=rel,
                gate="gated",
                recommendation="Rotate or replace the exposed secret and remove tracked material from source control.",
                source="gitleaks",
                rule_id=str(item.get("RuleID", "gitleaks")),
                surface="repo",
                dedupe_key=f"gitleaks:{item.get('RuleID')}:{rel}",
            )
        )
    return findings


def _parse_npm_audit(path: Path, prefix: str) -> List[Finding]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: List[Finding] = []
    reports = payload if isinstance(payload, list) else [payload]
    index = 1
    for report in reports:
        project = report.get("project", "")
        vulnerabilities = report.get("vulnerabilities", {})
        for name, item in vulnerabilities.items():
            severity = _severity_from_text(str(item.get("severity", "medium")))
            findings.append(
                Finding(
                    id=f"{prefix}-NPM-{index:03d}",
                    title=f"Dependency vulnerability in {name}",
                    severity=severity,
                    confidence=0.85,
                    category="dependency-audit",
                    description=f"npm audit reported a {severity.value} issue for {name} in {project or 'the repo root'}.",
                    evidence_path=project or "package.json",
                    gate="gated" if severity in {Severity.CRITICAL, Severity.HIGH} else "low-risk",
                    recommendation="Upgrade or replace the affected package and verify the fix with dependency audit output.",
                    source="npm-audit",
                    rule_id=name,
                    surface="dependencies",
                    dedupe_key=f"npm-audit:{project}:{name}",
                )
            )
            index += 1
    return findings


def _parse_pip_audit(path: Path, prefix: str) -> List[Finding]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: List[Finding] = []
    reports = payload if isinstance(payload, list) else [payload]
    index = 1
    for report in reports:
        project = report.get("project", "")
        for dependency in report.get("dependencies", []):
            for vuln in dependency.get("vulns", []):
                severity = _severity_from_text(str(vuln.get("severity", "high")))
                findings.append(
                    Finding(
                        id=f"{prefix}-PIP-{index:03d}",
                        title=f"Dependency vulnerability in {dependency.get('name', 'unknown')}",
                        severity=severity,
                        confidence=0.85,
                        category="dependency-audit",
                        description=str(vuln.get("description") or vuln.get("id") or "pip-audit reported a vulnerability."),
                        evidence_path=project or "pyproject.toml",
                        gate="gated" if severity in {Severity.CRITICAL, Severity.HIGH} else "low-risk",
                        recommendation="Upgrade or constrain the affected dependency and re-run pip-audit.",
                        source="pip-audit",
                        rule_id=str(vuln.get("id", dependency.get("name", "pip-audit"))),
                        surface="dependencies",
                        dedupe_key=f"pip-audit:{project}:{dependency.get('name')}:{vuln.get('id')}",
                    )
                )
                index += 1
    return findings


def _parse_trivy(path: Path, prefix: str) -> List[Finding]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: List[Finding] = []
    index = 1
    for result in payload.get("Results", []):
        target = str(result.get("Target", "Dockerfile"))
        for vuln in result.get("Vulnerabilities", []):
            severity = _severity_from_text(str(vuln.get("Severity", "medium")))
            findings.append(
                Finding(
                    id=f"{prefix}-TRV-{index:03d}",
                    title=f"Container vulnerability in {vuln.get('PkgName', 'unknown')}",
                    severity=severity,
                    confidence=0.85,
                    category="container-audit",
                    description=str(vuln.get("Title") or vuln.get("VulnerabilityID") or "Trivy reported a vulnerability."),
                    evidence_path=target,
                    gate="gated" if severity in {Severity.CRITICAL, Severity.HIGH} else "low-risk",
                    recommendation="Patch the base image or dependency and re-run Trivy.",
                    source="trivy",
                    rule_id=str(vuln.get("VulnerabilityID", "trivy")),
                    surface="containers",
                    dedupe_key=f"trivy:{target}:{vuln.get('VulnerabilityID')}",
                )
            )
            index += 1
    return findings


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_npm_audit(repo: Path, output_path: Path) -> tuple[bool, str]:
    reports = []
    errors = []
    for project_dir in _project_dirs(repo, ("package.json",)):
        try:
            completed = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=project_dir,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            errors.append((str(project_dir), str(exc)))
            continue
        if completed.stdout.strip():
            try:
                payload = json.loads(completed.stdout)
            except json.JSONDecodeError:
                payload = {"raw": completed.stdout}
        else:
            payload = {}
        payload["project"] = str(project_dir.relative_to(repo)) or "."
        reports.append(payload)
        if completed.returncode not in {0, 1}:
            errors.append((str(project_dir), completed.stderr.strip() or completed.stdout.strip()))
    _write_json(output_path, reports)
    return not errors, "\n".join(f"{project}: {message}" for project, message in errors)


def _run_pnpm_audit(repo: Path, output_path: Path) -> tuple[bool, str]:
    reports = []
    errors = []
    for project_dir in _project_dirs(repo, ("pnpm-lock.yaml",)):
        try:
            completed = subprocess.run(
                ["pnpm", "audit", "--json"],
                cwd=project_dir,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            errors.append((str(project_dir), str(exc)))
            continue
        if completed.stdout.strip():
            try:
                payload = json.loads(completed.stdout)
            except json.JSONDecodeError:
                payload = {"raw": completed.stdout}
        else:
            payload = {}
        payload["project"] = str(project_dir.relative_to(repo)) or "."
        reports.append(payload)
        if completed.returncode not in {0, 1}:
            errors.append((str(project_dir), completed.stderr.strip() or completed.stdout.strip()))
    _write_json(output_path, reports)
    return not errors, "\n".join(f"{project}: {message}" for project, message in errors)


def _run_pip_audit(repo: Path, output_path: Path) -> tuple[bool, str]:
    reports = []
    errors = []
    command_prefix = _scanner_binary("pip-audit")
    for project_dir in _project_dirs(repo, ("pyproject.toml", "requirements.txt")):
        command = command_prefix + ["-f", "json"]
        try:
            completed = subprocess.run(command, cwd=project_dir, capture_output=True, text=True, check=False)
        except OSError as exc:
            errors.append((str(project_dir), str(exc)))
            continue
        if completed.stdout.strip():
            try:
                payload = json.loads(completed.stdout)
            except json.JSONDecodeError:
                payload = {"raw": completed.stdout}
        else:
            payload = {}
        payload["project"] = str(project_dir.relative_to(repo)) or "."
        reports.append(payload)
        if completed.returncode not in {0, 1}:
            errors.append((str(project_dir), completed.stderr.strip() or completed.stdout.strip()))
    _write_json(output_path, reports)
    return not errors, "\n".join(f"{project}: {message}" for project, message in errors)


def run_scanners(repo: Path, profile: RepoProfile, config: Dict[str, Any], output_dir: Path, run_id: str) -> Dict[str, ScannerResult]:
    del run_id
    results: Dict[str, ScannerResult] = {}
    for name in required_scanner_names(profile, config):
        command = _scanner_binary(name)
        available = _scanner_available(command)
        result = ScannerResult(name=name, required=True, available=available, command=command)
        output_path = output_dir / f"{name}.json"
        result.output_path = str(output_path)
        if not available:
            result.coverage_gap = f"Required scanner {name} is not available on this machine."
            results[name] = result
            continue
        if name == "semgrep":
            full_command = ["semgrep", "scan", "--config", "auto", "--json", "--output", str(output_path), str(repo)]
            ok, error = _run_json_command(full_command, repo)
            result.command = full_command
            result.executed = True
            result.success = ok
            result.error = error if not ok else ""
            result.findings = [finding.to_dict() for finding in _parse_semgrep(output_path, "S")]
        elif name == "gitleaks":
            full_command = ["gitleaks", "detect", "--no-git", "--source", str(repo), "--report-format", "json", "--report-path", str(output_path)]
            ok, error = _run_json_command(full_command, repo)
            result.command = full_command
            result.executed = True
            result.success = ok
            result.error = error if not ok else ""
            result.findings = [finding.to_dict() for finding in _parse_gitleaks(output_path, "S")]
        elif name == "npm-audit":
            result.command = ["npm", "audit", "--json"]
            ok, error = _run_npm_audit(repo, output_path)
            result.executed = True
            result.success = ok
            result.error = error if not ok else ""
            result.findings = [finding.to_dict() for finding in _parse_npm_audit(output_path, "S")]
        elif name == "pnpm-audit":
            result.command = ["pnpm", "audit", "--json"]
            ok, error = _run_pnpm_audit(repo, output_path)
            result.executed = True
            result.success = ok
            result.error = error if not ok else ""
            result.findings = [finding.to_dict() for finding in _parse_npm_audit(output_path, "S")]
        elif name == "pip-audit":
            result.command = command + ["-f", "json"]
            ok, error = _run_pip_audit(repo, output_path)
            result.executed = True
            result.success = ok
            result.error = error if not ok else ""
            result.findings = [finding.to_dict() for finding in _parse_pip_audit(output_path, "S")]
        elif name == "trivy":
            full_command = ["trivy", "fs", "--format", "json", "--output", str(output_path), str(repo)]
            ok, error = _run_json_command(full_command, repo)
            result.command = full_command
            result.executed = True
            result.success = ok
            result.error = error if not ok else ""
            result.findings = [finding.to_dict() for finding in _parse_trivy(output_path, "S")]
        if result.executed and not result.success and not result.coverage_gap:
            result.coverage_gap = f"{name} did not complete successfully."
        results[name] = result
    return results
