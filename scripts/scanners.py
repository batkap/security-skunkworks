from __future__ import annotations

import json
import re
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
    ".fvm",
    "__pycache__",
    "dist",
    "build",
    ".dart_tool",
}

SEMGRP_EXCLUDES = [
    ".security-skunkworks",
    "ios/Flutter/ephemeral",
    "**/GeneratedPluginRegistrant.java",
    "**/GeneratedPluginRegistrant.m",
    "**/GeneratedPluginRegistrant.h",
]

SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
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


def _repo_relative(path: Path, repo: Path) -> str:
    try:
        return str(path.relative_to(repo)) or "."
    except ValueError:
        return str(path)


def _scanner_roots(repo: Path, profile: RepoProfile) -> List[Path]:
    roots = []
    if profile.supported_roots:
        for item in profile.supported_roots:
            roots.append(repo if item in {"", "."} else repo / item)
    else:
        roots.append(repo)
    unique: List[Path] = []
    seen = set()
    for root in sorted(roots, key=lambda value: (_repo_relative(value, repo), len(str(value)))):
        if not root.exists():
            continue
        value = str(root.resolve())
        if value in seen:
            continue
        seen.add(value)
        unique.append(root)
    return unique


def _trusted_project_dirs(repo: Path, profile: RepoProfile, markers: Sequence[str]) -> List[Path]:
    found: List[Path] = []
    for root in _scanner_roots(repo, profile):
        for marker in markers:
            if (root / marker).exists():
                found.append(root)
                break
        for path in root.rglob("*"):
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            if not path.is_dir():
                continue
            if any((path / marker).exists() for marker in markers):
                found.append(path)
    unique: List[Path] = []
    seen = set()
    for item in sorted(found, key=lambda value: _repo_relative(value, repo)):
        value = str(item.resolve())
        if value in seen:
            continue
        seen.add(value)
        unique.append(item)
    return unique


def _lockfiles(repo: Path, profile: RepoProfile, name: str) -> List[Path]:
    files: List[Path] = []
    seen = set()
    for root in _trusted_project_dirs(repo, profile, (name.replace(".lock", ".yaml"), name) if name == "pubspec.lock" else (name,)):
        candidate = root / name
        if not candidate.exists():
            continue
        value = str(candidate.resolve())
        if value in seen:
            continue
        seen.add(value)
        files.append(candidate)
    return files


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


def _run_json_command_with_codes(
    command: List[str],
    cwd: Path,
    output_path: Path | None = None,
    success_codes: Iterable[int] = (0,),
) -> tuple[bool, str]:
    try:
        completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    except OSError as exc:
        return False, str(exc)
    output = (completed.stdout + "\n" + completed.stderr).strip()
    if output_path is not None and completed.stdout.strip():
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(completed.stdout, encoding="utf-8")
    return completed.returncode in set(success_codes), output


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


def _float_score(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    match = re.search(r"\b(\d+(?:\.\d+)?)\b", value)
    if not match:
        return None
    return float(match.group(1))


def _severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _osv_vulnerability_severity(vulnerability: Dict[str, Any]) -> Severity:
    scores: List[float] = []
    text_values: List[str] = []
    for item in vulnerability.get("severity", []) or []:
        if not isinstance(item, dict):
            continue
        score = _float_score(item.get("score"))
        if score is not None:
            scores.append(score)
    database_specific = vulnerability.get("database_specific", {})
    if isinstance(database_specific, dict):
        if isinstance(database_specific.get("severity"), str):
            text_values.append(database_specific["severity"])
        cvss = database_specific.get("cvss", {})
        if isinstance(cvss, dict):
            for key in ("score", "baseScore", "base_score"):
                score = _float_score(cvss.get(key))
                if score is not None:
                    scores.append(score)
    ecosystem_specific = vulnerability.get("ecosystem_specific", {})
    if isinstance(ecosystem_specific, dict) and isinstance(ecosystem_specific.get("severity"), str):
        text_values.append(ecosystem_specific["severity"])
    if scores:
        return _severity_from_score(max(scores))
    for value in text_values:
        return _severity_from_text(value)
    return Severity.MEDIUM


def _parse_osv_scanner(path: Path, repo: Path, prefix: str) -> List[Finding]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: List[Finding] = []
    index = 1
    for result in payload.get("results", []):
        source = result.get("source", {})
        source_path = source.get("path", "pubspec.lock")
        try:
            evidence_path = str(Path(source_path).resolve().relative_to(repo.resolve()))
        except ValueError:
            evidence_path = str(source_path)
        for package_entry in result.get("packages", []):
            package_info = package_entry.get("package", {})
            package_name = str(package_info.get("name", "unknown"))
            vulnerabilities = {
                str(item.get("id")): item
                for item in package_entry.get("vulnerabilities", [])
                if isinstance(item, dict) and item.get("id")
            }
            groups = package_entry.get("groups", []) or [{"ids": list(vulnerabilities)}]
            for group in groups:
                if not isinstance(group, dict):
                    continue
                ids = [str(item) for item in group.get("ids", []) if str(item)]
                related = [vulnerabilities[item] for item in ids if item in vulnerabilities]
                if not related and vulnerabilities:
                    related = list(vulnerabilities.values())
                primary = related[0] if related else {}
                severity = max((_osv_vulnerability_severity(item) for item in related), default=Severity.MEDIUM, key=lambda value: SEVERITY_RANK[value])
                title = f"Dependency vulnerability in {package_name}"
                description = str(primary.get("summary") or primary.get("details") or (ids[0] if ids else "osv-scanner reported a vulnerability."))
                rule_id = ids[0] if ids else str(primary.get("id", package_name))
                findings.append(
                    Finding(
                        id=f"{prefix}-OSV-{index:03d}",
                        title=title,
                        severity=severity,
                        confidence=0.85,
                        category="dependency-audit",
                        description=description,
                        evidence_path=evidence_path,
                        gate="gated" if severity in {Severity.CRITICAL, Severity.HIGH} else "low-risk",
                        recommendation="Upgrade the affected Dart or Flutter dependency to a fixed version and re-run osv-scanner.",
                        source="osv-scanner",
                        rule_id=rule_id,
                        surface="dependencies",
                        dedupe_key=f"osv-scanner:{evidence_path}:{package_name}:{rule_id}",
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


def _run_osv_scanner(repo: Path, profile: RepoProfile, output_path: Path) -> tuple[bool, str, List[str]]:
    lockfiles = _lockfiles(repo, profile, "pubspec.lock")
    if not lockfiles:
        return False, "No pubspec.lock files were found inside the trusted Dart boundary.", []
    command = ["osv-scanner", "scan", "source", "--format", "json"]
    command.extend([f"--lockfile={path}" for path in lockfiles])
    ok, output = _run_json_command_with_codes(command, repo, output_path=output_path, success_codes=(0, 1))
    return ok, output, command


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
            exclude_paths = list(dict.fromkeys([*(config.get("exclude_paths") or []), *profile.excluded_host_paths, *SEMGRP_EXCLUDES]))
            full_command = ["semgrep", "scan", "--config", "auto", "--json", "--output", str(output_path)]
            for item in exclude_paths:
                full_command.extend(["--exclude", item])
            full_command.append(str(repo))
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
        elif name == "osv-scanner":
            ok, error, full_command = _run_osv_scanner(repo, profile, output_path)
            result.command = full_command or ["osv-scanner", "scan", "source", "--format", "json"]
            result.executed = bool(full_command)
            result.success = ok
            result.error = error if not ok else ""
            result.findings = [finding.to_dict() for finding in _parse_osv_scanner(output_path, repo, "S")]
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
