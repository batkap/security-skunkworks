from __future__ import annotations

import json
import subprocess
from pathlib import Path
from string import Template
from typing import Dict, Iterable, List

import yaml

from .models import (
    AgentStatus,
    AgentTask,
    CoverageStatus,
    FixationPlan,
    Finding,
    RepoProfile,
    RunLedger,
    RunMode,
    RunStatus,
    utc_now,
)


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"


def load_yaml(path: Path) -> Dict[str, object]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def write_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render_template(name: str, **values: object) -> str:
    template = Template((ASSETS / name).read_text(encoding="utf-8"))
    safe_values = {key: json.dumps(value, indent=2) if isinstance(value, (dict, list)) else str(value) for key, value in values.items()}
    return template.safe_substitute(safe_values)


def managed_section(tag: str, content: str) -> str:
    return f"<!-- security-skunkworks:{tag}:start -->\n{content.rstrip()}\n<!-- security-skunkworks:{tag}:end -->\n"


def upsert_section(path: Path, tag: str, content: str, heading: str) -> None:
    section = managed_section(tag, content)
    if not path.exists():
        path.write_text(f"# {heading}\n\n{section}", encoding="utf-8")
        return
    existing = path.read_text(encoding="utf-8")
    start = f"<!-- security-skunkworks:{tag}:start -->"
    end = f"<!-- security-skunkworks:{tag}:end -->"
    if start in existing and end in existing:
        before, _, rest = existing.partition(start)
        _, _, after = rest.partition(end)
        updated = before.rstrip() + "\n" + section + after.lstrip("\n")
        path.write_text(updated, encoding="utf-8")
        return
    suffix = "" if existing.endswith("\n") else "\n"
    path.write_text(existing + suffix + "\n" + section, encoding="utf-8")


def detect_git_branch(repo: Path, run_id: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return ""
    branch = f"security-skunkworks/{run_id}"
    current = subprocess.run(
        ["git", "branch", "--list", branch],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if current.stdout.strip():
        subprocess.run(["git", "switch", branch], cwd=repo, check=False, capture_output=True, text=True)
    else:
        subprocess.run(["git", "switch", "-c", branch], cwd=repo, check=False, capture_output=True, text=True)
    return branch


def allowed_write_scopes(mode: RunMode, docs_destination: str) -> List[str]:
    scopes = [".security-skunkworks"]
    if mode in {RunMode.DOCS_ONLY, RunMode.LOW_RISK}:
        scopes.extend(["README.md", "AGENTS.md", "SECURITY.md", docs_destination])
    return scopes


def create_workspace(
    repo: Path,
    run_id: str,
    profile: RepoProfile,
    mode: RunMode,
    effective_config: Dict[str, object],
    create_branch: bool = False,
) -> Dict[str, object]:
    branch = detect_git_branch(repo, run_id) if create_branch and mode != RunMode.READ_ONLY else ""
    workspace = repo / ".security-skunkworks"
    run_dir = workspace / "runs" / run_id
    for subdir in ("agents", "findings", "threats", "requirements", "plans", "reports"):
        (run_dir / subdir).mkdir(parents=True, exist_ok=True)
    profile_path = workspace / "repo-profile.md"
    profile_path.write_text(render_template("repo-profile.md", profile=json.dumps(profile.to_dict(), indent=2)), encoding="utf-8")
    ledger = RunLedger(
        run_id=run_id,
        repo_path=str(repo),
        status=RunStatus.INITIALIZED,
        mode=mode,
        branch=branch,
        coverage_status=CoverageStatus.PARTIAL,
        allowed_write_scopes=allowed_write_scopes(mode, str(effective_config.get("docs_destination", "docs/security"))),
        unsupported_items=list(profile.unsupported_items),
        supported_roots=list(profile.supported_roots),
        excluded_host_paths=list(profile.excluded_host_paths),
        support_reason=profile.support_reason,
        effective_config=effective_config,
    )
    write_json(
        run_dir / "run-manifest.json",
        {
            "run_id": run_id,
            "repo_path": str(repo),
            "mode": mode.value,
            "branch": branch,
            "created_at": utc_now(),
            "status": RunStatus.INITIALIZED.value,
            "allowed_write_scopes": ledger.allowed_write_scopes,
            "coverage_status": ledger.coverage_status.value,
            "unsupported_items": profile.unsupported_items,
            "supported_roots": profile.supported_roots,
            "excluded_host_paths": profile.excluded_host_paths,
            "support_reason": profile.support_reason,
            "effective_config": effective_config,
            "scanners": {},
        },
    )
    write_json(run_dir / "ledger.json", ledger.to_dict())
    return {"workspace": workspace, "run_dir": run_dir, "profile_path": profile_path, "ledger_path": run_dir / "ledger.json", "branch": branch}


def update_manifest(manifest_path: Path, payload: Dict[str, object]) -> None:
    write_json(manifest_path, payload)


def update_ledger(ledger_path: Path, ledger: RunLedger) -> None:
    ledger.touch()
    write_json(ledger_path, ledger.to_dict())


def build_agent_tasks(
    run_id: str,
    findings: List[Finding],
    repo_path: str,
    mode: RunMode,
    docs_destination: str,
    final_status: RunStatus,
) -> Dict[str, AgentTask]:
    now = utc_now()
    gated_ids = [finding.id for finding in findings if finding.gate == "gated"]
    report_command = f"security-skunkworks report --repo {repo_path} --run {run_id}"
    verify_command = f"security-skunkworks verify --repo {repo_path} --run {run_id}"
    write_docs = mode in {RunMode.DOCS_ONLY, RunMode.LOW_RISK}
    fixer_status = AgentStatus.BLOCKED if gated_ids else AgentStatus.SKIPPED if mode == RunMode.READ_ONLY else AgentStatus.COMPLETED
    fixer_completed_at = "" if fixer_status == AgentStatus.BLOCKED else now
    docs_status = AgentStatus.SKIPPED if not write_docs else AgentStatus.COMPLETED
    docs_completed_at = "" if docs_status == AgentStatus.SKIPPED else now
    return {
        "coordinator": AgentTask(
            role="coordinator",
            title="Own the end-to-end run state",
            summary="Keep sequencing, scanner coverage, branch hygiene, and final completion criteria aligned with the ledger.",
            dependencies=[],
            owned_paths=[".security-skunkworks"],
            commands=[report_command, verify_command],
            status=AgentStatus.COMPLETED if final_status in {RunStatus.REPORT_READY, RunStatus.BLOCKED} else AgentStatus.FAILED,
            started_at=now,
            updated_at=now,
            completed_at=now,
        ),
        "reviewer": AgentTask(
            role="reviewer",
            title="Review findings and threat mapping",
            summary="Convert repo evidence and scanner output into findings, severity, confidence, and threat inputs.",
            dependencies=["coordinator"],
            owned_paths=[".security-skunkworks/runs/*/findings", ".security-skunkworks/runs/*/threats"],
            commands=[report_command],
            status=AgentStatus.COMPLETED,
            started_at=now,
            updated_at=now,
            completed_at=now,
        ),
        "fixer": AgentTask(
            role="fixer",
            title="Stage safe remediation guidance and gated proposals",
            summary="Do not mutate canonical repo files in read-only mode. Leave sensitive changes as explicit gated items.",
            dependencies=["reviewer"],
            owned_paths=[".security-skunkworks/runs/*/plans", ".security-skunkworks/runs/*/reports"],
            commands=[report_command, verify_command],
            status=fixer_status,
            started_at=now,
            updated_at=now,
            completed_at=fixer_completed_at,
        ),
        "tester": AgentTask(
            role="tester",
            title="Verify requirements with automated checks",
            summary="Keep verification commands, scanner status, and requirement coverage aligned with the run state.",
            dependencies=["fixer"],
            owned_paths=[".security-skunkworks/runs/*/requirements", ".security-skunkworks/runs/*/reports"],
            commands=[verify_command],
            status=AgentStatus.COMPLETED,
            started_at=now,
            updated_at=now,
            completed_at=now,
        ),
        "docs": AgentTask(
            role="docs",
            title="Maintain durable repo documentation",
            summary="Update README, AGENTS, SECURITY, and security docs only when the selected run mode allows canonical repo writes.",
            dependencies=["reviewer"],
            owned_paths=[docs_destination],
            commands=[report_command],
            status=docs_status,
            started_at=now,
            updated_at=now,
            completed_at=docs_completed_at,
        ),
        "compliance": AgentTask(
            role="compliance",
            title="Maintain traceability and control mappings",
            summary="Keep the compliance matrix, coverage summary, and framework gap notes current.",
            dependencies=["reviewer"],
            owned_paths=[".security-skunkworks/runs/*/requirements", ".security-skunkworks/runs/*/reports"],
            commands=[report_command],
            status=AgentStatus.COMPLETED,
            started_at=now,
            updated_at=now,
            completed_at=now,
        ),
    }


def write_agent_packs(run_dir: Path, tasks: Dict[str, AgentTask], repo_path: str, run_id: str) -> None:
    for role, task in tasks.items():
        content = render_template(
            "agent-task.md",
            role=task.role,
            title=task.title,
            summary=task.summary,
            dependencies="\n".join(f"- {item}" for item in task.dependencies) or "- none",
            owned_paths="\n".join(f"- {item}" for item in task.owned_paths) or "- none",
            commands="\n".join(f"- `{item}`" for item in task.commands) or "- none",
            status=task.status.value,
            owner=task.owner,
            started_at=task.started_at,
            updated_at=task.updated_at,
            completed_at=task.completed_at,
            repo_path=repo_path,
            run_id=run_id,
        )
        (run_dir / "agents" / f"{role}.md").write_text(content, encoding="utf-8")


def write_durable_docs(repo: Path, run_id: str, profile: RepoProfile, fixation_plan: FixationPlan, mode: RunMode, docs_destination: str) -> None:
    if mode == RunMode.READ_ONLY:
        return
    readme_section = render_template("README.security-skunkworks.md", run_id=run_id, repo_name=repo.name)
    upsert_section(repo / "README.md", "readme", readme_section, repo.name)
    agents_section = render_template("AGENTS.security-skunkworks.md", run_id=run_id, mode=profile.mode, maturity=profile.maturity)
    upsert_section(repo / "AGENTS.md", "agents", agents_section, "AGENTS")
    security_content = render_template("SECURITY.md", repo_name=repo.name, run_id=run_id)
    (repo / "SECURITY.md").write_text(security_content, encoding="utf-8")
    docs_dir = repo / docs_destination
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "security-architecture.md").write_text(render_template("docs-security-architecture.md", repo_name=repo.name, mode=profile.mode), encoding="utf-8")
    (docs_dir / "security-test-plan.md").write_text(
        render_template("docs-security-test-plan.md", repo_name=repo.name, low_risk="\n".join(f"- {item}" for item in fixation_plan.low_risk) or "- none"),
        encoding="utf-8",
    )


def write_reports(
    run_dir: Path,
    profile: RepoProfile,
    findings: Iterable[Finding],
    fixation_plan: FixationPlan,
    compliance_markdown: str,
    requirements_markdown: str,
    traceability_markdown: str,
    mode: RunMode,
    coverage_status: CoverageStatus,
    scanner_summary: str,
    coverage_summary: str,
    unsupported_summary: str,
) -> None:
    findings_list = list(findings)
    findings_markdown = "\n".join(
        f"- `{finding.id}` {finding.severity.value}: {finding.title} ({finding.evidence_path}) [{finding.source}/{finding.rule_id or 'n/a'}]"
        for finding in findings_list
    ) or "- none"
    supported_roots = "\n".join(f"- {item}" for item in profile.supported_roots) or "- ."
    excluded_host_paths = "\n".join(f"- {item}" for item in profile.excluded_host_paths) or "- none"
    (run_dir / "reports" / "final-report.md").write_text(
        render_template(
            "final-report.md",
            repo_name=profile.repo_name,
            mode=mode.value,
            maturity=profile.maturity,
            coverage_status=coverage_status.value,
            support_reason=profile.support_reason,
            supported_roots=supported_roots,
            excluded_host_paths=excluded_host_paths,
            findings=findings_markdown,
            low_risk="\n".join(f"- {item}" for item in fixation_plan.low_risk) or "- none",
            gated="\n".join(f"- {item}" for item in fixation_plan.gated) or "- none",
            follow_up="\n".join(f"- {item}" for item in fixation_plan.follow_up) or "- none",
            scanner_summary=scanner_summary,
            coverage_summary=coverage_summary,
            unsupported_summary=unsupported_summary,
        ),
        encoding="utf-8",
    )
    (run_dir / "plans" / "fixation-plan.md").write_text(
        render_template(
            "fixation-plan.md",
            repo_name=profile.repo_name,
            low_risk="\n".join(f"- {item}" for item in fixation_plan.low_risk) or "- none",
            gated="\n".join(f"- {item}" for item in fixation_plan.gated) or "- none",
            follow_up="\n".join(f"- {item}" for item in fixation_plan.follow_up) or "- none",
            coverage_summary=coverage_summary,
            scanner_summary=scanner_summary,
            unsupported_summary=unsupported_summary,
        ),
        encoding="utf-8",
    )
    (run_dir / "reports" / "traceability-matrix.md").write_text(traceability_markdown, encoding="utf-8")
    (run_dir / "reports" / "compliance-matrix.md").write_text(compliance_markdown, encoding="utf-8")
    (run_dir / "requirements" / "requirements.md").write_text(requirements_markdown, encoding="utf-8")


def format_compliance_markdown(matrix: Dict[str, object]) -> str:
    lines = ["# Compliance Matrix"]
    for framework, controls in matrix.get("controls", {}).items():
        lines.extend(["", f"## {framework}"])
        for control, reqs in controls.items():
            lines.append(f"- `{control}` -> {', '.join(reqs)}")
        gaps = matrix.get("gaps", {}).get(framework, {})
        if gaps:
            lines.extend(["", "### Gaps"])
            for key, values in gaps.items():
                lines.append(f"- {key}: {', '.join(values) if values else 'none'}")
    return "\n".join(lines)


def format_traceability(traceability: Dict[str, List[str]]) -> str:
    lines = ["# Threat Traceability Matrix"]
    for threat_id, req_ids in traceability.items():
        lines.append(f"- `{threat_id}` -> {', '.join(req_ids)}")
    return "\n".join(lines)
