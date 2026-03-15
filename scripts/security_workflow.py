from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Sequence

from .analyzer import build_repo_profile, findings_for_repo, findings_to_threats
from .configuration import ConfigError, load_repo_config
from .models import (
    ComplianceFramework,
    CoverageStatus,
    FixationPlan,
    Finding,
    Severity,
    RunLedger,
    RunMode,
    RunStatus,
)
from .requirements_engine import ComplianceMapper, RequirementExtractor
from .scanners import run_scanners
from .verification import verify_run
from .workspace import (
    build_agent_tasks,
    create_workspace,
    format_compliance_markdown,
    format_traceability,
    update_ledger,
    update_manifest,
    write_agent_packs,
    write_durable_docs,
    write_json,
    write_reports,
)


def derive_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%SZ")


def select_frameworks(config: Dict[str, object]) -> List[ComplianceFramework]:
    configured = config.get("compliance_frameworks") or ["owasp", "asvs", "cwe"]
    frameworks = []
    for item in configured:
        try:
            frameworks.append(ComplianceFramework(str(item)))
        except ValueError:
            continue
    return frameworks or [ComplianceFramework.OWASP, ComplianceFramework.ASVS, ComplianceFramework.CWE]


def resolve_mode(config: Dict[str, object], requested: str | None) -> RunMode:
    value = requested or str(config.get("default_mode", RunMode.READ_ONLY.value))
    try:
        return RunMode(value)
    except ValueError as exc:
        raise SystemExit(f"Unsupported run mode: {value}") from exc


def dedupe_findings(findings: Sequence[Finding]) -> List[Finding]:
    rank = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
    }
    deduped: Dict[str, Finding] = {}
    for finding in findings:
        key = finding.dedupe_key or f"{finding.source}:{finding.rule_id}:{finding.evidence_path}:{finding.title}"
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = finding
            continue
        if rank[existing.severity] < rank[finding.severity]:
            deduped[key] = finding
    return list(deduped.values())


def finding_from_dict(payload: Dict[str, object]) -> Finding:
    return Finding(
        id=str(payload["id"]),
        title=str(payload["title"]),
        severity=Severity(str(payload["severity"])),
        confidence=float(payload["confidence"]),
        category=str(payload["category"]),
        description=str(payload["description"]),
        evidence_path=str(payload["evidence_path"]),
        gate=str(payload["gate"]),
        recommendation=str(payload["recommendation"]),
        source=str(payload.get("source", "builtin")),
        rule_id=str(payload.get("rule_id", "")),
        surface=str(payload.get("surface", "repo")),
        dedupe_key=str(payload.get("dedupe_key", "")),
        coverage=str(payload.get("coverage", CoverageStatus.FULL.value)),
    )


def fixation_plan_from_findings(findings: Sequence[Finding], coverage_status: CoverageStatus, unsupported_items: Sequence[str]) -> FixationPlan:
    low_risk = [finding.recommendation for finding in findings if finding.gate == "low-risk"]
    gated = [finding.recommendation for finding in findings if finding.gate == "gated"]
    follow_up = [
        "Review gated findings and approve or reject each high-risk change explicitly.",
        "Re-run security-skunkworks verify after resolving gated findings and scanner coverage gaps.",
    ]
    if coverage_status != CoverageStatus.FULL:
        follow_up.insert(0, "Resolve missing or failed required scanners before treating the report as complete coverage.")
    for item in unsupported_items:
        follow_up.append(f"Coverage limit: {item}")
    return FixationPlan(low_risk=low_risk, gated=gated, follow_up=follow_up)


def coverage_for_run(profile, scanner_results: Dict[str, object]) -> CoverageStatus:
    if profile.unsupported_items:
        return CoverageStatus.UNSUPPORTED
    if any((not result.available) or (result.executed and not result.success) for result in scanner_results.values()):
        return CoverageStatus.PARTIAL
    return CoverageStatus.FULL


def final_run_status(coverage_status: CoverageStatus, findings: Sequence[Finding]) -> RunStatus:
    if coverage_status != CoverageStatus.FULL:
        return RunStatus.BLOCKED
    if any(finding.gate == "gated" for finding in findings):
        return RunStatus.BLOCKED
    return RunStatus.REPORT_READY


def coverage_summary(profile, scanner_results: Dict[str, object]) -> List[str]:
    lines = []
    if profile.supported:
        lines.append("Supported stack detected for the first trusted release.")
    else:
        lines.append("Coverage is reduced because the repo is outside the first trusted release support matrix.")
    if not scanner_results:
        lines.append("No required scanners were selected for this repo.")
    for name, result in scanner_results.items():
        if not result.available:
            lines.append(f"{name}: missing")
        elif not result.executed:
            lines.append(f"{name}: not executed")
        elif not result.success:
            lines.append(f"{name}: failed")
        else:
            lines.append(f"{name}: ok ({len(result.findings)} findings)")
    return lines


def run_command(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.exists():
        raise SystemExit(f"Repository not found: {repo}")
    try:
        config = load_repo_config(repo)
    except ConfigError as exc:
        raise SystemExit(str(exc)) from exc
    mode = resolve_mode(config, args.mode)
    profile = build_repo_profile(repo, config=config)
    run_id = args.run or derive_run_id()
    paths = create_workspace(repo, run_id, profile, mode, config, create_branch=not args.no_branch)
    manifest_path = paths["run_dir"] / "run-manifest.json"
    builtin_findings = findings_for_repo(repo, config=config)
    scanner_results = run_scanners(repo, profile, config, paths["run_dir"] / "findings" / "scanners", run_id)
    scanner_findings = []
    for result in scanner_results.values():
        scanner_findings.extend(finding_from_dict(finding) for finding in result.findings)
    findings = dedupe_findings([*builtin_findings, *scanner_findings])
    coverage_status = coverage_for_run(profile, scanner_results)
    threat_model = findings_to_threats(findings, repo.name, profile.unsupported_items)
    extractor = RequirementExtractor()
    requirement_set = extractor.extract_requirements(threat_model.threats, repo.name)
    compliance = ComplianceMapper().generate_matrix(requirement_set, select_frameworks(config))
    fixation_plan = fixation_plan_from_findings(findings, coverage_status, profile.unsupported_items)
    status = final_run_status(coverage_status, findings)
    docs_destination = str(config.get("docs_destination", "docs/security"))
    tasks = build_agent_tasks(run_id, findings, str(repo), mode, docs_destination, status)
    summary_lines = coverage_summary(profile, scanner_results)
    ledger = RunLedger(
        run_id=run_id,
        repo_path=str(repo),
        status=status,
        mode=mode,
        branch=str(paths["branch"]) if paths["branch"] else "",
        findings=[finding.to_dict() for finding in findings],
        agent_tasks={role: task.to_dict() for role, task in tasks.items()},
        gated_findings=[finding.id for finding in findings if finding.gate == "gated"],
        coverage_status=coverage_status,
        scanners={name: result.to_dict() for name, result in scanner_results.items()},
        allowed_write_scopes=[".security-skunkworks"] if mode == RunMode.READ_ONLY else [".security-skunkworks", "README.md", "AGENTS.md", "SECURITY.md", docs_destination],
        unsupported_items=list(profile.unsupported_items),
        coverage_summary=summary_lines,
        effective_config=config,
    )
    update_ledger(paths["ledger_path"], ledger)
    update_manifest(
        manifest_path,
        {
            "run_id": run_id,
            "repo_path": str(repo),
            "mode": mode.value,
            "branch": str(paths["branch"]) if paths["branch"] else "",
            "created_at": ledger.created_at,
            "status": status.value,
            "allowed_write_scopes": ledger.allowed_write_scopes,
            "coverage_status": coverage_status.value,
            "unsupported_items": profile.unsupported_items,
            "effective_config": config,
            "scanners": ledger.scanners,
        },
    )
    write_json(paths["run_dir"] / "findings" / "findings.json", {"findings": [finding.to_dict() for finding in findings]})
    write_json(paths["run_dir"] / "threats" / "threat-model.json", threat_model.to_dict())
    write_json(paths["run_dir"] / "requirements" / "requirements.json", requirement_set.to_dict())
    write_json(paths["run_dir"] / "requirements" / "compliance-matrix.json", compliance.to_dict())
    write_json(paths["run_dir"] / "plans" / "fixation-plan.json", fixation_plan.to_dict())
    write_agent_packs(paths["run_dir"], tasks, str(repo), run_id)
    write_durable_docs(repo, run_id, profile, fixation_plan, mode, docs_destination)
    if mode != RunMode.READ_ONLY:
        docs_dir = repo / docs_destination
        docs_dir.mkdir(parents=True, exist_ok=True)
        (docs_dir / "security-requirements.md").write_text(requirement_set.export_markdown(), encoding="utf-8")
        (docs_dir / "compliance-matrix.md").write_text(format_compliance_markdown(compliance.to_dict()), encoding="utf-8")
        (docs_dir / "security-review.md").write_text(
            "# Security Review\n\n"
            + "\n".join(f"- `{finding.id}` {finding.severity.value}: {finding.title}" for finding in findings),
            encoding="utf-8",
        )
    scanner_summary = "\n".join(f"- {line}" for line in summary_lines) or "- none"
    unsupported_summary = "\n".join(f"- {item}" for item in profile.unsupported_items) or "- none"
    write_reports(
        paths["run_dir"],
        profile,
        findings,
        fixation_plan,
        format_compliance_markdown(compliance.to_dict()),
        requirement_set.export_markdown(),
        format_traceability(requirement_set.traceability_matrix()),
        mode,
        coverage_status,
        scanner_summary,
        "\n".join(f"- {line}" for line in summary_lines) or "- none",
        unsupported_summary,
    )
    print(f"Run complete: {run_id}")
    print(f"Mode: {mode.value}")
    print(f"Status: {status.value}")
    print(f"Coverage: {coverage_status.value}")
    print(f"Findings: {len(findings)}")
    print(f"Gated findings: {len(ledger.gated_findings)}")
    print(paths["run_dir"])
    return 0


def init_target(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.exists():
        raise SystemExit(f"Repository not found: {repo}")
    try:
        config = load_repo_config(repo)
    except ConfigError as exc:
        raise SystemExit(str(exc)) from exc
    mode = resolve_mode(config, args.mode)
    profile = build_repo_profile(repo, config=config)
    run_id = args.run or derive_run_id()
    create_workspace(repo, run_id, profile, mode, config, create_branch=not args.no_branch)
    if mode != RunMode.READ_ONLY:
        write_durable_docs(repo, run_id, profile, FixationPlan(low_risk=[], gated=[], follow_up=[]), mode, str(config.get("docs_destination", "docs/security")))
    print(f"Initialized target: {repo}")
    print(f"Run: {run_id}")
    print(f"Mode: {mode.value}")
    return 0


def report_command(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    run_id = args.run
    if not run_id:
        runs = sorted((repo / ".security-skunkworks" / "runs").iterdir())
        run_id = runs[-1].name
    run_dir = repo / ".security-skunkworks" / "runs" / run_id
    final_report = run_dir / "reports" / "final-report.md"
    if not final_report.exists():
        raise SystemExit(f"Missing report for run: {run_id}")
    print(final_report.read_text(encoding="utf-8"))
    return 0


def resume_command(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    run_dir = repo / ".security-skunkworks" / "runs" / args.run
    ledger_path = run_dir / "ledger.json"
    if not ledger_path.exists():
        raise SystemExit(f"Missing run ledger: {args.run}")
    ledger_data = json.loads(ledger_path.read_text(encoding="utf-8"))
    pending = {
        role: task["status"]
        for role, task in ledger_data.get("agent_tasks", {}).items()
        if task.get("status") not in {"completed", "skipped"}
    }
    print(
        json.dumps(
            {
                "run": args.run,
                "status": ledger_data.get("status"),
                "coverage_status": ledger_data.get("coverage_status"),
                "pending": pending,
                "unsupported_items": ledger_data.get("unsupported_items", []),
            },
            indent=2,
        )
    )
    return 0


def verify_command(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    ok, messages = verify_run(repo, args.run)
    if ok:
        run_dir = repo / ".security-skunkworks" / "runs" / args.run
        ledger_path = run_dir / "ledger.json"
        manifest_path = run_dir / "run-manifest.json"
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        ledger["status"] = RunStatus.VERIFIED.value
        manifest["status"] = RunStatus.VERIFIED.value
        write_json(ledger_path, ledger)
        update_manifest(manifest_path, manifest)
        print(f"Verification passed for {args.run}")
        return 0
    print("\n".join(messages))
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="security-skunkworks")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(subparser: argparse.ArgumentParser, include_run: bool = True) -> None:
        subparser.add_argument("--repo", required=True)
        if include_run:
            subparser.add_argument("--run")
        subparser.add_argument("--mode", choices=[item.value for item in RunMode])
        subparser.add_argument("--no-branch", action="store_true")

    init_parser = subparsers.add_parser("init-target")
    common(init_parser)
    init_parser.set_defaults(func=init_target)

    run_parser = subparsers.add_parser("run")
    common(run_parser)
    run_parser.set_defaults(func=run_command)

    resume_parser = subparsers.add_parser("resume")
    common(resume_parser)
    resume_parser.set_defaults(func=resume_command)

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--repo", required=True)
    report_parser.add_argument("--run")
    report_parser.set_defaults(func=report_command)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--repo", required=True)
    verify_parser.add_argument("--run", required=True)
    verify_parser.set_defaults(func=verify_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
