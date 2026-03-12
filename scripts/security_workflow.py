from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import yaml

from .analyzer import build_repo_profile, findings_for_repo, findings_to_threats
from .models import AgentTask, ComplianceFramework, FixationPlan, RunLedger, utc_now
from .requirements_engine import ComplianceMapper, RequirementExtractor
from .verification import verify_run
from .workspace import (
    build_agent_tasks,
    create_workspace,
    format_compliance_markdown,
    format_traceability,
    load_yaml,
    update_ledger,
    write_agent_packs,
    write_durable_docs,
    write_json,
    write_reports,
)


def derive_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%SZ")


def config_for_repo(repo: Path) -> Dict[str, object]:
    return load_yaml(repo / "security-skunkworks.yaml")


def select_frameworks(config: Dict[str, object]) -> List[ComplianceFramework]:
    configured = config.get("compliance_frameworks") or ["owasp", "asvs", "cwe"]
    frameworks = []
    for item in configured:
        try:
            frameworks.append(ComplianceFramework(str(item)))
        except ValueError:
            continue
    return frameworks or [ComplianceFramework.OWASP, ComplianceFramework.ASVS, ComplianceFramework.CWE]


def fixation_plan_from_findings(findings) -> FixationPlan:
    low_risk = [finding.recommendation for finding in findings if finding.gate == "low-risk"]
    gated = [finding.recommendation for finding in findings if finding.gate == "gated"]
    follow_up = [
        "Review gated findings and approve or reject each high-risk change explicitly.",
        "Re-run security-skunkworks verify after resolving gated findings.",
    ]
    return FixationPlan(low_risk=low_risk, gated=gated, follow_up=follow_up)


def run_command(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.exists():
        raise SystemExit(f"Repository not found: {repo}")
    config = config_for_repo(repo)
    profile = build_repo_profile(repo)
    run_id = args.run or derive_run_id()
    paths = create_workspace(repo, run_id, profile, create_branch=not args.no_branch)
    findings = findings_for_repo(repo)
    threat_model = findings_to_threats(findings, repo.name)
    extractor = RequirementExtractor()
    requirement_set = extractor.extract_requirements(threat_model.threats, repo.name)
    compliance = ComplianceMapper().generate_matrix(requirement_set, select_frameworks(config))
    fixation_plan = fixation_plan_from_findings(findings)
    tasks = build_agent_tasks(run_id, findings, str(repo))
    ledger = RunLedger(
        run_id=run_id,
        repo_path=str(repo),
        status="blocked" if fixation_plan.gated else "completed",
        mode=profile.mode,
        branch=str(paths["branch"]) if paths["branch"] else "",
        findings=[finding.to_dict() for finding in findings],
        agent_tasks={role: task.to_dict() for role, task in tasks.items()},
        gated_findings=[finding.id for finding in findings if finding.gate == "gated"],
    )
    update_ledger(paths["ledger_path"], ledger)
    write_json(paths["run_dir"] / "findings" / "findings.json", {"findings": [finding.to_dict() for finding in findings]})
    write_json(paths["run_dir"] / "threats" / "threat-model.json", threat_model.to_dict())
    write_json(paths["run_dir"] / "requirements" / "requirements.json", requirement_set.to_dict())
    write_json(paths["run_dir"] / "requirements" / "compliance-matrix.json", compliance.to_dict())
    write_json(paths["run_dir"] / "plans" / "fixation-plan.json", fixation_plan.to_dict())
    write_agent_packs(paths["run_dir"], tasks, str(repo), run_id)
    write_durable_docs(repo, run_id, profile, fixation_plan)
    docs_dir = repo / "docs" / "security"
    (docs_dir / "security-requirements.md").write_text(requirement_set.export_markdown(), encoding="utf-8")
    (docs_dir / "compliance-matrix.md").write_text(format_compliance_markdown(compliance.to_dict()), encoding="utf-8")
    (docs_dir / "security-review.md").write_text(
        "# Security Review\n\n"
        + "\n".join(f"- `{finding.id}` {finding.severity.value}: {finding.title}" for finding in findings),
        encoding="utf-8",
    )
    write_reports(
        paths["run_dir"],
        profile,
        findings,
        fixation_plan,
        format_compliance_markdown(compliance.to_dict()),
        requirement_set.export_markdown(),
        format_traceability(requirement_set.traceability_matrix()),
    )
    print(f"Run complete: {run_id}")
    print(f"Mode: {profile.mode}")
    print(f"Findings: {len(findings)}")
    print(f"Gated findings: {len(ledger.gated_findings)}")
    print(paths["run_dir"])
    return 0


def init_target(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    profile = build_repo_profile(repo)
    run_id = args.run or derive_run_id()
    create_workspace(repo, run_id, profile, create_branch=not args.no_branch)
    write_durable_docs(repo, run_id, profile, FixationPlan(low_risk=[], gated=[], follow_up=[]))
    print(f"Initialized target: {repo}")
    print(f"Run: {run_id}")
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
    statuses = {role: task["status"] for role, task in ledger_data.get("agent_tasks", {}).items() if task.get("status") != "completed"}
    print(json.dumps({"run": args.run, "pending": statuses}, indent=2))
    return 0


def verify_command(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    ok, messages = verify_run(repo, args.run)
    if ok:
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
