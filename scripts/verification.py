from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List, Tuple

import yaml


TERMINAL_AGENT_STATUSES = {"completed", "skipped"}


def detect_repo_commands(repo: Path) -> List[List[str]]:
    commands: List[List[str]] = []
    if (repo / "package.json").exists():
        if (repo / "pnpm-lock.yaml").exists():
            commands.append(["pnpm", "test", "--if-present"])
        else:
            commands.append(["npm", "test", "--if-present"])
    if (repo / "pytest.ini").exists():
        commands.append(["python3", "-m", "pytest", "-q"])
    elif (repo / "pyproject.toml").exists() and (repo / "tests").exists():
        commands.append(["python3", "-m", "unittest", "discover", "-s", "tests"])
    return commands


def run_repo_checks(repo: Path) -> List[Tuple[List[str], int, str]]:
    results = []
    for command in detect_repo_commands(repo):
        completed = subprocess.run(command, cwd=repo, capture_output=True, text=True, check=False)
        output = (completed.stdout + "\n" + completed.stderr).strip()
        results.append((command, completed.returncode, output))
    return results


def parse_agent_frontmatter(path: Path) -> dict:
    content = path.read_text(encoding="utf-8")
    if not content.startswith("---\n"):
        return {}
    _, rest = content.split("---\n", 1)
    frontmatter, _, _ = rest.partition("\n---\n")
    return yaml.safe_load(frontmatter) or {}


def verify_run(repo: Path, run_id: str) -> Tuple[bool, List[str]]:
    run_dir = repo / ".security-skunkworks" / "runs" / run_id
    ledger_path = run_dir / "ledger.json"
    manifest_path = run_dir / "run-manifest.json"
    if not ledger_path.exists():
        return False, [f"Missing ledger: {ledger_path}"]
    if not manifest_path.exists():
        return False, [f"Missing manifest: {manifest_path}"]
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    messages: List[str] = []
    if ledger.get("run_id") != manifest.get("run_id"):
        messages.append("Ledger and manifest run_id do not match")
    if ledger.get("mode") != manifest.get("mode"):
        messages.append("Ledger and manifest mode do not match")
    if ledger.get("status") != manifest.get("status"):
        messages.append("Ledger and manifest status do not match")
    if ledger.get("coverage_status") != manifest.get("coverage_status"):
        messages.append("Ledger and manifest coverage_status do not match")
    for role, task in ledger.get("agent_tasks", {}).items():
        agent_path = run_dir / "agents" / f"{role}.md"
        if not agent_path.exists():
            messages.append(f"Missing agent pack for {role}")
            continue
        metadata = parse_agent_frontmatter(agent_path)
        if metadata.get("status") != task.get("status"):
            messages.append(f"Ledger status mismatch for {role}")
    coordinator = ledger.get("agent_tasks", {}).get("coordinator", {})
    if coordinator.get("status") != "completed":
        messages.append("Coordinator task must be completed before verify can pass")
    if ledger.get("status") not in {"report_ready", "verified"}:
        messages.append(f"Run status must be report_ready or verified for verification, found {ledger.get('status')}")
    if ledger.get("gated_findings"):
        messages.append("Run still contains gated findings")
    if ledger.get("coverage_status") != "full":
        messages.append(f"Coverage status must be full for verification, found {ledger.get('coverage_status')}")
    scanners = ledger.get("scanners", {})
    for name, scanner in scanners.items():
        if scanner.get("required") and not scanner.get("available"):
            messages.append(f"Required scanner missing: {name}")
        elif scanner.get("required") and not scanner.get("executed"):
            messages.append(f"Required scanner not executed: {name}")
        elif scanner.get("required") and not scanner.get("success"):
            messages.append(f"Required scanner failed: {name}")
    if ledger.get("unsupported_items"):
        messages.append("Run includes unsupported items; verification cannot pass with reduced coverage")
    for role, task in ledger.get("agent_tasks", {}).items():
        if task.get("status") not in TERMINAL_AGENT_STATUSES:
            messages.append(f"Agent task {role} is not in a terminal status")
    for command, code, _ in run_repo_checks(repo):
        if code != 0:
            messages.append(f"Command failed: {' '.join(command)}")
    return not messages, messages
