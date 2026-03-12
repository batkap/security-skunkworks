from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List, Tuple

import yaml


def detect_repo_commands(repo: Path) -> List[List[str]]:
    commands: List[List[str]] = []
    if (repo / "package.json").exists():
        commands.append(["npm", "test", "--if-present"])
    if (repo / "pnpm-lock.yaml").exists():
        commands.append(["pnpm", "test", "--if-present"])
    if (repo / "pyproject.toml").exists() or (repo / "pytest.ini").exists():
        commands.append(["python3", "-m", "pytest", "-q"])
    if (repo / "pubspec.yaml").exists():
        commands.append(["flutter", "test"])
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
    if not ledger_path.exists():
        return False, [f"Missing ledger: {ledger_path}"]
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    messages: List[str] = []
    for role, task in ledger.get("agent_tasks", {}).items():
        agent_path = run_dir / "agents" / f"{role}.md"
        if not agent_path.exists():
            messages.append(f"Missing agent pack for {role}")
            continue
        metadata = parse_agent_frontmatter(agent_path)
        if metadata.get("status") != task.get("status"):
            messages.append(f"Ledger status mismatch for {role}")
    for finding_id in ledger.get("gated_findings", []):
        if ledger.get("status") == "completed":
            messages.append(f"Gated finding {finding_id} remains unresolved")
    for command, code, _ in run_repo_checks(repo):
        if code != 0:
            messages.append(f"Command failed: {' '.join(command)}")
    return not messages, messages

