from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Sequence, Tuple

import yaml


TERMINAL_AGENT_STATUSES = {"completed", "skipped"}
IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", ".fvm", "__pycache__", "dist", "build", ".dart_tool", ".security-skunkworks"}


def _repo_relative(path: Path, repo: Path) -> str:
    try:
        return str(path.relative_to(repo)) or "."
    except ValueError:
        return str(path)


def _candidate_roots(repo: Path, supported_roots: Sequence[str] | None = None) -> List[Path]:
    roots = []
    if supported_roots:
        for item in supported_roots:
            roots.append(repo if item in {"", "."} else repo / item)
    else:
        roots.append(repo)
    unique: List[Path] = []
    seen = set()
    for root in sorted(roots, key=lambda value: _repo_relative(value, repo)):
        if not root.exists():
            continue
        value = str(root.resolve())
        if value in seen:
            continue
        seen.add(value)
        unique.append(root)
    return unique


def _pubspec_roots(repo: Path, supported_roots: Sequence[str] | None = None) -> List[Path]:
    roots: List[Path] = []
    for base in _candidate_roots(repo, supported_roots):
        if (base / "pubspec.yaml").exists():
            roots.append(base)
        for path in base.rglob("pubspec.yaml"):
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            roots.append(path.parent)
    unique: List[Path] = []
    seen = set()
    for root in sorted(roots, key=lambda value: _repo_relative(value, repo)):
        value = str(root.resolve())
        if value in seen:
            continue
        seen.add(value)
        unique.append(root)
    return unique


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def _is_flutter_root(root: Path) -> bool:
    pubspec = root / "pubspec.yaml"
    if not pubspec.exists():
        return False
    content = _read_text(pubspec).lower()
    return "sdk: flutter" in content or "\nflutter:\n" in content


def _flutter_prefix(repo: Path) -> List[str]:
    bundled = repo / ".fvm" / "flutter_sdk" / "bin" / "flutter"
    if bundled.exists():
        return [str(bundled)]
    if shutil.which("fvm"):
        return ["fvm", "flutter"]
    return ["flutter"]


def _dart_prefix() -> List[str]:
    return ["dart"]


def detect_repo_commands(repo: Path, supported_roots: Sequence[str] | None = None) -> List[Tuple[Path, List[str]]]:
    commands: List[Tuple[Path, List[str]]] = []
    if (repo / "package.json").exists():
        if (repo / "pnpm-lock.yaml").exists():
            commands.append((repo, ["pnpm", "test", "--if-present"]))
        else:
            commands.append((repo, ["npm", "test", "--if-present"]))
    if (repo / "pytest.ini").exists():
        commands.append((repo, ["python3", "-m", "pytest", "-q"]))
    elif (repo / "pyproject.toml").exists() and (repo / "tests").exists():
        commands.append((repo, ["python3", "-m", "unittest", "discover", "-s", "tests"]))
    flutter_prefix = _flutter_prefix(repo)
    dart_prefix = _dart_prefix()
    for root in _pubspec_roots(repo, supported_roots):
        if _is_flutter_root(root):
            commands.append((root, [*flutter_prefix, "analyze"]))
            if (root / "test").exists():
                commands.append((root, [*flutter_prefix, "test"]))
        else:
            commands.append((root, [*dart_prefix, "analyze"]))
            if (root / "test").exists():
                commands.append((root, [*dart_prefix, "test"]))
    return commands


def run_repo_checks(repo: Path, supported_roots: Sequence[str] | None = None) -> List[Tuple[Path, List[str], int, str]]:
    results = []
    for cwd, command in detect_repo_commands(repo, supported_roots):
        try:
            completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
            output = (completed.stdout + "\n" + completed.stderr).strip()
            results.append((cwd, command, completed.returncode, output))
        except OSError as exc:
            results.append((cwd, command, 127, str(exc)))
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
    for cwd, command, code, _ in run_repo_checks(repo, ledger.get("supported_roots")):
        if code != 0:
            messages.append(f"Command failed in {_repo_relative(cwd, repo)}: {' '.join(command)}")
    return not messages, messages
