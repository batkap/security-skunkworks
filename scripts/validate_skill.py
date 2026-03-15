from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


def validator_path() -> Path | None:
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    candidate = codex_home / "skills" / ".system" / "skill-creator" / "scripts" / "quick_validate.py"
    if candidate.exists():
        return candidate
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    validator = validator_path()
    if validator is None:
        print("Skill validator not found under $CODEX_HOME/skills/.system/skill-creator/scripts/quick_validate.py")
        return 1 if args.strict else 0
    completed = subprocess.run(
        ["python3", str(validator), str(Path(args.repo).resolve())],
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
