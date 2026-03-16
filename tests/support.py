from __future__ import annotations

import os
from pathlib import Path
import subprocess
import textwrap


def fake_scanner_bin(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text(body.lstrip(), encoding="utf-8")
    path.chmod(0o755)


def install_fake_scanners(bin_dir: Path, package_manager: str = "npm") -> dict[str, str]:
    fake_scanner_bin(
        bin_dir,
        "semgrep",
        textwrap.dedent(
            """\
            #!/bin/sh
            while [ "$#" -gt 0 ]; do
              if [ "$1" = "--output" ]; then
                shift
                printf '{"results":[]}\n' > "$1"
              fi
              shift
            done
            exit 0
            """
        ),
    )
    fake_scanner_bin(
        bin_dir,
        "gitleaks",
        textwrap.dedent(
            """\
            #!/bin/sh
            while [ "$#" -gt 0 ]; do
              if [ "$1" = "--report-path" ]; then
                shift
                printf '[]\n' > "$1"
              fi
              shift
            done
            exit 0
            """
        ),
    )
    fake_scanner_bin(
        bin_dir,
        package_manager,
        textwrap.dedent(
            f"""\
            #!/bin/sh
            if [ "$1" = "audit" ]; then
              printf '{{"auditReportVersion":2,"vulnerabilities":{{}}}}\\n'
              exit 0
            fi
            if [ "$1" = "test" ]; then
              exit 0
            fi
            exit 0
            """
        ),
    )
    fake_scanner_bin(
        bin_dir,
        "osv-scanner",
        textwrap.dedent(
            """\
            #!/bin/sh
            mode="${OSV_SCANNER_MODE:-clean}"
            if [ "$mode" = "vuln" ]; then
              printf '%s\n' '{"results":[{"source":{"path":"pubspec.lock"},"packages":[{"package":{"name":"http"},"vulnerabilities":[{"id":"OSV-2026-0001","summary":"Critical advisory for http","database_specific":{"severity":"HIGH"}}],"groups":[{"ids":["OSV-2026-0001"]}]}]}]}'
              exit "${OSV_SCANNER_EXIT_CODE:-1}"
            fi
            printf '{"results":[]}\n'
            exit "${OSV_SCANNER_EXIT_CODE:-0}"
            """
        ),
    )
    fake_scanner_bin(
        bin_dir,
        "flutter",
        textwrap.dedent(
            """\
            #!/bin/sh
            if [ "$1" = "analyze" ] || [ "$1" = "test" ]; then
              exit 0
            fi
            exit 0
            """
        ),
    )
    fake_scanner_bin(
        bin_dir,
        "fvm",
        textwrap.dedent(
            """\
            #!/bin/sh
            if [ "$1" = "flutter" ]; then
              shift
              exec flutter "$@"
            fi
            exit 0
            """
        ),
    )
    fake_scanner_bin(
        bin_dir,
        "dart",
        textwrap.dedent(
            """\
            #!/bin/sh
            if [ "$1" = "analyze" ] || [ "$1" = "test" ]; then
              exit 0
            fi
            exit 0
            """
        ),
    )
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    return env


def initialize_git_repo(repo: Path) -> None:
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, capture_output=True, text=True, check=True)
