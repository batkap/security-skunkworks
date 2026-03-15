# Python Web/API Playbook

- First trusted release support: pip or setuptools style Python repos.
- Inspect `pyproject.toml`, `requirements.txt`, WSGI or ASGI entrypoints, Dockerfiles, deployment config, and security docs.
- Required scanners: Semgrep, gitleaks, pip-audit, and Trivy when container assets are present.
- Look for tracked secrets, unsafe debug settings, wildcard CORS, weak input validation, container hardening gaps, and missing pipeline security checks.
- Treat authz and crypto changes as gated even when the code path looks small.
