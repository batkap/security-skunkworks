# Python Web/API Playbook

- Inspect `pyproject.toml`, `requirements.txt`, WSGI/ASGI entrypoints, Dockerfiles, and deployment config.
- Look for tracked secrets, unsafe debug settings, missing durable docs, weak input validation, and missing pipeline security checks.
- Treat authz and crypto changes as gated even when the code path looks small.

