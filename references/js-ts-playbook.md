# JS/TS Web/API Playbook

- First trusted release support: npm and pnpm based JS/TS repos.
- Inspect `package.json`, lockfiles, framework config, Dockerfiles, CI files, reverse-proxy config, and security docs.
- Required scanners: Semgrep, gitleaks, package-manager-matched dependency audit (`npm audit` or `pnpm audit`), and Trivy when container assets are present.
- Look for tracked secrets, weak auth or authz handling, wildcard CORS, token storage in browser storage, unsafe HTML rendering, container hardening gaps, and missing additive security scans.
- Preserve stronger existing controls; prefer additive CI changes over replacing an existing pipeline.
