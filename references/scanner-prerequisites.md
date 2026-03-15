# Scanner Prerequisites

Install the required external scanners before trusting a run as complete coverage.

- `semgrep`
- `gitleaks`
- `npm audit` for `npm` repos
- `pnpm audit` for `pnpm` repos
- `pip-audit` for Python repos
- `trivy` when Dockerfiles or other container assets are present

If a required scanner is missing or fails, the run remains blocked and verification must fail.
