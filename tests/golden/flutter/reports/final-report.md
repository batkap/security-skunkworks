# Security Skunkworks Final Report

- Repository: `fixture`
- Mode: `read-only`
- Maturity: `established`
- Coverage Status: `full`

## Trusted Boundary
Trusted boundary covers: ., functions, packages/cache. Standard native host paths are excluded from trusted verification: android, ios.

### Supported Roots
- .
- functions
- packages/cache

### Excluded Native Host Paths
- android
- ios

## Coverage Summary
- Trusted boundary covers: ., functions, packages/cache. Standard native host paths are excluded from trusted verification: android, ios.
- semgrep: ok (0 findings)
- gitleaks: ok (0 findings)
- osv-scanner: ok (0 findings)
- pnpm-audit: ok (0 findings)

## Scanner Summary
- semgrep: ok (0 findings)
- gitleaks: ok (0 findings)
- osv-scanner: ok (0 findings)
- pnpm-audit: ok (0 findings)

## Unsupported Or Reduced-Coverage Areas
- none

## Findings
- `F-001` medium: Missing SECURITY.md (SECURITY.md) [builtin/docs.security_md.missing]
- `F-002` low: Missing AGENTS.md security operating contract (AGENTS.md) [builtin/docs.agents_md.missing]

## Low-Risk Follow-Up
- Create SECURITY.md with disclosure, support, and security posture guidance.
- Create AGENTS.md with run-state, gating, and update requirements for specialist agents.

## Gated Work
- none

## Required Next Steps
- Review gated findings and approve or reject each high-risk change explicitly.
- Re-run security-skunkworks verify after resolving gated findings and scanner coverage gaps.
