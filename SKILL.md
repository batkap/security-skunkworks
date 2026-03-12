---
name: security-skunkworks
description: Local-first repository security orchestration for existing frontend, backend, and web/API repositories. Use when Codex needs to assess a local repo, derive threats from code and config, extract security requirements, create or update SECURITY.md and docs/security outputs, coordinate reviewer/fixer/tester/docs/compliance agent work through .security-skunkworks run state, implement low-risk fixes, and produce a final report plus a detailed fixation plan.
---

# Security Skunkworks

## Overview

Run a resumable security workflow against a local repository. Use the CLI when you need durable run state, specialist task packs, requirements, compliance mappings, repo doc updates, and a final report that stops only at explicit gates.

## Workflow

1. Run `security-skunkworks init-target --repo <path>` when the target repo has not been initialized.
2. Run `security-skunkworks run --repo <path>` to inventory the repo, derive findings and threats, generate requirements, create run artifacts, and apply low-risk documentation work.
3. Read `AGENTS.md`, `.security-skunkworks/repo-profile.md`, `.security-skunkworks/runs/<run-id>/ledger.json`, and the role pack under `.security-skunkworks/runs/<run-id>/agents/` before doing role-specific work.
4. Use `security-skunkworks resume --repo <path> --run <id>` to inspect unfinished roles and continue a paused run.
5. Use `security-skunkworks report --repo <path> --run <id>` for the final report and `security-skunkworks verify --repo <path> --run <id>` before closing the run.

## Decision Rules

- Treat authentication, authorization, session, cryptography, secret rotation, IAM, Firestore rules, database privilege, and externally visible behavior changes as gated.
- Treat durable docs, repo-local run state, additive CI scan steps, test additions, and synthetic fixture cleanup as low-risk by default.
- Preserve stronger existing controls. Do not replace established security patterns unless the run evidence shows a specific regression or a gated redesign is approved.
- Write dated status updates back into the ledger and the agent pack before leaving work unfinished.

## References

- Read [references/gate-policy.md](references/gate-policy.md) for gate boundaries.
- Read [references/js-ts-playbook.md](references/js-ts-playbook.md) for JS/TS frontend and API repos.
- Read [references/python-playbook.md](references/python-playbook.md) for Python API repos.
- Read [references/compliance-baseline.md](references/compliance-baseline.md) for the default standards baseline.

## Outputs

- Keep active run state under `.security-skunkworks/`.
- Update `README.md`, `AGENTS.md`, `SECURITY.md`, and `docs/security/*` when low-risk.
- Produce a final report, compliance matrix, threat traceability matrix, and detailed fixation plan before closing the run.
