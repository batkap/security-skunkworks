---
name: security-skunkworks
description: Local-first repository security orchestration for JS/TS, Dart/Flutter, and Python repos. Use when Codex must assess a local repo, derive threats from code and config, extract security requirements, create resumable run state under .security-skunkworks, coordinate reviewer/fixer/tester/docs/compliance work, and produce a final report plus a detailed fixation plan without mutating canonical repo files by default.
---

# Security Skunkworks

## Overview

Run a resumable security workflow against a local repository. Default to `read-only` mode and treat `.security-skunkworks/` as the only writable target-repo surface. Do not create or switch git branches unless branch creation is explicitly requested.

## Workflow

1. Run `security-skunkworks init-target --repo <path>` when the target repo has not been initialized.
2. Run `security-skunkworks run --repo <path>` to inventory the repo, derive findings and threats, generate requirements, create run artifacts, and emit a fixation plan.
3. Read `.security-skunkworks/repo-profile.md`, `.security-skunkworks/runs/<run-id>/ledger.json`, and the role pack under `.security-skunkworks/runs/<run-id>/agents/` before doing role-specific work.
4. Use `security-skunkworks resume --repo <path> --run <id>` to inspect unfinished or blocked roles.
5. Use `security-skunkworks report --repo <path> --run <id>` for the final report and `security-skunkworks verify --repo <path> --run <id>` before treating the run as production-trustworthy.

## Decision Rules

- Default mode is `read-only`.
- Default branch behavior is no branch creation or branch switching.
- Required scanners must be present for supported repos. Missing or failed scanners reduce coverage and block verification.
- Treat authentication, authorization, session, cryptography, secret rotation, IAM, Firestore rules, database privilege, and externally visible behavior changes as gated.
- Preserve stronger existing controls. Do not replace established security patterns unless the run evidence shows a specific regression or a gated redesign is approved.
- Write dated status updates back into the ledger and the agent pack before leaving work unfinished.

## Supported First Trusted Release

- JS and TS repos using `npm` or `pnpm`
- Dart and Flutter repos using `pub`
- Python repos using `pip` or `setuptools`
- CI and container surfaces around those repos

Reduced coverage:

- `yarn`, `bun`, `poetry`
- repos without first-class JS/TS, Dart/Flutter, or Python sources
- native Android/iOS/macOS/Linux/Windows host code unless explicitly included
- mixed repos where unsupported areas affect trust boundaries

## References

- Read [references/gate-policy.md](references/gate-policy.md) for gate boundaries.
- Read [references/scanner-prerequisites.md](references/scanner-prerequisites.md) for required scanner setup.
- Read [references/support-matrix.md](references/support-matrix.md) for the support boundary.
- Read [references/copied-repo-pilot.md](references/copied-repo-pilot.md) before pilot runs on real repos.
- Read [references/dart-flutter-playbook.md](references/dart-flutter-playbook.md) for Flutter repos.
- Read [references/js-ts-playbook.md](references/js-ts-playbook.md) for JS/TS repos.
- Read [references/python-playbook.md](references/python-playbook.md) for Python repos.
- Read [references/compliance-baseline.md](references/compliance-baseline.md) for the default standards baseline.

## Outputs

- Keep active run state under `.security-skunkworks/`.
- In default mode, do not write canonical repo files and do not create git branches.
- Produce a final report, compliance matrix, threat traceability matrix, and detailed fixation plan before closing the run.
