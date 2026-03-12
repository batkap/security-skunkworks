# security-skunkworks

Local-first repository security orchestration for existing frontend, backend, and web/API repositories.

It scans a local repo, derives findings and threats, turns those into security requirements and compliance mappings, writes resumable run state under `.security-skunkworks/`, updates durable docs, and produces a final report plus a detailed fixation plan.

## What It Does

- Inventories repo shape, maturity, CI, container, and security artifacts
- Detects common high-signal issues such as tracked secrets and broad Firestore rules
- Derives threat inputs and generates security requirements, acceptance criteria, and test cases
- Writes agent task packs for `coordinator`, `reviewer`, `fixer`, `tester`, `docs`, and `compliance`
- Updates `README.md`, `AGENTS.md`, `SECURITY.md`, and `docs/security/*` in the target repo
- Produces a final report, compliance matrix, threat traceability matrix, and detailed fixation plan

## Supported Targets

First-class in v1:

- JS/TS frontend and web/API repos
- Python web/API repos
- CI, Docker, config, and repo-doc surfaces around those repos

Secondary:

- Firebase/Flutter and other mixed-stack repos

## Install

From GitHub:

```bash
python3 -m pip install "git+https://github.com/batkap/security-skunkworks.git"
```

For local development:

```bash
git clone https://github.com/batkap/security-skunkworks.git
cd security-skunkworks
python3 -m pip install -e .
```

## Optional Config

Create `security-skunkworks.yaml` in the target repo if you want to override defaults.

Start from:

```bash
cp /path/to/security-skunkworks/assets/security-skunkworks.yaml /path/to/target/security-skunkworks.yaml
```

## Start To Finish

1. Initialize the target repo.

```bash
security-skunkworks init-target --repo /path/to/target
```

This creates `.security-skunkworks/`, initializes run state, and writes baseline durable docs if they do not exist.

2. Run the full workflow.

```bash
security-skunkworks run --repo /path/to/target
```

This inventories the repo, classifies `bootstrap` or `improve` mode, generates findings, threats, requirements, compliance outputs, agent packs, and the fixation plan.

3. Inspect the active run directory.

```text
/path/to/target/.security-skunkworks/runs/<run-id>/
```

Key files:

- `run-manifest.json`
- `ledger.json`
- `agents/*.md`
- `findings/findings.json`
- `threats/threat-model.json`
- `requirements/requirements.json`
- `plans/fixation-plan.md`
- `reports/final-report.md`

4. Resume a paused run.

```bash
security-skunkworks resume --repo /path/to/target --run <run-id>
```

This shows unfinished or blocked agent roles from the shared ledger.

5. Read the final report.

```bash
security-skunkworks report --repo /path/to/target --run <run-id>
```

6. Verify before closing the run.

```bash
security-skunkworks verify --repo /path/to/target --run <run-id>
```

This checks ledger and agent-pack consistency and runs detected repo-native test commands when available.

## What Gets Written To The Target Repo

- `.security-skunkworks/`
- `README.md`
- `AGENTS.md`
- `SECURITY.md`
- `docs/security/security-architecture.md`
- `docs/security/security-requirements.md`
- `docs/security/security-test-plan.md`
- `docs/security/compliance-matrix.md`
- `docs/security/security-review.md`

## Gate Model

Low-risk work is applied continuously. High-risk work is surfaced and stopped behind explicit gates.

Gated by default:

- Authentication and authorization flow changes
- Session behavior changes
- Cryptography changes
- Secret rotation affecting runtime systems
- IAM, Firestore, database privilege, or externally visible API behavior changes

## Validation

Run the local test suite:

```bash
python3 -m unittest discover -s tests
```

Validate the embedded skill:

```bash
python3 /Users/batu/.codex/skills/.system/skill-creator/scripts/quick_validate.py /path/to/security-skunkworks
```

