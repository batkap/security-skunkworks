# security-skunkworks

Local-first repository security orchestration for existing JS/TS, Dart/Flutter, and Python frontend, backend, and web/API repos.

## Current Trust Model

`security-skunkworks` is now a read-only-first security pilot.

- Default mode: `read-only`
- Default write scope: `.security-skunkworks/` only
- Default branch behavior: no branch creation or branch switching
- Verification is allowed to pass only when required scanners ran successfully and coverage is `full`
- Use copied repos first before trusting results on production-bound work

## First Trusted Release Scope

Supported now:

- JavaScript and TypeScript repos using `npm` or `pnpm`
- Dart and Flutter repos using `pub`
- Python repos using `pip` or `setuptools`
- CI and container surfaces around those repos
- Mixed Firebase + Flutter + TS repos when the trusted boundary stays inside JS/TS, Dart/Flutter, and first-class security assets

Reduced coverage:

- `yarn`, `bun`, and `poetry`
- Repos without first-class JS/TS, Dart/Flutter, or Python sources
- Native Android/iOS/macOS/Linux/Windows host code unless those paths are explicitly included
- Mixed repos where unsupported areas still affect the trust boundary

## Required Scanners

Install the scanners needed for the repo you are analyzing:

- `semgrep`
- `gitleaks`
- `npm audit` for `npm` repos
- `pnpm audit` for `pnpm` repos
- `osv-scanner` for Dart/Flutter repos with `pubspec.lock`
- `pip-audit` for Python repos
- `trivy` when Dockerfiles or other container assets are present

If a required scanner is missing or fails, the run will stay `blocked` and `verify` will fail.

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

## Start To Finish

1. Work on a copied target repo.

```bash
cp -R /path/to/real-repo /tmp/real-repo-copy
```

2. Initialize the target.

```bash
security-skunkworks init-target --repo /tmp/real-repo-copy
```

3. Run the default read-only workflow.

```bash
security-skunkworks run --repo /tmp/real-repo-copy
```

If you explicitly want branch hygiene for a later non-read-only run:

```bash
security-skunkworks init-target --repo /tmp/real-repo-copy --create-branch
```

4. Inspect the generated run workspace.

```text
/tmp/real-repo-copy/.security-skunkworks/runs/<run-id>/
```

Key outputs:

- `run-manifest.json`
- `ledger.json`
- `findings/findings.json`
- `threats/threat-model.json`
- `requirements/requirements.json`
- `plans/fixation-plan.md`
- `reports/final-report.md`
- `reports/compliance-matrix.md`
- `reports/traceability-matrix.md`

5. Print the final report.

```bash
security-skunkworks report --repo /tmp/real-repo-copy --run <run-id>
```

6. Verify the run.

```bash
security-skunkworks verify --repo /tmp/real-repo-copy --run <run-id>
```

`verify` should pass only when:

- the run status is `report_ready` or `verified`
- scanner coverage is `full`
- no gated findings remain
- the ledger and agent packs agree
- repo-native test commands pass, including `flutter analyze` and `flutter test` across trusted Flutter roots when present

7. Resume if you need to inspect unfinished work.

```bash
security-skunkworks resume --repo /tmp/real-repo-copy --run <run-id>
```

## Config

Place `security-skunkworks.yaml` at the target repo root to override defaults.

Start from the bundled template:

```bash
cp /path/to/security-skunkworks/assets/security-skunkworks.yaml /tmp/real-repo-copy/security-skunkworks.yaml
```

Implemented config fields:

- `default_mode`
- `include_paths`
- `exclude_paths`
- `compliance_frameworks`
- `primary_frameworks`
- `sensitive_paths`
- `docs_destination`
- `gate_thresholds`
- `required_scanners`

Unknown config keys fail fast.

## Status Meanings

- `report_ready`: full coverage and no gated findings remain
- `blocked`: coverage is partial or unsupported, or gated findings remain
- `verified`: `verify` passed for the run
- `failed`: orchestration or validation failed

## Repo Validation

Run the test suite:

```bash
python3 -m unittest discover -s tests
```

Validate the embedded skill through the repo wrapper when the Codex skill validator is available on the machine:

```bash
python3 scripts/validate_skill.py
```

## References

- [references/gate-policy.md](references/gate-policy.md)
- [references/scanner-prerequisites.md](references/scanner-prerequisites.md)
- [references/support-matrix.md](references/support-matrix.md)
- [references/copied-repo-pilot.md](references/copied-repo-pilot.md)
- [references/dart-flutter-playbook.md](references/dart-flutter-playbook.md)
- [references/js-ts-playbook.md](references/js-ts-playbook.md)
- [references/python-playbook.md](references/python-playbook.md)
