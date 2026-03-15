## Security Skunkworks

This repository is wired for resumable local security orchestration.

- Active run: `${run_id}`
- Default mode: `read-only`
- Default branch behavior: no branch creation or branch switching
- Run: `security-skunkworks run --repo .`
- Resume: `security-skunkworks resume --repo . --run ${run_id}`
- Report: `security-skunkworks report --repo . --run ${run_id}`
- Verify: `security-skunkworks verify --repo . --run ${run_id}`

By default only `.security-skunkworks/` is written. Canonical repo docs are only updated when a non-default write mode is requested explicitly.
