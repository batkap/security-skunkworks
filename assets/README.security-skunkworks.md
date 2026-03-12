## Security Skunkworks

This repository is wired for resumable local security orchestration.

- Run: `security-skunkworks run --repo .`
- Resume: `security-skunkworks resume --repo . --run ${run_id}`
- Report: `security-skunkworks report --repo . --run ${run_id}`
- Verify: `security-skunkworks verify --repo . --run ${run_id}`

The active repo-local workspace lives under `.security-skunkworks/`.

