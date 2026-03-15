# Copied Repo Pilot Qualification

Use local copies of real repos before trusting this tool on production-bound work.

## Pilot Rules

- Run against a copied repo, not an active working checkout
- Leave the default mode as `read-only`
- Confirm required scanners are installed before the run
- Compare the final report against a manual senior-engineer review
- Verify that no canonical repo files changed

## Exit Criteria

- Findings are materially useful and not obviously incomplete
- Scanner coverage is `full`
- Verification passes
- The report clearly distinguishes gated work, low-risk follow-up, and unsupported areas
