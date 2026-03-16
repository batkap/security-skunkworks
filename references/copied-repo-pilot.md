# Copied Repo Pilot Qualification

Use local copies of real repos before trusting this tool on production-bound work.

## Pilot Rules

- Run against a copied repo, not an active working checkout
- Leave the default mode as `read-only`
- Confirm required scanners are installed before the run
- Expect all artifacts under `.security-skunkworks/runs/<run-id>/` inside the copied repo
- Do not create a branch for the first pilot run; default read-only mode does not need one
- For mixed Flutter/Firebase repos, trust the Dart/Flutter + JS/TS boundary and treat native host paths as excluded unless explicitly included
- Compare the final report against a manual senior-engineer review
- Verify that no canonical repo files changed

## Exit Criteria

- Findings are materially useful and not obviously incomplete
- Scanner coverage is `full`
- Verification passes
- The report clearly distinguishes gated work, low-risk follow-up, and unsupported areas
