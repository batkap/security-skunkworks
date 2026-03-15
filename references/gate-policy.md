# Gate Policy

## Default First Trusted Release

- Default run mode is `read-only`.
- The tool may write only `.security-skunkworks/` unless a non-default mode is requested explicitly.
- Missing required scanners or unsupported stack elements reduce coverage and block verification.

## Gated By Default

- Authentication and authorization flow changes
- Session behavior changes
- Cryptography changes
- Secret rotation or credential replacement that affects runtime systems
- IAM, Firestore rules, database privilege, or externally visible API behavior changes

## Non-Gated Only When An Explicit Write Mode Allows It

- Durable documentation updates
- Run workspace updates
- Test additions
- Additive CI security checks
- Synthetic fixture cleanup
