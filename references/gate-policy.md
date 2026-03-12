# Gate Policy

Treat these as gated by default:

- Authentication and authorization flow changes
- Session behavior changes
- Cryptography changes
- Secret rotation or credential replacement that affects runtime systems
- IAM, Firestore rules, database privilege, or externally visible API behavior changes

Treat these as low-risk by default:

- Durable documentation
- Run workspace updates
- Test additions
- Additive CI security checks
- Synthetic fixture cleanup

