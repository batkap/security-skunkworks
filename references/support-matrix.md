# Support Matrix

## First Trusted Release

- Supported languages: JavaScript, TypeScript, Python
- Supported package managers: `npm`, `pnpm`, `pip`, `setuptools`
- Supported surfaces: frontend, backend, CI, containers around supported repos

## Reduced Coverage

- Repos with unsupported package managers such as `yarn`, `bun`, or `poetry`
- Repos where first-class supported languages are absent
- Mixed-language repos where unsupported areas materially affect the trust boundary

Reduced-coverage runs still emit findings and plans, but they must not be treated as production-ready verification.
