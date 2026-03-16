# Support Matrix

## First Trusted Release

- Supported languages: JavaScript, TypeScript, Dart, Flutter, Python
- Supported package managers: `npm`, `pnpm`, `pub`, `pip`, `setuptools`
- Supported surfaces: frontend, backend, CI, containers around supported repos
- Trusted mixed-repo boundary: JS/TS, Dart/Flutter, Firebase config/rules, and other first-class supported roots
- Explicitly excluded by default: `android/`, `ios/`, `macos/`, `windows/`, `linux/` host code unless explicitly included

## Reduced Coverage

- Repos with unsupported package managers such as `yarn`, `bun`, or `poetry`
- Repos where first-class supported languages are absent
- Mixed-language repos where unsupported areas materially affect the trust boundary

Reduced-coverage runs still emit findings and plans, but they must not be treated as production-ready verification.
