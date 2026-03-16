# Dart / Flutter Playbook

## Supported Boundary

- Dart and Flutter roots are discovered from `pubspec.yaml`
- Dependency coverage is based on `pubspec.lock` with `osv-scanner`
- Mixed Firebase + Flutter + TS repos are supported when the trusted boundary stays inside JS/TS, Dart/Flutter, Firebase config/rules, and other first-class supported roots
- Native host paths `android/`, `ios/`, `macos/`, `windows/`, and `linux/` are excluded from trusted verification unless explicitly included

## Required Scanners

- `semgrep`
- `gitleaks`
- `osv-scanner`
- `pnpm audit` or `npm audit` when the repo also includes JS/TS package roots
- `trivy` when container assets are present

## Verify Behavior

- `verify` prefers repo-local `.fvm/flutter_sdk/bin/flutter` when present
- Otherwise `verify` uses `fvm flutter`, then `flutter`
- Each trusted Flutter root runs `flutter analyze`
- Each trusted Flutter root with a `test/` directory runs `flutter test`
- Pure Dart roots fall back to `dart analyze` and `dart test`

## Built-In Checks

- Missing `FirebaseAppCheck.instance.activate` in Flutter entrypoints
- `FlutterSecureStorage` usage without `encryptedSharedPreferences: true`
- Token-like material stored in `SharedPreferences`
- Permissive TLS overrides such as `badCertificateCallback`
- CI definitions missing explicit security scans, including `osv-scanner`

## Operator Workflow

1. Copy the target repo.
2. Keep the first run `read-only`.
3. Install `semgrep`, `gitleaks`, `osv-scanner`, and any required JS/Python/container scanners.
4. Run `security-skunkworks init-target --repo <copy>` if you want an explicit starting point.
5. Run `security-skunkworks run --repo <copy>`.
6. Inspect `.security-skunkworks/repo-profile.md`, `run-manifest.json`, `ledger.json`, and `reports/final-report.md`.
7. Run `security-skunkworks verify --repo <copy> --run <run-id>` once scanners and repo-native tests are ready.
