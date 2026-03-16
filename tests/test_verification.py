from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from scripts.analyzer import build_repo_profile
from scripts.verification import detect_repo_commands


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class VerificationTests(unittest.TestCase):
    def test_detect_repo_commands_for_mixed_flutter_repo(self) -> None:
        repo = FIXTURES / "flutter-firebase-pnpm-safe"
        profile = build_repo_profile(repo)
        commands = detect_repo_commands(repo, profile.supported_roots)
        rendered = [(str(cwd.relative_to(repo)) or ".", " ".join(command)) for cwd, command in commands]
        self.assertIn((".", "pnpm test --if-present"), rendered)
        self.assertTrue(any(cwd == "." and command.endswith(" analyze") for cwd, command in rendered))
        self.assertTrue(any(cwd == "." and command.endswith(" test") for cwd, command in rendered))
        self.assertTrue(any(cwd == "packages/cache" and command.endswith(" analyze") for cwd, command in rendered))
        self.assertTrue(any(cwd == "packages/cache" and command.endswith(" test") for cwd, command in rendered))

    def test_detect_repo_commands_prefers_repo_bundled_flutter(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "fixture"
            shutil.copytree(FIXTURES / "flutter-firebase-pnpm-safe", repo)
            bundled = repo / ".fvm" / "flutter_sdk" / "bin"
            bundled.mkdir(parents=True)
            flutter = bundled / "flutter"
            flutter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            flutter.chmod(0o755)
            profile = build_repo_profile(repo)
            commands = detect_repo_commands(repo, profile.supported_roots)
            flutter_commands = [command for _, command in commands if command[-1] in {"analyze", "test"}]
            self.assertTrue(flutter_commands)
            self.assertTrue(all(command[0] == str(flutter) for command in flutter_commands))


if __name__ == "__main__":
    unittest.main()
