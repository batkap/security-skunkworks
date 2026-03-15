from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.configuration import ConfigError, load_repo_config, path_is_in_scope


class ConfigurationTests(unittest.TestCase):
    def test_invalid_config_key_fails_fast(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            (repo / "security-skunkworks.yaml").write_text("unknown_key: true\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_repo_config(repo)

    def test_include_and_exclude_scope(self) -> None:
        config = {
            "include_paths": ["src", "api"],
            "exclude_paths": ["src/generated"],
        }
        self.assertTrue(path_is_in_scope("src/app.py", config))
        self.assertTrue(path_is_in_scope("api/routes.ts", config))
        self.assertFalse(path_is_in_scope("tests/test_app.py", config))
        self.assertFalse(path_is_in_scope("src/generated/client.py", config))


if __name__ == "__main__":
    unittest.main()
