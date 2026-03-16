from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

import yaml

from .models import RunMode


class ConfigError(ValueError):
    pass


DEFAULT_CONFIG: Dict[str, Any] = {
    "default_mode": RunMode.READ_ONLY.value,
    "include_paths": [],
    "exclude_paths": [
        ".git",
        "node_modules",
        ".venv",
        "venv",
        ".fvm",
        "__pycache__",
        "dist",
        "build",
    ],
    "compliance_frameworks": ["owasp", "asvs", "cwe"],
    "primary_frameworks": [],
    "sensitive_paths": [],
    "docs_destination": "docs/security",
    "gate_thresholds": {
        "default": "gated",
    },
    "required_scanners": {
        "javascript": ["semgrep", "gitleaks", "npm-audit"],
        "typescript": ["semgrep", "gitleaks", "npm-audit"],
        "dart": ["semgrep", "gitleaks", "osv-scanner"],
        "python": ["semgrep", "gitleaks", "pip-audit"],
        "containers": ["trivy"],
    },
}


def _merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def _validate_string_list(name: str, value: Any) -> List[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{name} must be a list of strings")
    return value


def _validate_required_scanners(value: Any) -> Dict[str, List[str]]:
    if not isinstance(value, dict):
        raise ConfigError("required_scanners must be a mapping")
    validated: Dict[str, List[str]] = {}
    for key, scanners in value.items():
        validated[str(key)] = _validate_string_list(f"required_scanners.{key}", scanners)
    return validated


def load_repo_config(repo: Path) -> Dict[str, Any]:
    config_path = repo / "security-skunkworks.yaml"
    if config_path.exists():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    else:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("security-skunkworks.yaml must contain a top-level mapping")
    unknown = sorted(set(raw) - set(DEFAULT_CONFIG))
    if unknown:
        raise ConfigError(f"Unsupported config keys: {', '.join(unknown)}")
    config = _merge_dicts(DEFAULT_CONFIG, raw)
    if config["default_mode"] not in {item.value for item in RunMode}:
        raise ConfigError("default_mode must be one of: read-only, docs-only, low-risk")
    for key in ("include_paths", "exclude_paths", "compliance_frameworks", "primary_frameworks", "sensitive_paths"):
        config[key] = _validate_string_list(key, config[key])
    if not isinstance(config["docs_destination"], str):
        raise ConfigError("docs_destination must be a string")
    if not isinstance(config["gate_thresholds"], dict):
        raise ConfigError("gate_thresholds must be a mapping")
    config["required_scanners"] = _validate_required_scanners(config["required_scanners"])
    return config


def path_is_in_scope(relative_path: str, config: Dict[str, Any]) -> bool:
    include_paths = config.get("include_paths") or []
    exclude_paths = config.get("exclude_paths") or []
    normalized = relative_path.strip("./")
    if include_paths:
        if not any(normalized == item or normalized.startswith(f"{item.rstrip('/')}/") for item in include_paths):
            return False
    if any(normalized == item or normalized.startswith(f"{item.rstrip('/')}/") for item in exclude_paths):
        return False
    return True
