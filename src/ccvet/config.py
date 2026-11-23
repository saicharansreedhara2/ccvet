"""Simple dotted-key YAML config store at ~/.ccvet/config.yaml. Nothing
reads this yet (Layer 2 / Phase 4 will be the first consumer, for
classifier.base_url etc.) — `ccvet status` already reports on it so the
plumbing is exercised before Phase 4 needs it.
"""

from pathlib import Path

import yaml

CONFIG_PATH = Path.home() / ".ccvet" / "config.yaml"


def _load() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    text = CONFIG_PATH.read_text()
    return (yaml.safe_load(text) or {}) if text.strip() else {}


def _save(data: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(yaml.safe_dump(data, sort_keys=False))


def get(key: str, default=None):
    node = _load()
    for part in key.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def set(key: str, value) -> None:
    data = _load()
    node = data
    parts = key.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
    _save(data)


def all_values() -> dict:
    return _load()
