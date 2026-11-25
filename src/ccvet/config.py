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
    if not text.strip():
        return {}
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        # A broken config.yaml must degrade to "nothing configured", not
        # raise - this is read on every Bash classification (to check
        # whether Layer 2 is enabled), so an uncaught error here would
        # force every command to the generic internal-error fallback.
        return {}
    return data if isinstance(data, dict) else {}


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
        # setdefault(part, {}) would return the EXISTING value if one is
        # already there, even if it's not a dict (e.g. a prior "classifier:
        # some_string" entry) - then the next `node[...] = value` raises
        # TypeError on a plain string. Overwrite a non-dict intermediate
        # instead of crashing on it.
        if not isinstance(node.get(part), dict):
            node[part] = {}
        node = node[part]
    node[parts[-1]] = value
    _save(data)


def all_values() -> dict:
    return _load()
