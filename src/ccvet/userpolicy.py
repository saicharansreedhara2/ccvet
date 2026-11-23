"""User-editable override rules, layered on top of the built-in engine.

These can only ever take effect where a built-in verdict was already
marked `overridable=True` (see verdict.py) — a generic program-list or
gray-zone fallback, never one of the named safety-floor guards. This is
enforced structurally in shellrules.py, not just by convention here.

Rule format (a list under `rules:` in policy.yaml):
    rules:
      - match: "^docker build \\."     # regex, searched against the raw command
        verdict: allow                  # allow | ask | deny
        reason: "reviewed, this is our standard build command"

Project-local rules (<cwd>/.ccvet/policy.yaml) are checked before global
ones (~/.ccvet/policy.yaml); first match anywhere wins.
"""

import re
from pathlib import Path

import yaml

from .verdict import Verdict

GLOBAL_PATH = Path.home() / ".ccvet" / "policy.yaml"


def project_path(cwd: str) -> Path:
    return Path(cwd) / ".ccvet" / "policy.yaml"


def _load_file(path: Path) -> list:
    if not path.exists():
        return []
    text = path.read_text()
    if not text.strip():
        return []
    data = yaml.safe_load(text) or {}
    return data.get("rules", []) or []


def load_rules(cwd: str) -> list:
    return _load_file(project_path(cwd)) + _load_file(GLOBAL_PATH)


def find_override(command: str, cwd: str):
    for rule in load_rules(cwd):
        pattern = rule.get("match")
        if not pattern:
            continue
        try:
            if re.search(pattern, command):
                verdict_name = rule.get("verdict", "ask")
                reason = rule.get("reason") or f"user policy rule matched: {pattern!r}"
                factory = getattr(Verdict, verdict_name, None)
                if factory is None:
                    continue
                return factory(reason)
        except re.error:
            continue
    return None


def add_rule(pattern: str, verdict: str, reason: str, use_global: bool, cwd: str) -> Path:
    path = GLOBAL_PATH if use_global else project_path(cwd)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {}
    if path.exists() and path.read_text().strip():
        data = yaml.safe_load(path.read_text()) or {}

    rules = data.get("rules", []) or []
    rules.append({"match": pattern, "verdict": verdict, "reason": reason})
    data["rules"] = rules

    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return path
