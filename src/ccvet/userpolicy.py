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

# Explicit whitelist, not getattr(Verdict, verdict_name) - a hand-edited
# policy.yaml must never be able to invoke `defer` (whose behavior
# depends on permission_mode, not something a user rule should produce)
# or, worse, an unrelated Verdict attribute like `rank` (an instance
# method - calling it as Verdict.rank(reason) would raise, discarding
# the already-computed correct built-in verdict for a generic internal-
# error ask instead).
_VERDICT_FACTORIES = {"allow": Verdict.allow, "ask": Verdict.ask, "deny": Verdict.deny}


def project_path(cwd: str) -> Path:
    return Path(cwd) / ".ccvet" / "policy.yaml"


def _load_file(path: Path) -> list:
    if not path.exists():
        return []
    text = path.read_text()
    if not text.strip():
        return []
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        # A broken policy.yaml must degrade to "no user rules", not
        # raise - raising here would propagate past the already-computed
        # built-in verdict in shellrules.evaluate() and discard it for a
        # generic internal-error ask, for every single overridable
        # command, until the file is fixed.
        return []
    if not isinstance(data, dict):
        return []
    rules = data.get("rules", []) or []
    return rules if isinstance(rules, list) else []


def load_rules(cwd: str) -> list:
    return _load_file(project_path(cwd)) + _load_file(GLOBAL_PATH)


def find_override(command: str, cwd: str):
    for rule in load_rules(cwd):
        if not isinstance(rule, dict):
            continue
        pattern = rule.get("match")
        if not pattern:
            continue
        try:
            if re.search(pattern, command):
                factory = _VERDICT_FACTORIES.get(rule.get("verdict", "ask"))
                if factory is None:
                    continue
                reason = rule.get("reason") or f"user policy rule matched: {pattern!r}"
                return factory(reason)
        except re.error:
            continue
    return None


def add_rule(pattern: str, verdict: str, reason: str, use_global: bool, cwd: str) -> Path:
    try:
        re.compile(pattern)
    except re.error as exc:
        # Without this, an invalid --regex pattern was written silently:
        # find_override()'s own `except re.error: continue` means the
        # rule would just never match anything, with zero feedback that
        # it's dead.
        raise ValueError(f"{pattern!r} is not a valid regex: {exc}") from exc

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
