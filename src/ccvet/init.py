"""Wires ccvet's PreToolUse hook into Claude Code's settings.json.

Spike-quality merge: re-serializes the whole settings file with sorted
keys, which reformats anything already in there rather than doing a
surgical patch. Fine for Phase 0.5 proving the plumbing; Phase 2 needs a
less invasive merge that preserves the rest of the file's formatting.
"""

import json
from pathlib import Path

HOOK_COMMAND = "ccvet gate"


def settings_path(use_global: bool) -> Path:
    base = Path.home() if use_global else Path.cwd()
    return base / ".claude" / "settings.json"


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text()
    return json.loads(text) if text.strip() else {}


def _is_ccvet_entry(entry: dict) -> bool:
    return any(
        hook.get("type") == "command" and hook.get("command", "").strip() == HOOK_COMMAND
        for hook in entry.get("hooks", [])
    )


def merge(settings: dict) -> dict:
    settings = dict(settings)
    hooks = dict(settings.get("hooks", {}))
    pre_tool_use = [e for e in hooks.get("PreToolUse", []) if not _is_ccvet_entry(e)]
    pre_tool_use.append(
        {
            "matcher": "*",
            "hooks": [{"type": "command", "command": HOOK_COMMAND, "timeout": 10}],
        }
    )
    hooks["PreToolUse"] = pre_tool_use
    settings["hooks"] = hooks
    return settings


def run(use_global: bool = False, assume_yes: bool = False) -> int:
    path = settings_path(use_global)
    before = _load(path)
    after = merge(before)

    before_text = json.dumps(before, indent=2, sort_keys=True)
    after_text = json.dumps(after, indent=2, sort_keys=True)

    if before_text == after_text:
        print(f"ccvet is already wired into {path} — nothing to do.")
        return 0

    print(f"About to write {path}:")
    print("--- before ---")
    print(before_text)
    print("--- after ---")
    print(after_text)

    if not assume_yes:
        reply = input("Write this? [y/N] ").strip().lower()
        if reply != "y":
            print("Aborted, no changes written.")
            return 1

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(after, indent=2) + "\n")
    print(f"Wired ccvet into {path}")
    return 0
