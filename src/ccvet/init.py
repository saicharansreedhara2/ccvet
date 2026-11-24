"""Wires ccvet's PreToolUse hook into Claude Code's settings.json.

Spike-quality merge: re-serializes the whole settings file with sorted
keys, which reformats anything already in there rather than doing a
surgical patch. Fine for Phase 0.5 proving the plumbing; Phase 2 needs a
less invasive merge that preserves the rest of the file's formatting.
"""

import json
import urllib.error
import urllib.request
from pathlib import Path

from . import config

HOOK_COMMAND = "ccvet gate"
# Generous relative to Layer 0/1 (sub-millisecond), to leave room for an
# optional Layer 2 LLM call on a slow local model. If a hook invocation
# does blow through this, PreToolUse fails open to the normal permission
# flow rather than blocking the tool call (see Docs/hook-contract.md) -
# the cost of a too-tight timeout here is degraded UX, not a safety gap.
HOOK_TIMEOUT_SECONDS = 20

LOCAL_SERVER_CANDIDATES = [
    ("Ollama", "http://localhost:11434/v1"),
    ("LM Studio", "http://localhost:1234/v1"),
]


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
            "hooks": [{"type": "command", "command": HOOK_COMMAND, "timeout": HOOK_TIMEOUT_SECONDS}],
        }
    )
    hooks["PreToolUse"] = pre_tool_use
    settings["hooks"] = hooks
    return settings


def _probe(base_url: str) -> bool:
    try:
        urllib.request.urlopen(base_url.rstrip("/") + "/models", timeout=0.5)
        return True
    except urllib.error.HTTPError:
        return True  # reachable and speaking HTTP at all is enough; auth/404 is fine
    except Exception:
        return False


def detect_local_server():
    for name, base_url in LOCAL_SERVER_CANDIDATES:
        if _probe(base_url):
            return name, base_url
    return None


def offer_layer2_setup(assume_yes: bool = False) -> None:
    if config.get("classifier.base_url"):
        return  # already configured, don't re-prompt every init

    found = detect_local_server()
    if not found:
        return

    name, base_url = found
    print(f"\nDetected a local model server ({name}) at {base_url}.")
    if not assume_yes:
        reply = input(f"Use it as ccvet's optional Layer 2 classifier? [y/N] ").strip().lower()
        if reply != "y":
            return
    config.set("classifier.base_url", base_url)
    print(f"Set classifier.base_url = {base_url}. Set classifier.model with `ccvet config set classifier.model <name>`.")


def run(use_global: bool = False, assume_yes: bool = False) -> int:
    path = settings_path(use_global)
    before = _load(path)
    after = merge(before)

    before_text = json.dumps(before, indent=2, sort_keys=True)
    after_text = json.dumps(after, indent=2, sort_keys=True)

    if before_text == after_text:
        print(f"ccvet is already wired into {path}, nothing to do.")
        offer_layer2_setup(assume_yes=assume_yes)
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
    offer_layer2_setup(assume_yes=assume_yes)
    return 0


def uninstall(use_global: bool = False, assume_yes: bool = False) -> int:
    path = settings_path(use_global)
    before = _load(path)
    pre_tool_use = before.get("hooks", {}).get("PreToolUse", [])
    remaining = [e for e in pre_tool_use if not _is_ccvet_entry(e)]

    if len(remaining) == len(pre_tool_use):
        print(f"ccvet is not wired into {path}, nothing to do.")
        return 0

    after = dict(before)
    after_hooks = dict(after.get("hooks", {}))
    if remaining:
        after_hooks["PreToolUse"] = remaining
    else:
        after_hooks.pop("PreToolUse", None)
    if after_hooks:
        after["hooks"] = after_hooks
    else:
        after.pop("hooks", None)

    before_text = json.dumps(before, indent=2, sort_keys=True)
    after_text = json.dumps(after, indent=2, sort_keys=True)

    print(f"About to update {path}:")
    print("--- before ---")
    print(before_text)
    print("--- after ---")
    print(after_text)

    if not assume_yes:
        reply = input("Remove ccvet's hook? [y/N] ").strip().lower()
        if reply != "y":
            print("Aborted, no changes written.")
            return 1

    path.write_text(json.dumps(after, indent=2) + "\n")
    print(f"Removed ccvet from {path}")
    return 0
