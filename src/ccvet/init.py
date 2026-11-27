"""Wires ccvet's PreToolUse hook into Claude Code's settings.json.

Re-serializes the whole settings file rather than doing a surgical,
format-preserving patch, so anything already in the file gets rewritten
to this module's own JSON formatting (2-space indent). This is a
deliberate, permanent tradeoff, not a Phase 0.5 placeholder waiting on a
later phase: a surgical patcher that preserves an arbitrary existing
file's whitespace/comments would need a format-preserving JSON library
(JSON has no comments and no standard for this), for a payoff that only
matters for `git diff` noise on a file nobody hand-edits often. The
written JSON is always semantically equivalent to what was there before,
just reformatted.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import config

HOOK_SUBCOMMAND = "gate"
# Generous relative to Layer 0/1 (sub-millisecond), to leave room for an
# optional Layer 2 LLM call on a slow local model. If a hook invocation
# does blow through this, PreToolUse fails open to the normal permission
# flow rather than blocking the tool call (see Docs/hook-contract.md) -
# the cost of a too-tight timeout here is degraded UX, not a safety gap.
HOOK_TIMEOUT_SECONDS = 20


def _hook_binary() -> str:
    """Absolute path to the ccvet executable, resolved from the running
    interpreter rather than a bare "ccvet" name. Found by external
    review: Claude Code spawns a PreToolUse hook command in its own
    shell, which is not guaranteed to carry the same PATH as the
    interactive shell `ccvet init` was run from - a venv install is the
    common case where it doesn't. The result: a bare "ccvet gate" hook
    entry resolves fine when typed by hand, but Claude Code's spawned
    shell reports "command not found", which (per the documented
    PreToolUse timeout/failure behavior) fails open to the normal
    permission flow with no error shown anywhere - ccvet silently never
    runs again, even though `ccvet status` still reports it as wired.

    pip/pipx/hatchling always install a project's console-script shim
    into the same directory as the venv's own `python`, so resolving
    against `sys.executable` (never PATH-dependent; it's exactly how the
    currently-running process was launched) reliably finds it even when
    PATH wouldn't. Falls back to the bare name only if that sibling file
    doesn't exist, which should be rare.
    """
    candidate = Path(sys.executable).parent / "ccvet"
    return str(candidate) if candidate.exists() else "ccvet"


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
    if not text.strip():
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{path} contains invalid JSON ({exc}). Fix or remove it before running ccvet init/uninstall."
        ) from exc


def _is_ccvet_entry(entry: dict) -> bool:
    # Matches by shape (last token "gate", the token before it a path
    # whose basename is "ccvet"), not by exact string equality to one
    # fixed command - the command string now bakes in an install-
    # specific absolute path (see _hook_binary), which changes across
    # reinstalls/venvs. Matching by shape means re-running `ccvet init`
    # after reinstalling elsewhere replaces the old entry in place
    # instead of leaving a stale, now-wrong absolute path sitting
    # alongside a second, newly-added one.
    for hook in entry.get("hooks", []):
        if hook.get("type") != "command":
            continue
        parts = hook.get("command", "").strip().split()
        if len(parts) == 2 and parts[1] == HOOK_SUBCOMMAND and Path(parts[0]).name == "ccvet":
            return True
    return False


def merge(settings: dict) -> dict:
    settings = dict(settings)
    hooks = dict(settings.get("hooks", {}))
    pre_tool_use = [e for e in hooks.get("PreToolUse", []) if not _is_ccvet_entry(e)]
    pre_tool_use.append(
        {
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": f"{_hook_binary()} {HOOK_SUBCOMMAND}",
                    "timeout": HOOK_TIMEOUT_SECONDS,
                }
            ],
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
        reply = input("Use it as ccvet's optional Layer 2 classifier? [y/N] ").strip().lower()
        if reply != "y":
            return
    config.set("classifier.base_url", base_url)
    print(f"Set classifier.base_url = {base_url}. Set classifier.model with `ccvet config set classifier.model <name>`.")


def run(use_global: bool = False, assume_yes: bool = False) -> int:
    path = settings_path(use_global)
    try:
        before = _load(path)
    except ValueError as exc:
        print(str(exc))
        return 1
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
    path.write_text(after_text + "\n")
    print(f"Wired ccvet into {path}")
    offer_layer2_setup(assume_yes=assume_yes)
    return 0


def uninstall(use_global: bool = False, assume_yes: bool = False) -> int:
    path = settings_path(use_global)
    try:
        before = _load(path)
    except ValueError as exc:
        print(str(exc))
        return 1
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

    path.write_text(after_text + "\n")
    print(f"Removed ccvet from {path}")
    return 0
