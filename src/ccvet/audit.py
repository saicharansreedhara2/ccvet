"""Append-only JSONL audit log of every decision ccvet makes. This is the
real user-facing record of `allow` decisions, since those aren't shown in
Claude Code's normal transcript (see Docs/hook-contract.md).

Lives at ~/.ccvet/audit.jsonl regardless of whether the hook itself was
wired in globally or per-project — one consolidated log across all
projects is easier to review than hunting per-project files, and each
entry carries `cwd` so project context isn't lost.

Concurrency: multiple Claude Code sessions (even across different
projects) may invoke `ccvet gate` at the same time, all appending to this
one file, so every write takes an exclusive flock around the append.
"""

import fcntl
import hashlib
import json
import time
from pathlib import Path

LOG_PATH = Path.home() / ".ccvet" / "audit.jsonl"


def _summarize_input(tool_name: str, tool_input: dict) -> dict:
    if tool_name == "Bash":
        return {"command": tool_input.get("command", "")}

    if tool_name in {"Edit", "Write", "NotebookEdit"}:
        path = tool_input.get("file_path") or tool_input.get("notebook_path")
        content = tool_input.get("content") or tool_input.get("new_string") or ""
        summary = {"path": path, "content_length": len(content)}
        if content:
            summary["content_sha256"] = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
        return summary

    if tool_name in {"Read", "Grep", "Glob"}:
        return {"path": tool_input.get("file_path") or tool_input.get("path") or tool_input.get("pattern")}

    if tool_name == "WebFetch":
        return {"url": tool_input.get("url")}

    return {"input_keys": sorted(tool_input.keys())}


def _ensure_log_file() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not LOG_PATH.exists():
        LOG_PATH.touch(mode=0o600)


def log(tool_name: str, tool_input: dict, cwd: str, verdict, latency_ms: float) -> None:
    entry = {
        "ts": time.time(),
        "tool": tool_name,
        "cwd": cwd,
        "input": _summarize_input(tool_name, tool_input),
        "decision": verdict.decision,
        "reason": verdict.reason,
        "latency_ms": round(latency_ms, 2),
    }
    _ensure_log_file()
    with open(LOG_PATH, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.write(json.dumps(entry) + "\n")
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
