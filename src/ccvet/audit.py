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

Secrets: a Bash command's full text is stored (unlike Write/Edit content,
which is hashed, not stored) since "what command actually ran" is the
whole point of this log for a human reviewing it later. Found by external
review: a live bearer token on a curl -H flag landed verbatim. redact.py's
best-effort patterns (Authorization headers, URL-embedded credentials,
well-known provider token prefixes, inline VARNAME=value secret
assignments) are applied to the command text and to a WebFetch URL (the
other field that can carry embedded credentials) before either is
written. This is a mitigation for the common, structurally-recognizable
shapes, not a guarantee every secret is caught — see SECURITY.md.
"""

import fcntl
import hashlib
import json
import time
from pathlib import Path

from . import redact

LOG_PATH = Path.home() / ".ccvet" / "audit.jsonl"


def _summarize_input(tool_name: str, tool_input: dict) -> dict:
    if tool_name == "Bash":
        return {"command": redact.redact(tool_input.get("command", ""))}

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
        return {"url": redact.redact(tool_input.get("url"))}

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
        # Found by external review, the sharpest gap in the original
        # redaction fix: redact.redact() was applied to the `command`/
        # `url` input fields but not here, even though the ASK_PROGRAMS
        # reason string is built by interpolating the same raw argv
        # text straight back in (rules.py's `f"{program} {' '.join(
        # args)}"`). ASK_PROGRAMS includes curl/aws/docker/kubectl/
        # gcloud - precisely the tools that carry credentials as CLI
        # arguments - so a secret that `command` correctly redacted
        # could still land verbatim in `reason` on the very same log
        # line.
        "reason": redact.redact(verdict.reason),
        "latency_ms": round(latency_ms, 2),
    }
    _ensure_log_file()
    with open(LOG_PATH, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.write(json.dumps(entry) + "\n")
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
