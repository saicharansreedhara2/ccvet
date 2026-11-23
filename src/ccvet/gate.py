"""PreToolUse hook entry point.

Phase 0.5 spike: no rule engine yet (that's Phase 1). This exists to prove
the stdin/stdout contract against a real Claude Code hook invocation before
any real classification logic is built on top of it.

Must never crash: a raw traceback on stdout would be an invalid hook
response, so every path here is wrapped to still emit valid JSON.
"""

import json
import sys


def _decision(decision: str, reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def build_response(raw_stdin: str) -> dict:
    # "defer" (no opinion, let normal permission flow decide) is correct here
    # since there's genuinely no rule engine yet. On an internal error we use
    # "ask" instead, deliberately not "defer" — defer's behavior depends on
    # the session's current permission_mode (e.g. bypassPermissions would let
    # it straight through), which is exactly the wrong failure mode for a crash.
    try:
        payload = json.loads(raw_stdin) if raw_stdin.strip() else {}
        tool_name = payload.get("tool_name", "unknown")
        return _decision(
            "defer",
            f"ccvet spike build: rule engine not implemented yet (Phase 1), "
            f"deferring {tool_name} to normal permission flow.",
        )
    except Exception as exc:
        return _decision(
            "ask", f"ccvet internal error ({exc.__class__.__name__}); escalating to be safe."
        )


def run() -> int:
    response = build_response(sys.stdin.read())
    print(json.dumps(response))
    return 0
