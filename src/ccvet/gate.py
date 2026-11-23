"""PreToolUse hook entry point. Must never crash: a raw traceback on stdout
would be an invalid hook response, so the whole evaluation is wrapped and
any internal error degrades to an explicit `ask` (not `defer` — see
verdict.py for why those aren't interchangeable as a failure mode).
"""

import json
import sys
import time

from . import audit, engine
from .verdict import Verdict


def _hook_output(verdict: Verdict) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": verdict.decision,
            "permissionDecisionReason": verdict.reason,
        }
    }


def _evaluate(raw_stdin: str):
    """Returns (tool_name, tool_input, cwd, verdict, elapsed_ms)."""
    start = time.monotonic()
    tool_name, tool_input, cwd = "", {}, "."
    try:
        payload = json.loads(raw_stdin) if raw_stdin.strip() else {}
        tool_name = payload.get("tool_name", "")
        tool_input = payload.get("tool_input") or {}
        cwd = payload.get("cwd") or "."

        if not tool_name:
            verdict = Verdict.defer("hook input had no tool_name")
        else:
            verdict = engine.evaluate(tool_name, tool_input, cwd)
    except Exception as exc:
        verdict = Verdict.ask(f"ccvet internal error ({exc.__class__.__name__}); escalating to be safe.")
    elapsed_ms = (time.monotonic() - start) * 1000
    return tool_name, tool_input, cwd, verdict, elapsed_ms


def build_response(raw_stdin: str) -> dict:
    _tool_name, _tool_input, _cwd, verdict, _elapsed_ms = _evaluate(raw_stdin)
    return _hook_output(verdict)


def run(dry_run: bool = False) -> int:
    tool_name, tool_input, cwd, verdict, elapsed_ms = _evaluate(sys.stdin.read())
    print(json.dumps(_hook_output(verdict)))

    if not dry_run and tool_name:
        try:
            audit.log(tool_name, tool_input, cwd, verdict, elapsed_ms)
        except Exception:
            pass  # a logging failure must never affect the already-emitted decision

    return 0
