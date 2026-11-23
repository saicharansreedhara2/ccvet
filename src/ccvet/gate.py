"""PreToolUse hook entry point. Must never crash: a raw traceback on stdout
would be an invalid hook response, so the whole evaluation is wrapped and
any internal error degrades to an explicit `ask` (not `defer` — see
verdict.py for why those aren't interchangeable as a failure mode).
"""

import json
import sys

from . import engine
from .verdict import Verdict


def _hook_output(verdict: Verdict) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": verdict.decision,
            "permissionDecisionReason": verdict.reason,
        }
    }


def build_response(raw_stdin: str) -> dict:
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

    return _hook_output(verdict)


def run() -> int:
    print(json.dumps(build_response(sys.stdin.read())))
    return 0
