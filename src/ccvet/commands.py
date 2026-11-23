"""Human-facing CLI commands: check, status, log, allow, policy edit,
config get/set. Distinct from gate.py/init.py, which are the hook-facing
machinery these commands inspect or configure.
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, audit, config, engine, init, userpolicy


def check(args) -> int:
    cwd = args.cwd or os.getcwd()
    if args.tool:
        tool_input = {}
        if args.path:
            tool_input["file_path"] = args.path
        if args.url:
            tool_input["url"] = args.url
        tool_name = args.tool
    else:
        if not args.shell_command:
            print("Provide either a bash command or --tool.", file=sys.stderr)
            return 1
        tool_name = "Bash"
        tool_input = {"command": args.shell_command}

    verdict = engine.evaluate(tool_name, tool_input, cwd)
    print(f"tool:     {tool_name}")
    print(f"decision: {verdict.decision}")
    print(f"reason:   {verdict.reason}")
    if verdict.decision != "defer":
        print(f"overridable: {verdict.overridable}")
    return 0


def status(args) -> int:
    cwd = os.getcwd()
    print(f"ccvet {__version__}")

    project_settings = init.settings_path(use_global=False)
    global_settings = init.settings_path(use_global=True)
    for label, path in (("project", project_settings), ("global", global_settings)):
        wired = any(
            init._is_ccvet_entry(e)
            for e in init._load(path).get("hooks", {}).get("PreToolUse", [])
        )
        print(f"{label} hook ({path}): {'wired' if wired else 'not wired'}")

    for label, path in (("project", userpolicy.project_path(cwd)), ("global", userpolicy.GLOBAL_PATH)):
        rules = userpolicy._load_file(path)
        if path.exists():
            print(f"{label} policy ({path}): {len(rules)} rule(s)")
        else:
            print(f"{label} policy ({path}): not present")

    base_url = config.get("classifier.base_url")
    print(f"Layer 2 classifier: {'configured (' + base_url + ')' if base_url else 'disabled (no classifier.base_url configured)'}")

    if audit.LOG_PATH.exists():
        count = sum(1 for _ in audit.LOG_PATH.open())
        print(f"audit log ({audit.LOG_PATH}): {count} entries")
    else:
        print(f"audit log ({audit.LOG_PATH}): no entries yet")

    return 0


def log_view(args) -> int:
    if not audit.LOG_PATH.exists():
        print("No audit log entries yet.")
        return 0

    lines = audit.LOG_PATH.read_text().strip().splitlines()
    tail = lines[-args.tail:] if args.tail else lines

    for line in tail:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = datetime.fromtimestamp(entry["ts"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"[{ts}] {entry['decision']:>5}  {entry['tool']:<10} {entry['reason']}")

    return 0


def allow(args) -> int:
    cwd = os.getcwd()
    pattern = args.pattern if args.regex else re.escape(args.pattern)
    reason = args.reason or f"promoted via `ccvet allow` on {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
    path = userpolicy.add_rule(pattern, args.verdict, reason, use_global=args.global_, cwd=cwd)
    print(f"Added rule to {path}: {args.verdict} when command matches {pattern!r}")
    return 0


def policy_edit(args) -> int:
    cwd = os.getcwd()
    path = userpolicy.GLOBAL_PATH if args.global_ else userpolicy.project_path(cwd)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("rules: []\n")

    editor = os.environ.get("EDITOR", "vi")
    subprocess.run([editor, str(path)])
    return 0


def config_get(args) -> int:
    value = config.get(args.key)
    if value is None:
        print(f"{args.key} is not set")
        return 1
    print(value)
    return 0


def config_set(args) -> int:
    config.set(args.key, args.value)
    print(f"Set {args.key} = {args.value}")
    return 0
