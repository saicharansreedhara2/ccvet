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
        try:
            settings = init._load(path)
        except ValueError:
            print(f"{label} hook ({path}): invalid JSON, cannot determine")
            continue
        wired = any(
            init._is_ccvet_entry(e)
            for e in settings.get("hooks", {}).get("PreToolUse", [])
        )
        print(f"{label} hook ({path}): {'wired' if wired else 'not wired'}")

    unanchored_rules = []
    for label, path in (("project", userpolicy.project_path(cwd)), ("global", userpolicy.GLOBAL_PATH)):
        rules = userpolicy._load_file(path)
        if path.exists():
            print(f"{label} policy ({path}): {len(rules)} rule(s)")
        else:
            print(f"{label} policy ({path}): not present")
        for rule in rules:
            match = rule.get("match") or ""
            if match and not (match.startswith("^") and match.endswith("$")):
                unanchored_rules.append((label, match))

    if unanchored_rules:
        # Found by external review: the ^...$ anchoring fix in
        # commands.allow() only applies to a rule written from this
        # point forward. A rule already sitting in policy.yaml - written
        # by a pre-0.0.9 ccvet, by hand, or by --regex deliberately -
        # stays exactly as unanchored as it always was; upgrading ccvet
        # does nothing to it. Can't safely auto-migrate: a stored
        # pattern string carries no record of whether it was meant as an
        # exact literal or a deliberately broad --regex, so silently
        # rewriting it risks narrowing a rule someone wrote on purpose.
        # Surfacing it here, read-only, lets the user decide.
        print(
            f"\nNote: {len(unanchored_rules)} policy rule(s) don't anchor to the "
            "whole command (no leading ^ and trailing $), so they match as a "
            "substring search anywhere in the command text:"
        )
        for label, match in unanchored_rules:
            print(f"  [{label}] {match!r}")
        print(
            "If any of these were meant to allow one exact command rather than "
            "a deliberately broad pattern, re-run `ccvet allow` on it - as of "
            "v0.0.9 a literal (non-regex) pattern is anchored automatically."
        )

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
    # A negative --tail used to produce confusing slice behavior
    # (lines[5:] for --tail -5, i.e. "skip the first 5" instead of
    # "show all"); treat anything that isn't a positive count as "all".
    tail = lines[-args.tail:] if args.tail and args.tail > 0 else lines

    for line in tail:
        try:
            entry = json.loads(line)
            ts = datetime.fromtimestamp(entry["ts"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[{ts}] {entry['decision']:>5}  {entry['tool']:<10} {entry['reason']}")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            # A single malformed or unexpectedly-shaped line (foreign
            # content, a future log format, a truncated write) must not
            # take down the rest of the log view with it.
            continue

    return 0


def allow(args) -> int:
    cwd = os.getcwd()
    # Found by external review: userpolicy.find_override matches with a
    # plain, unanchored re.search, so a literal (non-regex) pattern that
    # was only escaped, not anchored, silently matched as a substring
    # anywhere in the command - `ccvet allow "ls"` approved "ls -la",
    # "lsof -i", and "false-ls-check" alike, not just "ls". A promotion
    # the user believes is narrow ("allow exactly this command I just
    # reviewed") was actually widening the allow surface to "allow
    # anything containing this text", with no indication it had done so.
    # --regex is the explicit, documented opt-in for anything broader
    # than an exact match (the module docstring's own example, an
    # unanchored-at-the-end prefix match, relies on this); the literal
    # path now anchors to the whole command, matching what "literal
    # string" actually implies to someone typing it.
    pattern = args.pattern if args.regex else f"^{re.escape(args.pattern)}$"
    reason = args.reason or f"promoted via `ccvet allow` on {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
    try:
        path = userpolicy.add_rule(pattern, args.verdict, reason, use_global=args.global_, cwd=cwd)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Added rule to {path}: {args.verdict} when command matches {pattern!r}")
    return 0


def policy_edit(args) -> int:
    cwd = os.getcwd()
    path = userpolicy.GLOBAL_PATH if args.global_ else userpolicy.project_path(cwd)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("rules: []\n")

    editor = os.environ.get("EDITOR", "vi")
    try:
        subprocess.run([editor, str(path)])
    except OSError as exc:
        print(f"Could not launch editor {editor!r}: {exc}. Set $EDITOR or edit {path} directly.", file=sys.stderr)
        return 1
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
