import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ccvet",
        description=(
            "A risk-classifying permission gate for Claude Code. "
            "Auto-approves safe tool calls, blocks dangerous ones, and asks about the rest. "
            "Run `ccvet init` to get started."
        ),
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")

    sub = parser.add_subparsers(dest="command")

    gate_help = "run as a PreToolUse hook, reading one tool-call JSON payload from stdin"
    gate_p = sub.add_parser("gate", help=gate_help, description=gate_help)
    gate_p.add_argument(
        "--dry-run", action="store_true",
        help="evaluate and print the decision without writing an audit log entry",
    )

    init_help = "wire ccvet's hook into Claude Code's settings.json"
    init_p = sub.add_parser("init", help=init_help, description=f"{init_help}. Safe to run again later; re-running just refreshes the entry.")
    init_p.add_argument(
        "--global", dest="global_", action="store_true",
        help="install into ~/.claude/settings.json instead of the project-local .claude/settings.json",
    )
    init_p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    uninstall_help = "remove ccvet's hook from Claude Code's settings.json"
    uninstall_p = sub.add_parser(
        "uninstall", help=uninstall_help,
        description=f"{uninstall_help}. Leaves any other hooks you have configured untouched.",
    )
    uninstall_p.add_argument(
        "--global", dest="global_", action="store_true",
        help="remove from ~/.claude/settings.json instead of the project-local .claude/settings.json",
    )
    uninstall_p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    check_help = "see what ccvet would decide for a command, without running it for real"
    check_p = sub.add_parser("check", help=check_help, description=check_help)
    check_p.add_argument("shell_command", nargs="?", metavar="command", help="a bash command string to evaluate")
    check_p.add_argument("--tool", help="tool name to evaluate instead of a bash command, e.g. Write, WebFetch")
    check_p.add_argument("--path", help="file_path to use with --tool for Read/Write/Edit-style checks")
    check_p.add_argument("--url", help="url to use with --tool WebFetch")
    check_p.add_argument("--cwd", help="working directory to evaluate against (defaults to the current directory)")

    status_help = "show wired hooks, active policy files, and Layer 2 and audit-log state"
    sub.add_parser("status", help=status_help, description=status_help)

    log_help = "view the audit log of every decision ccvet has made"
    log_p = sub.add_parser("log", help=log_help, description=log_help)
    log_p.add_argument("--tail", type=int, default=20, help="show only the last N entries (0 for all)")

    allow_help = "add a policy rule promoting a command to a verdict, so ccvet stops asking about it"
    allow_p = sub.add_parser("allow", help=allow_help, description=allow_help)
    allow_p.add_argument("pattern", help="command text to match (treated as a literal string unless --regex)")
    allow_p.add_argument("--regex", action="store_true", help="treat pattern as a regex instead of a literal string")
    allow_p.add_argument(
        "--verdict", choices=["allow", "ask", "deny"], default="allow",
        help="the decision to record for this pattern (default: allow)",
    )
    allow_p.add_argument("--global", dest="global_", action="store_true", help="write to the global policy instead of the project-local one")
    allow_p.add_argument("--reason", help="custom reason text stored with the rule")

    policy_help = "manage ccvet's user policy file (your own allow/ask/deny rules)"
    policy_p = sub.add_parser("policy", help=policy_help, description=policy_help)
    policy_sub = policy_p.add_subparsers(dest="policy_command")
    policy_edit_help = "open the active policy.yaml in $EDITOR, creating it first if it doesn't exist"
    policy_edit_p = policy_sub.add_parser("edit", help=policy_edit_help, description=policy_edit_help)
    policy_edit_p.add_argument("--global", dest="global_", action="store_true", help="edit the global policy instead of the project-local one")

    config_help = "get or set ccvet's own config (currently just the optional Layer 2 classifier settings)"
    config_p = sub.add_parser("config", help=config_help, description=config_help)
    config_sub = config_p.add_subparsers(dest="config_command")
    config_get_p = config_sub.add_parser("get", help="print a config value", description="print a config value")
    config_get_p.add_argument("key", help="dotted key, e.g. classifier.base_url")
    config_set_p = config_sub.add_parser("set", help="set a config value", description="set a config value")
    config_set_p.add_argument("key", help="dotted key, e.g. classifier.base_url")
    config_set_p.add_argument("value", help="value to store")

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.version:
        from . import __version__
        print(__version__)
        return 0

    if args.command == "gate":
        from . import gate
        return gate.run(dry_run=args.dry_run)

    if args.command == "init":
        from . import init as init_mod
        return init_mod.run(use_global=args.global_, assume_yes=args.yes)

    if args.command == "uninstall":
        from . import init as init_mod
        return init_mod.uninstall(use_global=args.global_, assume_yes=args.yes)

    if args.command == "check":
        from . import commands
        return commands.check(args)

    if args.command == "status":
        from . import commands
        return commands.status(args)

    if args.command == "log":
        from . import commands
        return commands.log_view(args)

    if args.command == "allow":
        from . import commands
        return commands.allow(args)

    if args.command == "policy":
        from . import commands
        if args.policy_command == "edit":
            return commands.policy_edit(args)
        build_parser().parse_args(["policy", "--help"])
        return 0

    if args.command == "config":
        from . import commands
        if args.config_command == "get":
            return commands.config_get(args)
        if args.config_command == "set":
            return commands.config_set(args)
        build_parser().parse_args(["config", "--help"])
        return 0

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
