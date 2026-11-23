import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ccvet", description="Risk-classifying PreToolUse gate for Claude Code")
    parser.add_argument("--version", action="store_true", help="print version and exit")

    sub = parser.add_subparsers(dest="command")

    gate_p = sub.add_parser("gate", help="run as a PreToolUse hook (reads JSON from stdin)")
    gate_p.add_argument(
        "--dry-run", action="store_true",
        help="evaluate and print the decision without writing an audit log entry",
    )

    init_p = sub.add_parser("init", help="wire ccvet into Claude Code's settings.json")
    init_p.add_argument(
        "--global", dest="global_", action="store_true",
        help="install into ~/.claude/settings.json instead of the project-local .claude/settings.json",
    )
    init_p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    uninstall_p = sub.add_parser("uninstall", help="remove ccvet's hook from Claude Code's settings.json")
    uninstall_p.add_argument(
        "--global", dest="global_", action="store_true",
        help="remove from ~/.claude/settings.json instead of the project-local .claude/settings.json",
    )
    uninstall_p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    check_p = sub.add_parser("check", help="dry-run a single command/tool call through the engine")
    check_p.add_argument("shell_command", nargs="?", metavar="command", help="a bash command string to evaluate")
    check_p.add_argument("--tool", help="tool name to evaluate instead of a bash command (e.g. Write, WebFetch)")
    check_p.add_argument("--path", help="file_path to use with --tool for Read/Write/Edit-style checks")
    check_p.add_argument("--url", help="url to use with --tool WebFetch")
    check_p.add_argument("--cwd", help="working directory to evaluate against (defaults to the current directory)")

    sub.add_parser("status", help="show wired hooks, active policy files, and Layer 2/audit-log state")

    log_p = sub.add_parser("log", help="view the audit log")
    log_p.add_argument("--tail", type=int, default=20, help="show only the last N entries (0 for all)")

    allow_p = sub.add_parser("allow", help="add a policy rule promoting a command to a verdict")
    allow_p.add_argument("pattern", help="command text to match (treated as a literal unless --regex)")
    allow_p.add_argument("--regex", action="store_true", help="treat pattern as a regex instead of a literal string")
    allow_p.add_argument("--verdict", choices=["allow", "ask", "deny"], default="allow")
    allow_p.add_argument("--global", dest="global_", action="store_true", help="write to the global policy instead of the project-local one")
    allow_p.add_argument("--reason", help="custom reason text stored with the rule")

    policy_p = sub.add_parser("policy", help="policy file commands")
    policy_sub = policy_p.add_subparsers(dest="policy_command")
    policy_edit_p = policy_sub.add_parser("edit", help="open the active policy.yaml in $EDITOR")
    policy_edit_p.add_argument("--global", dest="global_", action="store_true", help="edit the global policy instead of the project-local one")

    config_p = sub.add_parser("config", help="get/set ccvet config (e.g. Layer 2 classifier settings)")
    config_sub = config_p.add_subparsers(dest="config_command")
    config_get_p = config_sub.add_parser("get", help="print a config value")
    config_get_p.add_argument("key", help="dotted key, e.g. classifier.base_url")
    config_set_p = config_sub.add_parser("set", help="set a config value")
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
