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

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
