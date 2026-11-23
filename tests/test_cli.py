"""Integration tests against the real argparse parser — catches dest
collisions and similar wiring bugs that hand-built Namespace objects in
test_commands.py can't see (that's exactly how the `check` subcommand's
positional colliding with the top-level `dest="command"` slipped through).
"""

from ccvet.cli import build_parser, main


def test_check_subcommand_does_not_clobber_top_level_command_dest():
    args = build_parser().parse_args(["check", "docker build ."])
    assert args.command == "check"
    assert args.shell_command == "docker build ."


def test_every_subcommand_sets_command_to_its_own_name():
    cases = [
        (["gate"], "gate"),
        (["init"], "init"),
        (["uninstall"], "uninstall"),
        (["check", "ls"], "check"),
        (["status"], "status"),
        (["log"], "log"),
        (["allow", "some pattern"], "allow"),
        (["policy", "edit"], "policy"),
        (["config", "get", "classifier.base_url"], "config"),
    ]
    for argv, expected in cases:
        args = build_parser().parse_args(argv)
        assert args.command == expected, f"{argv} -> command={args.command!r}, expected {expected!r}"


def test_check_end_to_end_via_main(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)  # gate isn't invoked here, just defensive
    rc = main(["check", "git status"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "decision: allow" in out
