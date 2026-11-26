"""Integration tests against the real argparse parser — catches dest
collisions and similar wiring bugs that hand-built Namespace objects in
test_commands.py can't see (that's exactly how the `check` subcommand's
positional colliding with the top-level `dest="command"` slipped through).
"""

import contextlib
import io

import pytest

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


def test_version_flag():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(["--version"])
    assert rc == 0
    assert buf.getvalue().strip()  # prints something, don't pin the exact version string here


def test_version_matches_installed_package_metadata():
    # Regression: __version__ used to be a hand-maintained string literal
    # in __init__.py, separate from pyproject.toml's version field. They
    # drifted (0.0.2 shipped printing "0.0.1"), caught only by installing
    # the real published package, not by any test, since nothing checked
    # that the two actually agreed. __version__ is now read from
    # installed package metadata at runtime instead of hand-copied, so
    # this can't drift again structurally, but this test still pins the
    # cross-check explicitly so the mechanism itself stays honest.
    import importlib.metadata

    from ccvet import __version__

    assert __version__ == importlib.metadata.version("ccvet")


def test_main_dispatches_gate(monkeypatch):
    calls = []
    monkeypatch.setattr("ccvet.gate.run", lambda dry_run=False: calls.append(dry_run) or 0)
    assert main(["gate", "--dry-run"]) == 0
    assert calls == [True]


def test_main_dispatches_init(monkeypatch):
    calls = []
    monkeypatch.setattr("ccvet.init.run", lambda use_global, assume_yes: calls.append((use_global, assume_yes)) or 0)
    assert main(["init", "--global", "--yes"]) == 0
    assert calls == [(True, True)]


def test_main_dispatches_uninstall(monkeypatch):
    calls = []
    monkeypatch.setattr("ccvet.init.uninstall", lambda use_global, assume_yes: calls.append((use_global, assume_yes)) or 0)
    assert main(["uninstall"]) == 0
    assert calls == [(False, False)]


def test_main_dispatches_status(monkeypatch):
    calls = []
    monkeypatch.setattr("ccvet.commands.status", lambda args: calls.append(args) or 0)
    assert main(["status"]) == 0
    assert len(calls) == 1


def test_main_dispatches_log(monkeypatch):
    calls = []
    monkeypatch.setattr("ccvet.commands.log_view", lambda args: calls.append(args.tail) or 0)
    assert main(["log", "--tail", "5"]) == 0
    assert calls == [5]


def test_main_dispatches_allow(monkeypatch):
    calls = []
    monkeypatch.setattr("ccvet.commands.allow", lambda args: calls.append(args.pattern) or 0)
    assert main(["allow", "docker build ."]) == 0
    assert calls == ["docker build ."]


def test_main_dispatches_policy_edit(monkeypatch):
    calls = []
    monkeypatch.setattr("ccvet.commands.policy_edit", lambda args: calls.append(args.global_) or 0)
    assert main(["policy", "edit", "--global"]) == 0
    assert calls == [True]


def test_main_policy_with_no_subcommand_shows_help_and_exits(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["policy"])
    assert exc_info.value.code == 0


def test_main_dispatches_config_get(monkeypatch):
    calls = []
    monkeypatch.setattr("ccvet.commands.config_get", lambda args: calls.append(args.key) or 0)
    assert main(["config", "get", "classifier.base_url"]) == 0
    assert calls == ["classifier.base_url"]


def test_main_dispatches_config_set(monkeypatch):
    calls = []
    monkeypatch.setattr("ccvet.commands.config_set", lambda args: calls.append((args.key, args.value)) or 0)
    assert main(["config", "set", "classifier.base_url", "http://x"]) == 0
    assert calls == [("classifier.base_url", "http://x")]


def test_main_config_with_no_subcommand_shows_help_and_exits():
    with pytest.raises(SystemExit) as exc_info:
        main(["config"])
    assert exc_info.value.code == 0


def test_main_with_no_command_prints_help(capsys):
    rc = main([])
    assert rc == 0
    assert "usage" in capsys.readouterr().out.lower()
