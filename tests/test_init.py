import json
import sys
from pathlib import Path

from ccvet import init


def test_settings_path_project_vs_global(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")

    assert init.settings_path(use_global=False) == tmp_path / ".claude" / "settings.json"
    assert init.settings_path(use_global=True) == tmp_path / "home" / ".claude" / "settings.json"


def test_merge_adds_hook_to_empty_settings():
    after = init.merge({})
    entries = after["hooks"]["PreToolUse"]
    assert len(entries) == 1
    command = entries[0]["hooks"][0]["command"]
    assert command.endswith(" gate")
    assert Path(command[: -len(" gate")]).name == "ccvet"


def test_merge_is_idempotent():
    once = init.merge({})
    twice = init.merge(once)
    assert twice == once


def test_merge_preserves_other_hooks():
    existing = {
        "hooks": {
            "PreToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "some-other-hook"}]}]
        }
    }
    after = init.merge(existing)
    commands = [h["command"] for entry in after["hooks"]["PreToolUse"] for h in entry["hooks"]]
    assert "some-other-hook" in commands
    assert any(c.endswith(" gate") and Path(c[: -len(" gate")]).name == "ccvet" for c in commands)


def test_merge_uses_an_absolute_path_when_the_sibling_binary_exists(tmp_path, monkeypatch):
    # Found by external review: Claude Code's hook-spawning shell is not
    # guaranteed to carry the same PATH the interactive shell `ccvet
    # init` was run from - a venv install is the common case where it
    # doesn't. A bare "ccvet gate" command then resolves to nothing,
    # fails open (per the documented PreToolUse timeout behavior), and
    # ccvet silently never runs again even though `ccvet status` still
    # reports it as wired. Baking in the absolute path at wiring time
    # removes the dependency on PATH entirely.
    fake_venv_bin = tmp_path / "bin"
    fake_venv_bin.mkdir()
    (fake_venv_bin / "ccvet").write_text("#!/bin/sh\n")
    monkeypatch.setattr(sys, "executable", str(fake_venv_bin / "python"))

    after = init.merge({})
    command = after["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert command == f"{fake_venv_bin / 'ccvet'} gate"


def test_merge_falls_back_to_bare_name_when_no_sibling_binary_exists(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "executable", str(tmp_path / "nonexistent" / "python"))

    after = init.merge({})
    command = after["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert command == "ccvet gate"

    # Found by review: falling back silently would reintroduce the exact
    # PATH-resolution bug this module just fixed, just on a rarer path
    # (no installed console script at all, e.g. a source-checkout `python
    # -m ccvet.cli init`). Must warn, not go quiet.
    assert "Warning" in capsys.readouterr().out


def test_is_ccvet_entry_recognizes_an_absolute_path_command():
    entry = {"hooks": [{"type": "command", "command": "/some/venv/bin/ccvet gate"}]}
    assert init._is_ccvet_entry(entry)


def test_is_ccvet_entry_recognizes_a_hand_edited_command_with_trailing_flags():
    # Found by review: a hand-edited "ccvet gate --dry-run" (or any
    # future flag ccvet itself gains after "gate") must still be
    # recognized by a later re-init/uninstall/status, not treated as an
    # unrelated hook and left duplicated or orphaned.
    entry = {"hooks": [{"type": "command", "command": "/some/venv/bin/ccvet gate --dry-run"}]}
    assert init._is_ccvet_entry(entry)


def test_is_ccvet_entry_skips_non_command_hook_types():
    entry = {"hooks": [{"type": "prompt", "command": "ccvet gate"}]}
    assert not init._is_ccvet_entry(entry)


def test_rerunning_merge_from_a_different_install_replaces_the_old_entry(tmp_path, monkeypatch):
    # A stale absolute path from a previous install (e.g. a since-deleted
    # venv) must be replaced, not left sitting alongside a second,
    # newly-added entry pointing at the current one.
    old_bin = tmp_path / "old_venv" / "bin"
    old_bin.mkdir(parents=True)
    (old_bin / "ccvet").write_text("#!/bin/sh\n")
    monkeypatch.setattr(sys, "executable", str(old_bin / "python"))
    once = init.merge({})

    new_bin = tmp_path / "new_venv" / "bin"
    new_bin.mkdir(parents=True)
    (new_bin / "ccvet").write_text("#!/bin/sh\n")
    monkeypatch.setattr(sys, "executable", str(new_bin / "python"))
    twice = init.merge(once)

    entries = twice["hooks"]["PreToolUse"]
    assert len(entries) == 1
    assert entries[0]["hooks"][0]["command"] == f"{new_bin / 'ccvet'} gate"


def test_load_treats_whitespace_only_existing_file_as_empty(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("   \n")
    assert init._load(path) == {}


def test_run_reports_malformed_settings_json_instead_of_crashing(tmp_path, monkeypatch, capsys):
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text("{not valid json")
    monkeypatch.setattr(init, "settings_path", lambda use_global: settings_path)

    exit_code = init.run(use_global=False, assume_yes=True)

    assert exit_code == 1
    assert "invalid JSON" in capsys.readouterr().out


def test_uninstall_reports_malformed_settings_json_instead_of_crashing(tmp_path, monkeypatch, capsys):
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text("{not valid json")
    monkeypatch.setattr(init, "settings_path", lambda use_global: settings_path)

    exit_code = init.uninstall(use_global=False, assume_yes=True)

    assert exit_code == 1
    assert "invalid JSON" in capsys.readouterr().out


def test_run_aborts_when_user_declines(tmp_path, monkeypatch, capsys):
    settings_path = tmp_path / ".claude" / "settings.json"
    monkeypatch.setattr(init, "settings_path", lambda use_global: settings_path)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    monkeypatch.setattr(init, "offer_layer2_setup", lambda **k: None)

    exit_code = init.run(use_global=False, assume_yes=False)

    assert exit_code == 1
    assert not settings_path.exists()
    assert "Aborted" in capsys.readouterr().out


def test_uninstall_aborts_when_user_declines(tmp_path, monkeypatch, capsys):
    settings_path = tmp_path / ".claude" / "settings.json"
    monkeypatch.setattr(init, "settings_path", lambda use_global: settings_path)

    init.run(use_global=False, assume_yes=True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    exit_code = init.uninstall(use_global=False, assume_yes=False)

    assert exit_code == 1
    after = init._load(settings_path)
    assert init._is_ccvet_entry(after["hooks"]["PreToolUse"][0])  # still there, nothing removed


def test_run_second_time_is_a_noop_and_still_offers_layer2(tmp_path, monkeypatch):
    settings_path = tmp_path / ".claude" / "settings.json"
    monkeypatch.setattr(init, "settings_path", lambda use_global: settings_path)
    calls = []
    monkeypatch.setattr(init, "offer_layer2_setup", lambda **k: calls.append(k))

    init.run(use_global=False, assume_yes=True)
    exit_code = init.run(use_global=False, assume_yes=True)  # second run hits the "already wired" branch

    assert exit_code == 0
    assert len(calls) == 2  # offered on both the wiring run and the already-wired run


def test_uninstall_removes_only_ccvet_entry(tmp_path, monkeypatch):
    settings_path = tmp_path / ".claude" / "settings.json"
    monkeypatch.setattr(init, "settings_path", lambda use_global: settings_path)

    init.run(use_global=False, assume_yes=True)
    assert init._is_ccvet_entry(init._load(settings_path)["hooks"]["PreToolUse"][0])

    # add an unrelated hook alongside ccvet's before uninstalling
    data = init._load(settings_path)
    data["hooks"]["PreToolUse"].append({"matcher": "Edit", "hooks": [{"type": "command", "command": "other-hook"}]})
    settings_path.write_text(json.dumps(data))

    exit_code = init.uninstall(use_global=False, assume_yes=True)
    assert exit_code == 0

    after = init._load(settings_path)
    entries = after["hooks"]["PreToolUse"]
    assert not any(init._is_ccvet_entry(e) for e in entries)
    commands = [h["command"] for entry in entries for h in entry["hooks"]]
    assert "other-hook" in commands


def test_uninstall_is_a_noop_when_not_installed(tmp_path, monkeypatch):
    settings_path = tmp_path / ".claude" / "settings.json"
    monkeypatch.setattr(init, "settings_path", lambda use_global: settings_path)

    exit_code = init.uninstall(use_global=False, assume_yes=True)
    assert exit_code == 0
    assert not settings_path.exists()


def test_uninstall_drops_empty_hooks_key_entirely(tmp_path, monkeypatch):
    settings_path = tmp_path / ".claude" / "settings.json"
    monkeypatch.setattr(init, "settings_path", lambda use_global: settings_path)

    init.run(use_global=False, assume_yes=True)
    init.uninstall(use_global=False, assume_yes=True)

    after = init._load(settings_path)
    assert after == {}


def test_run_writes_exactly_the_bytes_shown_in_the_preview(tmp_path, monkeypatch, capsys):
    # Found by external review: the preview printed sorted-key JSON
    # (json.dumps(..., sort_keys=True)) but the actual write used plain
    # json.dumps(...) with no sort_keys, so on a settings.json with
    # existing unsorted keys, what the user approved and what landed on
    # disk were two different byte sequences (JSON-equivalent, but not
    # the same text) - a real accuracy bug in a "here's what I'm about
    # to write" confirmation prompt, even though harmless here.
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({"zeta": 1, "alpha": 2}))
    monkeypatch.setattr(init, "settings_path", lambda use_global: settings_path)

    init.run(use_global=False, assume_yes=True)

    printed = capsys.readouterr().out
    after_preview = printed.split("--- after ---\n", 1)[1].split("\nWired ccvet into")[0].rstrip("\n")
    on_disk = settings_path.read_text().rstrip("\n")
    assert after_preview == on_disk


def test_uninstall_writes_exactly_the_bytes_shown_in_the_preview(tmp_path, monkeypatch, capsys):
    settings_path = tmp_path / ".claude" / "settings.json"
    monkeypatch.setattr(init, "settings_path", lambda use_global: settings_path)
    init.run(use_global=False, assume_yes=True)

    data = init._load(settings_path)
    data["zeta"] = 1
    data["alpha"] = 2
    settings_path.write_text(json.dumps(data))

    capsys.readouterr()
    init.uninstall(use_global=False, assume_yes=True)

    printed = capsys.readouterr().out
    after_preview = printed.split("--- after ---\n", 1)[1].split("\nRemoved ccvet from")[0].rstrip("\n")
    on_disk = settings_path.read_text().rstrip("\n")
    assert after_preview == on_disk
