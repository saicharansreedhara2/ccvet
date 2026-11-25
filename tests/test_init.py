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
    assert entries[0]["hooks"][0]["command"] == "ccvet gate"


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
    assert "ccvet gate" in commands


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
    settings_path.write_text(__import__("json").dumps(data))

    exit_code = init.uninstall(use_global=False, assume_yes=True)
    assert exit_code == 0

    after = init._load(settings_path)
    commands = [h["command"] for entry in after["hooks"]["PreToolUse"] for h in entry["hooks"]]
    assert "ccvet gate" not in commands
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
