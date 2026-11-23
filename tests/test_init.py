from ccvet import init


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
