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
