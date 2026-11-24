import io
import json

from ccvet import audit, gate


def _payload(tool_name, tool_input, cwd="/tmp/project"):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool_name, "tool_input": tool_input, "cwd": cwd})


def test_safe_bash_command_is_allowed_end_to_end():
    response = gate.build_response(_payload("Bash", {"command": "git status"}))
    out = response["hookSpecificOutput"]
    assert out["permissionDecision"] == "allow"


def test_dangerous_bash_command_is_denied_end_to_end():
    response = gate.build_response(_payload("Bash", {"command": "sudo rm -rf /"}))
    out = response["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"


def test_unknown_tool_defers():
    response = gate.build_response(_payload("SomeBrandNewMCPTool", {}))
    assert response["hookSpecificOutput"]["permissionDecision"] == "defer"


def test_missing_tool_name_defers():
    response = gate.build_response(json.dumps({"hook_event_name": "PreToolUse"}))
    assert response["hookSpecificOutput"]["permissionDecision"] == "defer"


def test_empty_stdin_defers():
    response = gate.build_response("")
    assert response["hookSpecificOutput"]["permissionDecision"] == "defer"


def test_malformed_json_falls_back_to_ask_not_defer():
    response = gate.build_response("{not json")
    assert response["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_truncated_json_falls_back_to_ask():
    truncated = '{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_inp'
    response = gate.build_response(truncated)
    assert response["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_tool_input_as_wrong_type_does_not_crash():
    # A string instead of an object - engine.evaluate's tool_input.get()
    # calls would raise AttributeError on a plain str; must still produce
    # a valid decision, not a traceback.
    payload = json.dumps({"tool_name": "Bash", "tool_input": "not-a-dict", "cwd": "/tmp"})
    response = gate.build_response(payload)
    assert response["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_tool_input_null_is_treated_as_empty_dict():
    payload = json.dumps({"tool_name": "Bash", "tool_input": None, "cwd": "/tmp"})
    response = gate.build_response(payload)
    # command defaults to "" -> empty command -> allow, not a crash
    assert response["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_top_level_json_array_instead_of_object_does_not_crash():
    response = gate.build_response("[1, 2, 3]")
    assert response["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_cwd_missing_entirely_does_not_crash():
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
    response = gate.build_response(payload)
    assert response["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_run_writes_an_audit_log_entry(monkeypatch):
    calls = []
    monkeypatch.setattr(audit, "log", lambda *a, **k: calls.append(a))
    monkeypatch.setattr("sys.stdin", io.StringIO(_payload("Bash", {"command": "ls"})))

    gate.run()

    assert len(calls) == 1


def test_run_dry_run_skips_the_audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr(audit, "log", lambda *a, **k: calls.append(a))
    monkeypatch.setattr("sys.stdin", io.StringIO(_payload("Bash", {"command": "ls"})))

    gate.run(dry_run=True)

    assert calls == []


def test_run_survives_an_audit_log_failure(monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(audit, "log", boom)
    monkeypatch.setattr("sys.stdin", io.StringIO(_payload("Bash", {"command": "ls"})))

    exit_code = gate.run()  # must not raise even though audit.log blew up

    assert exit_code == 0
