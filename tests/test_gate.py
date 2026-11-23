import json

from ccvet import gate


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
