import json

from ccvet import gate


def test_valid_input_defers():
    payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}})
    response = gate.build_response(payload)
    out = response["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "defer"
    assert "Bash" in out["permissionDecisionReason"]


def test_empty_input_does_not_crash():
    response = gate.build_response("")
    assert response["hookSpecificOutput"]["permissionDecision"] == "defer"


def test_malformed_json_falls_back_to_ask_not_defer():
    response = gate.build_response("{not json")
    out = response["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask"
