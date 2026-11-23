from ccvet.engine import evaluate


def test_websearch_is_allowed():
    assert evaluate("WebSearch", {"query": "anything"}, "/tmp").decision == "allow"


def test_webfetch_asks():
    assert evaluate("WebFetch", {"url": "https://example.com"}, "/tmp").decision == "ask"


def test_task_spawn_asks():
    assert evaluate("Task", {"description": "do something"}, "/tmp").decision == "ask"


def test_unknown_tool_defers():
    verdict = evaluate("SomeFutureMCPTool", {}, "/tmp")
    assert verdict.decision == "defer"
