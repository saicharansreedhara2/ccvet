import json
import threading

from ccvet import audit
from ccvet.verdict import Verdict


def test_log_writes_valid_jsonl(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    audit.log("Bash", {"command": "git status"}, "/tmp/project", Verdict.allow("git status is read-only"), 1.23)

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["tool"] == "Bash"
    assert entry["input"]["command"] == "git status"
    assert entry["decision"] == "allow"
    assert entry["latency_ms"] == 1.23


def test_log_redacts_write_content_as_hash_not_plaintext(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    audit.log(
        "Write",
        {"file_path": "/tmp/project/secret.txt", "content": "API_KEY=super-secret-value"},
        "/tmp/project",
        Verdict.ask("writes to secret.txt"),
        0.5,
    )

    entry = json.loads(log_path.read_text().strip())
    assert "super-secret-value" not in json.dumps(entry)
    assert "content_sha256" in entry["input"]
    assert entry["input"]["content_length"] == len("API_KEY=super-secret-value")


def test_log_summarizes_read_tools_by_path_only(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    audit.log("Grep", {"pattern": "TODO", "path": "/tmp/project"}, "/tmp/project", Verdict.allow("grep is fine"), 0.1)

    entry = json.loads(log_path.read_text().strip())
    assert entry["input"] == {"path": "/tmp/project"}


def test_log_summarizes_webfetch_by_url(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    audit.log("WebFetch", {"url": "https://example.com"}, "/tmp", Verdict.ask("webfetch"), 0.1)

    entry = json.loads(log_path.read_text().strip())
    assert entry["input"] == {"url": "https://example.com"}


def test_log_summarizes_unknown_tool_by_input_keys(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    audit.log("SomeMCPTool", {"foo": 1, "bar": 2}, "/tmp", Verdict.defer("unknown tool"), 0.1)

    entry = json.loads(log_path.read_text().strip())
    assert entry["input"] == {"input_keys": ["bar", "foo"]}


def test_log_file_created_with_restrictive_permissions(tmp_path, monkeypatch):
    log_path = tmp_path / "nested" / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    audit.log("Bash", {"command": "ls"}, "/tmp", Verdict.allow("ls"), 0.1)

    mode = log_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_concurrent_writes_do_not_corrupt_the_log(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    def write_one(i):
        audit.log("Bash", {"command": f"echo {i}"}, "/tmp", Verdict.allow("echo"), 0.1)

    threads = [threading.Thread(target=write_one, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 50
    for line in lines:
        json.loads(line)  # every line must be independently parseable, none merged/truncated
