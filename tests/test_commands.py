import argparse
import json

from ccvet import audit, commands, config, init, userpolicy


def _ns(**kw):
    return argparse.Namespace(**kw)


def test_check_bash_command(capsys):
    rc = commands.check(_ns(shell_command="git status", tool=None, path=None, url=None, cwd="/tmp"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "decision: allow" in out


def test_check_requires_command_or_tool(capsys):
    rc = commands.check(_ns(shell_command=None, tool=None, path=None, url=None, cwd="/tmp"))
    assert rc == 1


def test_check_with_tool_and_url(capsys):
    rc = commands.check(_ns(shell_command=None, tool="WebFetch", path=None, url="https://example.com", cwd="/tmp"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "decision: ask" in out
    assert "example.com" in out


def test_check_with_tool_and_path(tmp_path, capsys):
    rc = commands.check(_ns(shell_command=None, tool="Write", path=str(tmp_path / "x.txt"), url=None, cwd=str(tmp_path)))
    out = capsys.readouterr().out
    assert rc == 0
    assert "decision: ask" in out


def test_status_runs_without_crashing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(init, "settings_path", lambda use_global: tmp_path / ("g.json" if use_global else "p.json"))
    monkeypatch.setattr(userpolicy, "GLOBAL_PATH", tmp_path / "global_policy.yaml")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")
    monkeypatch.chdir(tmp_path)

    rc = commands.status(_ns())
    out = capsys.readouterr().out
    assert rc == 0
    assert "ccvet" in out
    assert "not wired" in out


def test_status_reports_populated_policy_and_audit_log(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(init, "settings_path", lambda use_global: tmp_path / ("g.json" if use_global else "p.json"))
    monkeypatch.setattr(userpolicy, "GLOBAL_PATH", tmp_path / "global_policy.yaml")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")
    monkeypatch.chdir(tmp_path)

    userpolicy.add_rule(r"^docker build \.$", "allow", "reviewed", use_global=False, cwd=str(tmp_path))
    from ccvet.verdict import Verdict
    audit.log("Bash", {"command": "ls"}, str(tmp_path), Verdict.allow("ls"), 0.1)

    rc = commands.status(_ns())
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 rule(s)" in out
    assert "1 entries" in out


def test_log_view_skips_malformed_lines_but_shows_the_rest(tmp_path, monkeypatch, capsys):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log_path)
    from ccvet.verdict import Verdict
    audit.log("Bash", {"command": "ls"}, "/tmp", Verdict.allow("ls is fine"), 0.1)
    with open(log_path, "a") as f:
        f.write("{not valid json\n")

    rc = commands.log_view(_ns(tail=20))
    out = capsys.readouterr().out
    assert rc == 0
    assert "ls is fine" in out


def test_policy_edit_creates_file_and_invokes_editor(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("EDITOR", "true")

    rc = commands.policy_edit(_ns(global_=False))

    assert rc == 0
    assert (tmp_path / ".ccvet" / "policy.yaml").exists()


def test_log_view_prints_recent_entries(tmp_path, monkeypatch, capsys):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log_path)
    from ccvet.verdict import Verdict
    audit.log("Bash", {"command": "ls"}, "/tmp", Verdict.allow("ls is fine"), 0.5)

    rc = commands.log_view(_ns(tail=20))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Bash" in out
    assert "allow" in out


def test_log_view_with_no_log_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "does-not-exist.jsonl")
    rc = commands.log_view(_ns(tail=20))
    assert rc == 0
    assert "No audit log entries" in capsys.readouterr().out


def test_allow_writes_an_escaped_literal_rule(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    commands.allow(_ns(pattern="docker build .", regex=False, verdict="allow", global_=False, reason=None))

    rules = userpolicy._load_file(tmp_path / ".ccvet" / "policy.yaml")
    assert len(rules) == 1
    # a literal "." must be escaped, not treated as a regex wildcard
    assert rules[0]["match"] == r"docker\ build\ \."


def test_allow_with_regex_flag_stores_pattern_verbatim(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    commands.allow(_ns(pattern=r"^docker build", regex=True, verdict="ask", global_=False, reason="custom"))

    rules = userpolicy._load_file(tmp_path / ".ccvet" / "policy.yaml")
    assert rules[0]["match"] == r"^docker build"
    assert rules[0]["reason"] == "custom"


def test_config_all_values(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.yaml")
    config.set("classifier.base_url", "http://localhost:11434/v1")
    config.set("classifier.model", "qwen2.5")

    assert config.all_values() == {"classifier": {"base_url": "http://localhost:11434/v1", "model": "qwen2.5"}}


def test_config_get_set_roundtrip(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.yaml")

    rc = commands.config_get(_ns(key="classifier.base_url"))
    assert rc == 1
    assert "not set" in capsys.readouterr().out

    commands.config_set(_ns(key="classifier.base_url", value="http://localhost:11434/v1"))
    rc = commands.config_get(_ns(key="classifier.base_url"))
    assert rc == 0
    assert "http://localhost:11434/v1" in capsys.readouterr().out
