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


def test_status_warns_about_unanchored_policy_rules(tmp_path, monkeypatch, capsys):
    # Found by external review: the ^...$ anchoring fix in
    # commands.allow() only applies going forward. A rule already
    # sitting in policy.yaml from before v0.0.9 (or written directly via
    # userpolicy.add_rule, bypassing the CLI's anchoring) stays exactly
    # as unanchored, and silently over-broad, as it always was -
    # upgrading ccvet does nothing to it. `ccvet status` now surfaces
    # this read-only, since auto-migrating risks narrowing a rule
    # someone wrote on purpose with --regex.
    monkeypatch.setattr(init, "settings_path", lambda use_global: tmp_path / ("g.json" if use_global else "p.json"))
    monkeypatch.setattr(userpolicy, "GLOBAL_PATH", tmp_path / "global_policy.yaml")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")
    monkeypatch.chdir(tmp_path)

    userpolicy.add_rule("ls", "allow", "written by ccvet 0.0.8", use_global=False, cwd=str(tmp_path))

    rc = commands.status(_ns())
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 rule(s)" in out
    assert "don't fully anchor" in out
    assert "'ls'" in out


def test_status_does_not_warn_about_an_anchored_rule(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(init, "settings_path", lambda use_global: tmp_path / ("g.json" if use_global else "p.json"))
    monkeypatch.setattr(userpolicy, "GLOBAL_PATH", tmp_path / "global_policy.yaml")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")
    monkeypatch.chdir(tmp_path)

    userpolicy.add_rule(r"^docker\ build\ \.$", "allow", "reviewed", use_global=False, cwd=str(tmp_path))

    rc = commands.status(_ns())
    out = capsys.readouterr().out
    assert rc == 0
    assert "don't fully anchor" not in out


def test_status_describes_a_suffix_anchored_rule_accurately(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(init, "settings_path", lambda use_global: tmp_path / ("g.json" if use_global else "p.json"))
    monkeypatch.setattr(userpolicy, "GLOBAL_PATH", tmp_path / "global_policy.yaml")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")
    monkeypatch.chdir(tmp_path)

    userpolicy.add_rule(r"build\.$", "ask", "suffix rule", use_global=False, cwd=str(tmp_path))

    rc = commands.status(_ns())
    out = capsys.readouterr().out
    assert rc == 0
    assert "suffix search" in out
    assert "substring search anywhere" not in out


def test_status_skips_a_rule_with_no_match_pattern(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(init, "settings_path", lambda use_global: tmp_path / ("g.json" if use_global else "p.json"))
    monkeypatch.setattr(userpolicy, "GLOBAL_PATH", tmp_path / "global_policy.yaml")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")
    monkeypatch.chdir(tmp_path)

    policy_path = userpolicy.project_path(str(tmp_path))
    policy_path.parent.mkdir(parents=True)
    policy_path.write_text("rules:\n  - verdict: allow\n    reason: no match key at all\n")

    rc = commands.status(_ns())
    out = capsys.readouterr().out
    assert rc == 0
    assert "don't fully anchor" not in out


def test_status_does_not_crash_on_a_non_dict_rule_entry(tmp_path, monkeypatch, capsys):
    # Found by external review: userpolicy._load_file deliberately
    # tolerates a malformed rules list (find_override itself skips any
    # non-dict item, specifically so a broken policy.yaml can't take
    # anything down), but this status() loop's rule.get("match") crashed
    # with an AttributeError on a hand-edited file with a bare string
    # item - ironic for the one command whose job is telling you your
    # policy is shaped wrong. The gate path was never affected (verified
    # separately via find_override's own guard); this is specific to
    # status()'s own loop.
    monkeypatch.setattr(init, "settings_path", lambda use_global: tmp_path / ("g.json" if use_global else "p.json"))
    monkeypatch.setattr(userpolicy, "GLOBAL_PATH", tmp_path / "global_policy.yaml")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")
    monkeypatch.chdir(tmp_path)

    policy_path = userpolicy.project_path(str(tmp_path))
    policy_path.parent.mkdir(parents=True)
    policy_path.write_text("rules:\n  - just a string\n")

    rc = commands.status(_ns())
    assert rc == 0


def test_status_describes_a_prefix_anchored_rule_accurately(tmp_path, monkeypatch, capsys):
    # Found by external review: a rule anchored at only one end (e.g.
    # the project's own docstring example, "^docker build\.") is a
    # prefix match, not an unanchored substring search - the original
    # wording called every unanchored-at-either-end rule a "substring
    # search anywhere", which overstated what a partially-anchored
    # pattern actually does.
    monkeypatch.setattr(init, "settings_path", lambda use_global: tmp_path / ("g.json" if use_global else "p.json"))
    monkeypatch.setattr(userpolicy, "GLOBAL_PATH", tmp_path / "global_policy.yaml")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")
    monkeypatch.chdir(tmp_path)

    userpolicy.add_rule(r"^docker build\.", "ask", "prefix rule", use_global=False, cwd=str(tmp_path))

    rc = commands.status(_ns())
    out = capsys.readouterr().out
    assert rc == 0
    assert "prefix search" in out
    assert "substring search anywhere" not in out


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


def test_allow_reports_invalid_regex_instead_of_writing_a_dead_rule(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = commands.allow(_ns(pattern="[unterminated", regex=True, verdict="allow", global_=False, reason=None))
    assert rc == 1
    assert "not a valid regex" in capsys.readouterr().err
    assert not (tmp_path / ".ccvet" / "policy.yaml").exists()


def test_policy_edit_handles_a_missing_editor_gracefully(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("EDITOR", "this-editor-does-not-exist-12345")
    rc = commands.policy_edit(_ns(global_=False))
    assert rc == 1
    assert "Could not launch editor" in capsys.readouterr().err


def test_log_view_survives_an_entry_missing_expected_keys(tmp_path, monkeypatch, capsys):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log_path)
    from ccvet.verdict import Verdict
    audit.log("Bash", {"command": "ls"}, "/tmp", Verdict.allow("ls is fine"), 0.1)
    with open(log_path, "a") as f:
        f.write('{"this": "has none of the expected fields"}\n')

    rc = commands.log_view(_ns(tail=20))
    out = capsys.readouterr().out
    assert rc == 0
    assert "ls is fine" in out


def test_log_view_negative_tail_shows_all_instead_of_weird_slice(tmp_path, monkeypatch, capsys):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", log_path)
    from ccvet.verdict import Verdict
    for i in range(3):
        audit.log("Bash", {"command": f"echo {i}"}, "/tmp", Verdict.allow(f"echo {i}"), 0.1)

    commands.log_view(_ns(tail=-5))
    out = capsys.readouterr().out
    assert out.count("echo 0") == 1
    assert out.count("echo 1") == 1
    assert out.count("echo 2") == 1


def test_status_handles_malformed_settings_json(tmp_path, monkeypatch, capsys):
    bad_settings = tmp_path / "bad_settings.json"
    bad_settings.write_text("{not valid json")
    monkeypatch.setattr(init, "settings_path", lambda use_global: bad_settings)
    monkeypatch.setattr(userpolicy, "GLOBAL_PATH", tmp_path / "global_policy.yaml")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")
    monkeypatch.chdir(tmp_path)

    rc = commands.status(_ns())
    out = capsys.readouterr().out
    assert rc == 0
    assert "invalid JSON" in out


def test_allow_writes_an_escaped_and_anchored_literal_rule(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    commands.allow(_ns(pattern="docker build .", regex=False, verdict="allow", global_=False, reason=None))

    rules = userpolicy._load_file(tmp_path / ".ccvet" / "policy.yaml")
    assert len(rules) == 1
    # a literal "." must be escaped, not treated as a regex wildcard, and
    # anchored to the whole command - not just escaped, see
    # test_literal_allow_pattern_does_not_match_as_an_unanchored_substring
    assert rules[0]["match"] == r"^docker\ build\ \.$"


def test_literal_allow_pattern_does_not_match_as_an_unanchored_substring(tmp_path, monkeypatch):
    # Found by external review: before anchoring, `ccvet allow "ls"`
    # stored the bare regex "ls", which re.search (unanchored) matched
    # inside "ls -la", "lsof -i", and "false-ls-check" alike (all three
    # otherwise land on the generic, overridable "ask" baseline) - a
    # promotion the user believes is narrow silently widening the allow
    # surface to "contains this text anywhere", with no indication it
    # had done so.
    monkeypatch.chdir(tmp_path)
    commands.allow(_ns(pattern="lsof -i", regex=False, verdict="allow", global_=False, reason=None))

    from ccvet.shellrules import evaluate

    assert evaluate("lsof -i", str(tmp_path)).decision == "allow"
    assert evaluate("lsof -iTCP", str(tmp_path)).decision != "allow"
    assert evaluate("false-ls-check", str(tmp_path)).decision != "allow"


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
