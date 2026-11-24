from ccvet import userpolicy
from ccvet.shellrules import evaluate


def _write_project_rule(tmp_path, pattern, verdict, reason="test rule"):
    userpolicy.add_rule(pattern, verdict, reason, use_global=False, cwd=str(tmp_path))


def test_user_rule_promotes_an_overridable_ask_to_allow(tmp_path):
    # "docker build ." falls into the generic ASK_PROGRAMS fallback, which
    # is marked overridable in rules.py.
    assert evaluate("docker build .", str(tmp_path)).decision == "ask"
    _write_project_rule(tmp_path, r"^docker build \.$", "allow")
    assert evaluate("docker build .", str(tmp_path)).decision == "allow"


def test_user_rule_cannot_override_a_safety_floor_guard(tmp_path):
    # rm -rf / hits a non-overridable hard-coded guard; even an exact-match
    # "allow everything" rule for it must not take effect.
    _write_project_rule(tmp_path, r"rm -rf /", "allow")
    verdict = evaluate("rm -rf /", str(tmp_path))
    assert verdict.decision == "deny"


def test_user_rule_can_add_its_own_stricter_deny(tmp_path):
    _write_project_rule(tmp_path, r"^docker run", "deny", reason="we don't allow docker run here")
    verdict = evaluate("docker run -it ubuntu", str(tmp_path))
    assert verdict.decision == "deny"
    assert "don't allow docker run" in verdict.reason


def test_project_rule_takes_precedence_over_global_rule(tmp_path, monkeypatch):
    global_path = tmp_path / "global_policy.yaml"
    monkeypatch.setattr(userpolicy, "GLOBAL_PATH", global_path)
    userpolicy.add_rule(r"^npm run build$", "ask", "global default", use_global=True, cwd=str(tmp_path))

    project_dir = tmp_path / "myproject"
    project_dir.mkdir()
    userpolicy.add_rule(r"^npm run build$", "allow", "project override", use_global=False, cwd=str(project_dir))

    verdict = evaluate("npm run build", str(project_dir))
    assert verdict.decision == "allow"
    assert "project override" in verdict.reason


def test_malformed_regex_in_user_policy_is_skipped_not_fatal(tmp_path):
    _write_project_rule(tmp_path, r"[unterminated", "allow")
    # must not raise, and must fall through to the normal built-in verdict
    verdict = evaluate("docker build .", str(tmp_path))
    assert verdict.decision == "ask"


def test_no_policy_file_is_a_silent_noop(tmp_path):
    assert userpolicy.load_rules(str(tmp_path)) == []


def test_empty_policy_file_is_a_silent_noop(tmp_path):
    path = userpolicy.project_path(str(tmp_path))
    path.parent.mkdir(parents=True)
    path.write_text("   \n")
    assert userpolicy.load_rules(str(tmp_path)) == []


def test_rule_with_no_match_key_is_skipped(tmp_path):
    path = userpolicy.project_path(str(tmp_path))
    path.parent.mkdir(parents=True)
    path.write_text("rules:\n  - verdict: allow\n    reason: oops, forgot match\n")

    assert evaluate("docker build .", str(tmp_path)).decision == "ask"


def test_rule_with_invalid_verdict_name_is_skipped(tmp_path):
    path = userpolicy.project_path(str(tmp_path))
    path.parent.mkdir(parents=True)
    path.write_text("rules:\n  - match: 'docker build'\n    verdict: not_a_real_verdict\n")

    assert evaluate("docker build .", str(tmp_path)).decision == "ask"


def test_add_rule_appends_to_an_existing_populated_file(tmp_path):
    userpolicy.add_rule(r"^npm run build$", "allow", "first rule", use_global=False, cwd=str(tmp_path))
    userpolicy.add_rule(r"^docker build \.$", "allow", "second rule", use_global=False, cwd=str(tmp_path))

    rules = userpolicy._load_file(userpolicy.project_path(str(tmp_path)))
    assert len(rules) == 2
    assert {r["reason"] for r in rules} == {"first rule", "second rule"}
