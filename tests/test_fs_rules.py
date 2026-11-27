import os

import pytest

from ccvet.engine import evaluate


def test_read_inside_project_is_allowed(tmp_path):
    f = tmp_path / "README.md"
    f.write_text("hi")
    verdict = evaluate("Read", {"file_path": str(f)}, str(tmp_path))
    assert verdict.decision == "allow"


def test_write_inside_project_asks(tmp_path):
    verdict = evaluate("Write", {"file_path": str(tmp_path / "new.txt")}, str(tmp_path))
    assert verdict.decision == "ask"


def test_write_outside_project_root_is_denied(tmp_path, monkeypatch):
    outside = tmp_path.parent / "outside_sibling_dir"
    outside.mkdir(exist_ok=True)
    verdict = evaluate("Write", {"file_path": str(outside / "x.txt")}, str(tmp_path))
    assert verdict.decision == "deny"


def test_write_to_shell_rc_file_is_denied(tmp_path):
    rc = tmp_path / ".bashrc"
    verdict = evaluate("Write", {"file_path": str(rc)}, str(tmp_path))
    assert verdict.decision == "deny"


def test_write_to_git_hooks_is_denied(tmp_path):
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    verdict = evaluate("Edit", {"file_path": str(hooks_dir / "pre-commit")}, str(tmp_path))
    assert verdict.decision == "deny"


@pytest.mark.parametrize("filename", [".env", ".netrc", ".npmrc", ".pypirc", ".envrc"])
def test_read_env_style_credential_files_is_denied(tmp_path, filename):
    # Previously missing entirely: these are arguably the most common
    # real-world location for secrets, more so than some entries (like
    # /etc/shadow) that were already covered.
    verdict = evaluate("Read", {"file_path": str(tmp_path / filename)}, str(tmp_path))
    assert verdict.decision == "deny"


@pytest.mark.parametrize(
    "filename",
    [".env.local", ".env.production", ".env.development", ".env.staging"],
)
def test_read_env_variant_credential_files_is_denied(tmp_path, filename):
    # Found by external review (third round): component-exact matching on
    # a plain ".env" pattern caught only the literal ".env", so
    # .env.local/.env.production (the conventional, real-secret-bearing
    # variants, e.g. Next.js's env file loading order) read straight
    # through as allow.
    verdict = evaluate("Read", {"file_path": str(tmp_path / filename)}, str(tmp_path))
    assert verdict.decision == "deny"


@pytest.mark.parametrize(
    "filename",
    [".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults"],
)
def test_read_env_safe_variant_is_not_falsely_flagged_as_credential(tmp_path, filename):
    # The flip side of the above: .env.example and friends are the
    # equally conventional, safe, usually-committed documentation
    # variants and must not be swept up by a prefix-only fix.
    verdict = evaluate("Read", {"file_path": str(tmp_path / filename)}, str(tmp_path))
    assert verdict.decision != "deny"


@pytest.mark.parametrize(
    "relpath",
    [
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".mcp.json",
        ".claude/commands/evil.md",
        ".claude/agents/evil.md",
    ],
)
def test_write_to_claude_code_own_config_is_denied(tmp_path, relpath):
    # Found by external review (third round): these are the files that
    # define Claude Code's own permissions, hooks, and MCP servers -
    # rewriting one is exactly the "agent quietly makes itself persistent
    # / rewrites its own rules" class PERSISTENCE_PATTERNS exists to
    # catch, and a rewritten settings.json can silently drop ccvet's own
    # hook in the next session.
    target = tmp_path / relpath
    verdict = evaluate("Edit", {"file_path": str(target)}, str(tmp_path))
    assert verdict.decision == "deny"


def test_write_to_global_claude_settings_is_denied(tmp_path, monkeypatch):
    fake_home = tmp_path / "fakehome"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    verdict = evaluate("Edit", {"file_path": "~/.claude/settings.json"}, str(tmp_path))
    assert verdict.decision == "deny"


def test_read_credential_path_is_denied(tmp_path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    verdict = evaluate("Read", {"file_path": str(ssh_dir / "id_rsa")}, str(tmp_path))
    assert verdict.decision == "deny"


@pytest.mark.parametrize(
    "relpath",
    [
        ".git-credentials",
        ".config/gh/hosts.yml",
        ".docker/config.json",
        ".aws/sso/cache/abc123.json",
    ],
)
def test_read_other_credential_stores_is_denied(tmp_path, relpath):
    # Found by external review: the same class of gap .env was in
    # 0.0.1, for other credential stores - each of these is exclusively
    # a credential store by design (contrast .gitconfig, deliberately
    # not added, see the next test and paths.SECRET_PATTERNS).
    target = tmp_path / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    verdict = evaluate("Read", {"file_path": str(target)}, str(tmp_path))
    assert verdict.decision == "deny"


def test_gitconfig_and_sibling_gh_config_are_not_treated_as_credential_stores(tmp_path):
    # Deliberate judgment call, not an oversight: .gitconfig is an
    # ordinary config file that only atypically embeds a credential
    # (unlike .git-credentials, which is nothing but a plaintext
    # user:token@host store by design), and gh's own config.yml (sibling
    # to the denied hosts.yml) carries no token either.
    assert evaluate("Read", {"file_path": str(tmp_path / ".gitconfig")}, str(tmp_path)).decision != "deny"
    gh_dir = tmp_path / ".config" / "gh"
    gh_dir.mkdir(parents=True)
    assert evaluate("Read", {"file_path": str(gh_dir / "config.yml")}, str(tmp_path)).decision != "deny"


def test_similarly_named_file_is_not_falsely_flagged_as_secret(tmp_path):
    # Regression: "/etc/passwd" used to substring-match "/etc/passwd_notes.md".
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    verdict = evaluate("Read", {"file_path": str(etc_dir / "passwd_notes.md")}, str(tmp_path))
    assert verdict.decision != "deny"


def test_similarly_named_file_is_not_falsely_flagged_as_persistence(tmp_path):
    # Regression: ".bashrc" used to substring-match "my.bashrc_backup.txt".
    verdict = evaluate("Write", {"file_path": str(tmp_path / "my.bashrc_backup.txt")}, str(tmp_path))
    assert verdict.decision != "deny"


def test_similarly_named_file_is_not_falsely_flagged_as_manifest(tmp_path):
    # Regression: "package.json" used to substring-match "mypackage.json".
    verdict = evaluate("Write", {"file_path": str(tmp_path / "mypackage.json")}, str(tmp_path))
    assert "manifest" not in verdict.reason


def test_write_with_no_recognizable_path_field_asks_rather_than_crashes(tmp_path):
    verdict = evaluate("Write", {"content": "hello"}, str(tmp_path))
    assert verdict.decision == "ask"
    assert "no recognizable path" in verdict.reason


@pytest.mark.parametrize(
    "pattern",
    [".env.production", ".env", "credential", "**/.ssh/id_*", "/etc/passwd"],
)
def test_grep_glob_pattern_field_is_not_treated_as_a_path(tmp_path, pattern):
    # Found by external review: "pattern" (a search term for Grep/Glob,
    # not a filesystem path) used to be in _PATH_KEYS as a fallback, so
    # it got resolved and checked against the credential-path list like
    # any other path - a Grep for the literal text ".env.production", or
    # a Glob for "**/.ssh/id_*", is an ordinary, harmless search that was
    # denied outright with no scoping path involved at all.
    grep_verdict = evaluate("Grep", {"pattern": pattern}, str(tmp_path))
    assert grep_verdict.decision == "allow"
    glob_verdict = evaluate("Glob", {"pattern": pattern}, str(tmp_path))
    assert glob_verdict.decision == "allow"


def test_grep_with_a_credential_path_as_the_scoping_path_still_denies(tmp_path):
    # The fix above must not blind the check entirely - a real scoping
    # "path" field pointed at a credential path is still a real read of
    # that path and must still deny, same as it always has.
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    verdict = evaluate("Grep", {"pattern": "PRIVATE KEY", "path": str(ssh_dir / "id_rsa")}, str(tmp_path))
    assert verdict.decision == "deny"


def test_grep_with_no_path_field_at_all_is_allowed_not_asked(tmp_path):
    # Found by external review: with no "path" and "pattern" no longer
    # treated as one, a bare Grep(pattern=...) (search the whole cwd,
    # an entirely ordinary case) used to fall to "ask, no recognizable
    # path field" - but Grep/Glob are read-only by construction
    # (Docs/risk-taxonomy.md), so this is an AUTO case, not a gray zone.
    verdict = evaluate("Grep", {"pattern": "TODO"}, str(tmp_path))
    assert verdict.decision == "allow"


def test_write_to_package_manifest_asks(tmp_path):
    pkg = tmp_path / "package.json"
    verdict = evaluate("Write", {"file_path": str(pkg)}, str(tmp_path))
    assert verdict.decision == "ask"
    assert "manifest" in verdict.reason


def test_write_to_ci_workflow_asks(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    verdict = evaluate("Edit", {"file_path": str(workflow_dir / "ci.yml")}, str(tmp_path))
    assert verdict.decision == "ask"


def test_relative_dotdot_traversal_to_credential_path_is_denied(tmp_path):
    # Not a symlink this time - just a "../../.ssh/id_rsa"-shaped relative
    # path handed to the tool, which must resolve against cwd and still
    # hit the credential-path check rather than being treated as a benign
    # in-project relative path.
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir(exist_ok=True)
    (ssh_dir / "id_rsa").write_text("fake key")

    project = tmp_path / "project"
    project.mkdir()
    relative = "../.ssh/id_rsa"

    verdict = evaluate("Read", {"file_path": relative}, str(project))
    assert verdict.decision == "deny"


def test_relative_dotdot_traversal_outside_project_root_is_denied(tmp_path):
    sibling = tmp_path.parent / "sibling_outside"
    sibling.mkdir(exist_ok=True)
    (sibling / "notes.txt").write_text("x")

    project = tmp_path / "project2"
    project.mkdir()

    verdict = evaluate("Write", {"file_path": "../sibling_outside/notes.txt"}, str(project))
    assert verdict.decision == "deny"


def test_symlink_traversal_outside_root_is_denied(tmp_path):
    outside = tmp_path.parent / "outside_target_dir"
    outside.mkdir(exist_ok=True)
    real_target = outside / "secret.txt"
    real_target.write_text("x")
    link = tmp_path / "innocuous_link.txt"
    os.symlink(real_target, link)
    verdict = evaluate("Write", {"file_path": str(link)}, str(tmp_path))
    assert verdict.decision == "deny"
