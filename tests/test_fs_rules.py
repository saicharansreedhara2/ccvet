import os

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


def test_read_credential_path_is_denied(tmp_path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    verdict = evaluate("Read", {"file_path": str(ssh_dir / "id_rsa")}, str(tmp_path))
    assert verdict.decision == "deny"


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


def test_symlink_traversal_outside_root_is_denied(tmp_path):
    outside = tmp_path.parent / "outside_target_dir"
    outside.mkdir(exist_ok=True)
    real_target = outside / "secret.txt"
    real_target.write_text("x")
    link = tmp_path / "innocuous_link.txt"
    os.symlink(real_target, link)
    verdict = evaluate("Write", {"file_path": str(link)}, str(tmp_path))
    assert verdict.decision == "deny"
