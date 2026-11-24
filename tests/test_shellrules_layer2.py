from ccvet import classifier, config
from ccvet.shellrules import evaluate


def test_layer2_promotes_a_gray_zone_command_when_configured(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.yaml")
    config.set("classifier.base_url", "http://localhost:11434/v1")
    monkeypatch.setattr(
        classifier,
        "_call_llm",
        lambda *a, **k: '{"risk": "low", "reversible": true, "blast_radius": "repo", "rationale": "fine"}',
    )

    verdict = evaluate("docker build .", str(tmp_path))
    assert verdict.decision == "allow"
    assert "Layer 2" in verdict.reason


def test_user_policy_wins_over_layer2(tmp_path, monkeypatch):
    from ccvet import userpolicy

    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.yaml")
    config.set("classifier.base_url", "http://localhost:11434/v1")
    monkeypatch.setattr(
        classifier,
        "_call_llm",
        lambda *a, **k: '{"risk": "low", "reversible": true, "blast_radius": "repo", "rationale": "fine"}',
    )
    userpolicy.add_rule(r"^docker build \.$", "ask", "we review these manually", use_global=False, cwd=str(tmp_path))

    verdict = evaluate("docker build .", str(tmp_path))
    assert verdict.decision == "ask"
    assert "we review these manually" in verdict.reason


def test_layer2_cannot_touch_a_safety_floor_verdict(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.yaml")
    config.set("classifier.base_url", "http://localhost:11434/v1")
    monkeypatch.setattr(
        classifier,
        "_call_llm",
        lambda *a, **k: '{"risk": "low", "reversible": true, "blast_radius": "local", "rationale": "fine"}',
    )

    verdict = evaluate("rm -rf /", str(tmp_path))
    assert verdict.decision == "deny"


def test_layer2_is_never_even_called_for_a_non_overridable_verdict(tmp_path, monkeypatch):
    # Stronger than checking the final decision: prove the classifier is
    # structurally skipped, not just that its (possibly wrong) answer
    # happens to get ignored.
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.yaml")
    config.set("classifier.base_url", "http://localhost:11434/v1")

    calls = []
    monkeypatch.setattr(classifier, "_call_llm", lambda *a, **k: calls.append(a) or '{"risk": "low", "reversible": true, "blast_radius": "local", "rationale": "x"}')

    for dangerous_command in ("rm -rf /", "sudo anything", "git push --force", "terraform destroy"):
        evaluate(dangerous_command, str(tmp_path))

    assert calls == []


def test_layer2_disabled_falls_back_to_plain_ask(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.yaml")
    verdict = evaluate("docker build .", str(tmp_path))
    assert verdict.decision == "ask"
