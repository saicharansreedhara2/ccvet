from ccvet import config, init


def test_detect_local_server_returns_none_when_nothing_running(monkeypatch):
    monkeypatch.setattr(init, "_probe", lambda base_url: False)
    assert init.detect_local_server() is None


def test_detect_local_server_returns_first_match(monkeypatch):
    monkeypatch.setattr(init, "_probe", lambda base_url: "11434" in base_url)
    found = init.detect_local_server()
    assert found is not None
    name, base_url = found
    assert "11434" in base_url


def test_offer_layer2_setup_skips_if_already_configured(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.yaml")
    config.set("classifier.base_url", "http://already-set/v1")
    monkeypatch.setattr(init, "detect_local_server", lambda: ("Ollama", "http://localhost:11434/v1"))

    init.offer_layer2_setup(assume_yes=True)

    assert config.get("classifier.base_url") == "http://already-set/v1"
    assert "Detected" not in capsys.readouterr().out


def test_offer_layer2_setup_writes_config_on_yes(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(init, "detect_local_server", lambda: ("Ollama", "http://localhost:11434/v1"))

    init.offer_layer2_setup(assume_yes=True)

    assert config.get("classifier.base_url") == "http://localhost:11434/v1"
    assert "Detected a local model server" in capsys.readouterr().out


def test_offer_layer2_setup_noop_when_nothing_detected(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(init, "detect_local_server", lambda: None)

    init.offer_layer2_setup(assume_yes=True)

    assert config.get("classifier.base_url") is None
    assert capsys.readouterr().out == ""
