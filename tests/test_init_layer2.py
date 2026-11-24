import urllib.error

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


def test_offer_layer2_setup_declines_when_user_says_no(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(init, "detect_local_server", lambda: ("Ollama", "http://localhost:11434/v1"))
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    init.offer_layer2_setup(assume_yes=False)

    assert config.get("classifier.base_url") is None


def test_probe_treats_http_error_as_reachable(monkeypatch):
    def raise_http_error(*a, **k):
        raise urllib.error.HTTPError("http://x", 404, "not found", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", raise_http_error)
    assert init._probe("http://localhost:11434/v1") is True


def test_probe_returns_true_on_a_clean_response(monkeypatch):
    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _FakeResponse())
    assert init._probe("http://localhost:11434/v1") is True


def test_probe_treats_connection_refused_as_unreachable(monkeypatch):
    def raise_connection_error(*a, **k):
        raise ConnectionRefusedError("nope")

    monkeypatch.setattr("urllib.request.urlopen", raise_connection_error)
    assert init._probe("http://localhost:19999/v1") is False
