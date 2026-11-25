from ccvet import config


def test_existing_but_whitespace_only_file_is_empty(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("   \n\n")
    monkeypatch.setattr(config, "CONFIG_PATH", path)

    assert config.all_values() == {}


def test_malformed_yaml_degrades_to_empty_not_raise(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("not: valid: yaml: [")
    monkeypatch.setattr(config, "CONFIG_PATH", path)

    assert config.get("anything") is None
    assert config.all_values() == {}


def test_non_dict_top_level_yaml_degrades_to_empty(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("- just\n- a\n- list\n")
    monkeypatch.setattr(config, "CONFIG_PATH", path)

    assert config.all_values() == {}


def test_set_overwrites_a_non_dict_intermediate_instead_of_crashing(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("classifier: just_a_string\n")
    monkeypatch.setattr(config, "CONFIG_PATH", path)

    config.set("classifier.base_url", "http://localhost:11434/v1")

    assert config.get("classifier.base_url") == "http://localhost:11434/v1"
