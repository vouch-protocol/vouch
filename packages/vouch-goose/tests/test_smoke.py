"""Smoke tests for the vouch-goose package."""

import pytest


def test_package_exports():
    import vouch_goose

    assert vouch_goose.install is not None
    assert vouch_goose.extension_config is not None
    assert vouch_goose.goose_config_path is not None


def test_extension_config_shape():
    from vouch_goose import extension_config

    cfg = extension_config()

    assert cfg["type"] == "stdio"
    assert cfg["cmd"] == "vouch-mcp"
    assert cfg["enabled"] is True
    assert cfg["args"] == []
    assert cfg["timeout"] == 300


def test_install_creates_file_and_registers(tmp_path):
    pytest.importorskip("yaml")
    import yaml

    from vouch_goose import install

    cfg = tmp_path / "sub" / "config.yaml"
    path = install(config_path=cfg)

    assert path.exists()
    data = yaml.safe_load(path.read_text())
    assert data["extensions"]["vouch"]["type"] == "stdio"
    assert data["extensions"]["vouch"]["cmd"] == "vouch-mcp"


def test_install_preserves_existing(tmp_path):
    pytest.importorskip("yaml")
    import yaml

    from vouch_goose import install

    cfg = tmp_path / "config.yaml"
    cfg.write_text("GOOSE_MODEL: gpt\nextensions:\n  other:\n    type: stdio\n    cmd: foo\n")
    install(config_path=cfg)

    data = yaml.safe_load(cfg.read_text())
    assert data["extensions"]["vouch"]["cmd"] == "vouch-mcp"
    assert data["extensions"]["other"]["cmd"] == "foo"  # preserved
    assert data["GOOSE_MODEL"] == "gpt"  # preserved


def test_install_keep_existing(tmp_path):
    pytest.importorskip("yaml")
    import yaml

    from vouch_goose import install

    cfg = tmp_path / "config.yaml"
    cfg.write_text("extensions:\n  vouch:\n    type: stdio\n    cmd: custom-vouch-mcp\n")
    install(config_path=cfg, overwrite=False)

    data = yaml.safe_load(cfg.read_text())
    assert data["extensions"]["vouch"]["cmd"] == "custom-vouch-mcp"  # left intact
