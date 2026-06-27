"""
Tests for `vouch init` non-interactive setup.

`vouch init --yes` (or any non-TTY invocation) must provision an identity without
prompting, persist it to the keystore, and print the one-line wiring hint - so a
developer goes from nothing to "every tool call is signed" in a single command.
"""

import types

import pytest

from vouch import cli
from vouch.keys import KeyManager


@pytest.fixture
def temp_keystore(tmp_path, monkeypatch):
    """Point KeyManager at a temp directory for the duration of a test."""
    orig_init = KeyManager.__init__
    monkeypatch.setattr(
        KeyManager, "__init__", lambda self, key_dir=str(tmp_path): orig_init(self, str(tmp_path))
    )
    return tmp_path


def test_init_yes_is_non_interactive_and_persists(temp_keystore, capsys):
    args = types.SimpleNamespace(domain="agent.example.com", env=False, yes=True)
    rc = cli.cmd_init(args)
    assert rc == 0

    # Identity persisted to the keystore.
    files = list(temp_keystore.glob("*.json"))
    assert len(files) == 1

    out = capsys.readouterr().out
    assert "Identity saved" in out
    # The one-line wiring hint is shown.
    assert "from vouch import protect" in out


def test_init_persisted_identity_is_resolved_by_autosign(temp_keystore, monkeypatch):
    monkeypatch.delenv("VOUCH_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("VOUCH_DID", raising=False)

    args = types.SimpleNamespace(domain="agent.example.com", env=False, yes=True)
    assert cli.cmd_init(args) == 0

    import vouch.autosign as autosign

    autosign.reset_default_signer()
    signer = autosign.resolve_signer()
    assert signer is not None
    assert signer.get_did() == "did:web:agent.example.com"
    autosign.reset_default_signer()


def test_init_env_prints_exports_and_hint(temp_keystore, capsys):
    args = types.SimpleNamespace(domain="agent.example.com", env=True, yes=False)
    assert cli.cmd_init(args) == 0
    captured = capsys.readouterr()
    assert "export VOUCH_DID=" in captured.out
    assert "export VOUCH_PRIVATE_KEY=" in captured.out
