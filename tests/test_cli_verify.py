"""
Tests for `vouch verify`.

The command must check the signature whether or not a key is passed. With no
key it uses the matching identity in the local keystore, and otherwise resolves
the issuer's key from its DID. A credential whose signature cannot be checked
is reported invalid.
"""

import copy
import json
import types

import pytest

import vouch
from vouch import cli
from vouch.keys import KeyManager, generate_identity
from vouch.root_of_trust import generate_did_key_identity

INTENT = {
    "action": "read.file",
    "target": "report",
    "resource": "https://api.example.com/reports/1",
}


@pytest.fixture
def temp_keystore(tmp_path, monkeypatch):
    """Point KeyManager at a temp directory for the duration of a test."""
    orig_init = KeyManager.__init__
    monkeypatch.setattr(
        KeyManager, "__init__", lambda self, key_dir=str(tmp_path): orig_init(self, str(tmp_path))
    )
    monkeypatch.delenv("VOUCH_PUBLIC_KEY", raising=False)
    return tmp_path


@pytest.fixture
def no_network(monkeypatch):
    """Make any did:web lookup fail, so a test cannot reach the network."""
    from vouch import did_web

    def refuse(did, *args, **kwargs):
        raise RuntimeError(f"network lookup attempted for {did}")

    monkeypatch.setattr(did_web, "resolve_did_web_sync", refuse)


def run_verify(credential, key=None, as_json=False):
    token = credential if isinstance(credential, str) else json.dumps(credential)
    return cli.cmd_verify(types.SimpleNamespace(token=token, key=key, json=as_json))


def stored_identity(domain="agent.example.com", password=None):
    keys = generate_identity(domain)
    KeyManager().save_identity(keys, password=password)
    return keys


def tampered(credential):
    altered = copy.deepcopy(credential)
    altered["credentialSubject"]["intent"]["action"] = "ledger.transfer"
    return altered


# ---------------------------------------------------------------------------
# No key passed, issuer is in the local keystore
# ---------------------------------------------------------------------------


def test_verifies_own_credential_without_a_key(temp_keystore, no_network, capsys):
    keys = stored_identity()
    credential = vouch.sign(keys, INTENT)

    assert run_verify(credential) == 0
    out = capsys.readouterr().out
    assert "VALID" in out and "INVALID" not in out
    assert "local keystore" in out


def test_rejects_tampered_credential_without_a_key(temp_keystore, no_network, capsys):
    keys = stored_identity()
    credential = vouch.sign(keys, INTENT)

    assert run_verify(tampered(credential)) == 1
    out = capsys.readouterr().out
    assert "INVALID" in out
    # The key was found locally, so there is no hint about supplying one.
    assert "--key" not in out


def test_rejects_credential_with_no_proof(temp_keystore, no_network):
    keys = stored_identity()
    unsigned = vouch.sign(keys, INTENT)
    del unsigned["proof"]

    assert run_verify(unsigned) == 1


def test_rejects_forgery_under_a_local_issuer_name(temp_keystore, no_network):
    """Someone else signs a credential that names our DID as its issuer."""
    stored_identity("agent.example.com")
    impostor = generate_identity("agent.example.com")  # same DID, different key

    assert run_verify(vouch.sign(impostor, INTENT)) == 1


def test_encrypted_identity_still_verifies_without_a_password(temp_keystore, no_network):
    keys = stored_identity(password="correct horse battery staple")
    credential = vouch.sign(keys, INTENT)

    assert run_verify(credential) == 0
    assert run_verify(tampered(credential)) == 1


def test_post_quantum_credential_needs_both_proofs_checked(temp_keystore, no_network, capsys):
    """A proof set carries two proofs. With only the Ed25519 key at hand the
    command cannot check the second one, so it must not report VALID."""
    pytest.importorskip("pqcrypto.sign.ml_dsa_44")
    keys = stored_identity()
    signer = vouch.Signer(private_key=keys.private_key_jwk, did=keys.did)
    credential = signer.sign_hybrid(intent=INTENT)
    assert isinstance(credential["proof"], list)

    assert run_verify(credential) == 1
    assert "✅" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# No key passed, issuer is not in the local keystore
# ---------------------------------------------------------------------------


def test_unknown_issuer_is_not_reported_valid(temp_keystore, no_network, capsys):
    stranger = generate_identity("stranger.example.com")  # never saved
    credential = vouch.sign(stranger, INTENT)

    assert run_verify(credential) == 1
    out = capsys.readouterr().out
    assert "INVALID" in out
    assert "--key" in out


def test_did_key_issuer_verifies_offline(temp_keystore, no_network, capsys):
    keys = generate_did_key_identity()
    credential = vouch.sign(keys, INTENT)

    assert run_verify(credential) == 0
    assert "issuer's DID" in capsys.readouterr().out
    assert run_verify(tampered(credential)) == 1


def test_did_key_issuer_cannot_borrow_another_key(temp_keystore, no_network):
    """A credential signed by one key but naming a different did:key fails."""
    signer_keys = generate_did_key_identity()
    other = generate_did_key_identity()
    credential = vouch.sign(signer_keys, INTENT)
    relabelled = copy.deepcopy(credential)
    relabelled["issuer"] = other.did

    assert run_verify(relabelled) == 1


# ---------------------------------------------------------------------------
# Key passed explicitly
# ---------------------------------------------------------------------------


def test_explicit_key_is_used(temp_keystore, no_network, capsys):
    keys = generate_identity("partner.example.com")  # not in the keystore
    credential = vouch.sign(keys, INTENT)

    assert run_verify(credential, key=keys.public_key_jwk) == 0
    assert "key you supplied" in capsys.readouterr().out
    assert run_verify(tampered(credential), key=keys.public_key_jwk) == 1


def test_explicit_wrong_key_overrides_the_keystore(temp_keystore, no_network):
    keys = stored_identity()
    credential = vouch.sign(keys, INTENT)
    wrong = generate_identity("other.example.com")

    assert run_verify(credential, key=wrong.public_key_jwk) == 1


# ---------------------------------------------------------------------------
# Output and input handling
# ---------------------------------------------------------------------------


def test_json_output(temp_keystore, no_network, capsys):
    keys = stored_identity()
    credential = vouch.sign(keys, INTENT)

    assert run_verify(credential, as_json=True) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is True
    assert result["iss"] == keys.did
    assert result["intent"]["action"] == "read.file"
    assert result["key_source"] == "your local keystore"

    assert run_verify(tampered(credential), as_json=True) == 1
    assert json.loads(capsys.readouterr().out) == {"valid": False}


@pytest.mark.parametrize("token", ["not json", "[]", '"a string"', "{}", '{"issuer": 7}'])
def test_malformed_input_is_rejected(temp_keystore, no_network, token):
    assert run_verify(token) == 1


# ---------------------------------------------------------------------------
# KeyManager.get_public_key
# ---------------------------------------------------------------------------


def test_get_public_key_returns_only_the_exact_identity(temp_keystore):
    keys = stored_identity("agent.example.com")
    km = KeyManager()

    assert km.get_public_key(keys.did) == keys.public_key_jwk
    assert km.get_public_key("did:web:unknown.example.com") is None
    # These map to the same filename as the stored DID but are different DIDs.
    assert km.get_public_key("did-web-agent.example.com") is None
    assert km.get_public_key("did/web/agent.example.com") is None
    assert km.get_public_key("../did-web-agent.example.com") is None


def test_get_public_key_ignores_unreadable_files(temp_keystore):
    km = KeyManager()
    (temp_keystore / "did-web-broken.example.com.json").write_text("{not json")
    (temp_keystore / "did-web-list.example.com.json").write_text("[]")
    (temp_keystore / "did-web-nokey.example.com.json").write_text(
        json.dumps({"id": "did:web:nokey.example.com"})
    )

    assert km.get_public_key("did:web:broken.example.com") is None
    assert km.get_public_key("did:web:list.example.com") is None
    assert km.get_public_key("did:web:nokey.example.com") is None
