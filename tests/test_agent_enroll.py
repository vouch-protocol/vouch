"""
Tests for the portable identity bundle and the one-command enroll and
root-anchored verify flow.

Covers the library layer (build_identity_bundle + verify_bundle, happy path and
a wrong pinned root) and the CLI (`vouch agent enroll` produces a bundle that
`vouch agent verify` accepts against the correct root and rejects against a
wrong one). Everything runs offline with did:key identities and a temp keystore,
no network and no passphrase prompts.
"""

import json
import types

import pytest

from vouch import cli
from vouch.keys import KeyManager
from vouch.signer import Signer
from vouch.root_of_trust import (
    ACTION_ISSUE_AGENT_IDENTITY,
    IDENTITY_BUNDLE_TYPE,
    build_agent_identity,
    build_identity_bundle,
    build_recognized_issuer,
    build_root_of_trust,
    generate_did_key_identity,
    verify_bundle,
)


def _signer():
    """A fresh did:key signer."""
    return Signer.from_keypair(generate_did_key_identity())


def _read(path):
    with open(path, "r") as f:
        return json.load(f)


@pytest.fixture
def temp_keystore(tmp_path, monkeypatch):
    """Point KeyManager at a temp directory for the duration of a test."""
    key_dir = str(tmp_path / "keys")
    orig_init = KeyManager.__init__
    monkeypatch.setattr(
        KeyManager, "__init__", lambda self, key_dir=key_dir: orig_init(self, key_dir)
    )
    return tmp_path


# ---------------------------------------------------------------------------
# Library: build_identity_bundle + verify_bundle
# ---------------------------------------------------------------------------


def test_bundle_happy_path():
    """Root recognizes issuer, issuer attests agent, bundle verifies to root."""
    root = _signer()
    issuer = _signer()
    agent = _signer()

    root_cred = build_root_of_trust(root, name="Vouch Machine Identity Root")
    recognition = build_recognized_issuer(
        root, issuer_did=issuer.did, recognized_actions=[ACTION_ISSUE_AGENT_IDENTITY]
    )
    identity = build_agent_identity(
        issuer,
        subject_did=agent.did,
        attributes={"owner": "Acme", "model": "gpt-x", "capabilityClass": "shopping"},
    )
    action = agent.sign(
        intent={"action": "buy", "target": "store", "resource": "https://store.example/item/1"}
    )

    bundle = build_identity_bundle(
        identity=identity, recognition=recognition, action=action, root=root_cred
    )
    assert bundle["type"] == IDENTITY_BUNDLE_TYPE
    assert bundle["vouchVersion"] == "1.0"
    assert bundle["identity"] == identity
    assert bundle["recognizedIssuer"] == recognition
    assert bundle["action"] == action
    assert bundle["root"] == root_cred

    result = verify_bundle(bundle, trusted_root=root.did)
    assert result.ok
    assert result.agent_did == agent.did
    assert result.issuer_did == issuer.did
    assert result.root_did == root.did
    assert result.attributes == {
        "owner": "Acme",
        "model": "gpt-x",
        "capabilityClass": "shopping",
    }
    assert result.action is not None


def test_bundle_omits_optional_keys_when_none():
    root = _signer()
    issuer = _signer()
    agent = _signer()
    recognition = build_recognized_issuer(root, issuer_did=issuer.did)
    identity = build_agent_identity(issuer, subject_did=agent.did, attributes={"owner": "Acme"})

    bundle = build_identity_bundle(identity=identity, recognition=recognition)
    assert "action" not in bundle
    assert "root" not in bundle
    assert verify_bundle(bundle, trusted_root=root.did).ok


def test_bundle_wrong_root_rejected():
    """A bundle pinned to a root the verifier does not trust is rejected."""
    root = _signer()
    issuer = _signer()
    agent = _signer()
    recognition = build_recognized_issuer(root, issuer_did=issuer.did)
    identity = build_agent_identity(issuer, subject_did=agent.did, attributes={"owner": "Acme"})
    bundle = build_identity_bundle(identity=identity, recognition=recognition)

    wrong_root = _signer()
    result = verify_bundle(bundle, trusted_root=wrong_root.did)
    assert not result.ok
    assert result.reason == "recognized_issuer_not_from_root"


def test_verify_bundle_malformed():
    assert verify_bundle({}, trusted_root="did:key:zabc").reason == "bad_bundle"
    assert verify_bundle("nope", trusted_root="did:key:zabc").reason == "bad_bundle"
    assert (
        verify_bundle(
            {"type": IDENTITY_BUNDLE_TYPE, "identity": 1, "recognizedIssuer": {}},
            trusted_root="did:key:zabc",
        ).reason
        == "bad_bundle"
    )


# ---------------------------------------------------------------------------
# CLI: agent enroll -> agent verify
# ---------------------------------------------------------------------------


def _init_root(temp_keystore, out_name, capsys):
    """Mint a did:key identity via `root init` and return its DID."""
    out = str(temp_keystore / out_name)
    assert (
        cli.cmd_root_init(
            types.SimpleNamespace(
                name="Root", scope=None, domain=None, out=out, reference=False, yes=True
            )
        )
        == 0
    )
    capsys.readouterr()
    return _read(out)["issuer"]


def test_cli_enroll_and_verify(temp_keystore, capsys):
    # Root and issuer identities (both stored in the temp keystore).
    root_did = _init_root(temp_keystore, "root.json", capsys)
    issuer_did = _init_root(temp_keystore, "issuer.json", capsys)

    # Root recognizes the issuer.
    recognition_out = str(temp_keystore / "recognition.json")
    assert (
        cli.cmd_root_recognize(
            types.SimpleNamespace(
                issuer=issuer_did, actions=None, root_did=root_did, out=recognition_out
            )
        )
        == 0
    )
    capsys.readouterr()

    # Enroll an agent: generate a fresh agent DID, attest it, write the bundle.
    bundle_out = str(temp_keystore / "identity-bundle.json")
    rc = cli.cmd_agent_enroll(
        types.SimpleNamespace(
            agent_did=None,
            issuer_did=issuer_did,
            attr=["owner=Acme", "model=gpt-x"],
            recognition=recognition_out,
            action=None,
            out=bundle_out,
            yes=True,
        )
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Agent enrolled" in out
    assert "Generated agent identity:" in out

    bundle = _read(bundle_out)
    assert bundle["type"] == IDENTITY_BUNDLE_TYPE
    agent_did = bundle["identity"]["credentialSubject"]["id"]
    assert bundle["identity"]["issuer"] == issuer_did

    # Verify the bundle against the correct root.
    rc = cli.cmd_agent_verify(
        types.SimpleNamespace(
            bundle=bundle_out, root=root_did, action_required="issueAgentIdentity"
        )
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Identity bundle verified" in out
    assert agent_did in out
    assert issuer_did in out
    assert "Acme" in out

    # Verify against a WRONG root: non-zero exit and a clear reason on stderr.
    rc = cli.cmd_agent_verify(
        types.SimpleNamespace(
            bundle=bundle_out,
            root="did:key:z6MkNotTheRealRootDidPinnedByAnHonestVerifier00",
            action_required="issueAgentIdentity",
        )
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "rejected" in err.lower()
    assert "recognized_issuer_not_from_root" in err


def test_cli_enroll_verify_via_main(temp_keystore):
    """Drive the flow through cli.main with argv lists, including a supplied DID."""
    root_out = str(temp_keystore / "r.json")
    issuer_out = str(temp_keystore / "i.json")
    recognition_out = str(temp_keystore / "rec.json")
    bundle_out = str(temp_keystore / "bundle.json")

    assert cli.main(["root", "init", "--yes", "--out", root_out]) == 0
    assert cli.main(["root", "init", "--yes", "--out", issuer_out]) == 0
    root_did = _read(root_out)["issuer"]
    issuer_did = _read(issuer_out)["issuer"]

    assert (
        cli.main(
            [
                "root",
                "recognize",
                "--issuer",
                issuer_did,
                "--root-did",
                root_did,
                "--out",
                recognition_out,
            ]
        )
        == 0
    )

    agent_did = "did:key:z6MkagentSubjectPlaceholderDidForTest000000000000"
    assert (
        cli.main(
            [
                "agent",
                "enroll",
                "--agent-did",
                agent_did,
                "--issuer-did",
                issuer_did,
                "--attr",
                "owner=Acme",
                "--recognition",
                recognition_out,
                "--out",
                bundle_out,
            ]
        )
        == 0
    )
    assert _read(bundle_out)["identity"]["credentialSubject"]["id"] == agent_did

    # Correct root via --root.
    assert cli.main(["agent", "verify", "--bundle", bundle_out, "--root", root_did]) == 0

    # Root supplied through the VOUCH_TRUSTED_ROOT env var (no --root).
    import os

    os.environ["VOUCH_TRUSTED_ROOT"] = root_did
    try:
        assert cli.main(["agent", "verify", "--bundle", bundle_out]) == 0
    finally:
        del os.environ["VOUCH_TRUSTED_ROOT"]

    # Wrong root: non-zero.
    assert (
        cli.main(
            [
                "agent",
                "verify",
                "--bundle",
                bundle_out,
                "--root",
                "did:key:z6MkWrongRoot000000000000000000000000000000000000",
            ]
        )
        == 1
    )
