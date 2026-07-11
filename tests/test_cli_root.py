"""
End-to-end tests for the `vouch root` command group (Root of Trust for Machine
Identity).

Drives the CLI handlers directly through argparse namespaces with a temp
keystore and temp output files, so the full flow runs offline with did:key
identities and no passphrase prompts:

    root init  ->  root recognize  ->  root issue-identity  ->  root verify-chain

Covers the happy path (a chain that verifies with the right agent, issuer, and
attributes) and a rejection (verify-chain against a wrong pinned root DID).
"""

import json
import types

import pytest

from vouch import cli
from vouch.keys import KeyManager


@pytest.fixture
def temp_keystore(tmp_path, monkeypatch):
    """Point KeyManager at a temp directory for the duration of a test."""
    key_dir = str(tmp_path / "keys")
    orig_init = KeyManager.__init__
    monkeypatch.setattr(
        KeyManager, "__init__", lambda self, key_dir=key_dir: orig_init(self, key_dir)
    )
    return tmp_path


def _read(path):
    with open(path, "r") as f:
        return json.load(f)


def _stored_dids(temp_keystore):
    """Return the DIDs saved to the temp keystore, root first is not guaranteed."""
    km = KeyManager()
    return [ident["did"] for ident in km.list_identities()]


def test_root_chain_happy_path(temp_keystore, capsys):
    root_out = str(temp_keystore / "root-of-trust.json")
    recognition_out = str(temp_keystore / "recognition.json")
    identity_out = str(temp_keystore / "identity.json")

    # 1. Create the root (did:key, non-interactive, no passphrase).
    rc = cli.cmd_root_init(
        types.SimpleNamespace(
            name="Vouch Machine Identity Root",
            scope=None,
            domain=None,
            out=root_out,
            reference=True,
            yes=True,
        )
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Root DID:" in out
    assert "reference root" in out.lower()

    root_cred = _read(root_out)
    root_did = root_cred["issuer"]
    assert root_did.startswith("did:key:")
    assert "VouchRootOfTrust" in root_cred["type"]

    # 2. Create a recognized issuer identity to name. It just needs a DID and a
    #    stored key, so reuse `root init` to mint a second did:key identity, then
    #    recognize it from the root.
    issuer_out = str(temp_keystore / "issuer-root.json")
    assert (
        cli.cmd_root_init(
            types.SimpleNamespace(
                name="Issuer",
                scope=None,
                domain=None,
                out=issuer_out,
                reference=False,
                yes=True,
            )
        )
        == 0
    )
    capsys.readouterr()
    issuer_did = _read(issuer_out)["issuer"]
    assert issuer_did != root_did

    # 3. Root recognizes the issuer for issueAgentIdentity.
    rc = cli.cmd_root_recognize(
        types.SimpleNamespace(
            issuer=issuer_did,
            actions="issueAgentIdentity",
            root_did=root_did,
            out=recognition_out,
        )
    )
    assert rc == 0
    recognition = _read(recognition_out)
    assert recognition["issuer"] == root_did
    assert recognition["credentialSubject"]["id"] == issuer_did

    # 4. The recognized issuer issues an agent identity with attributes.
    agent_did = "did:key:z6MkagentSubjectPlaceholderDidForTest000000000000"
    rc = cli.cmd_root_issue_identity(
        types.SimpleNamespace(
            subject=agent_did,
            attr=["owner=Acme", "model=gpt-x", "capabilityClass=shopping"],
            issuer_did=issuer_did,
            out=identity_out,
        )
    )
    assert rc == 0
    identity = _read(identity_out)
    assert identity["issuer"] == issuer_did
    assert identity["credentialSubject"]["id"] == agent_did
    assert identity["credentialSubject"]["identity"]["owner"] == "Acme"

    # 5. Verify the chain against the correctly pinned root.
    rc = cli.cmd_root_verify_chain(
        types.SimpleNamespace(
            identity=identity_out,
            recognition=recognition_out,
            root=root_did,
            action=None,
            root_cred=root_out,
            action_required="issueAgentIdentity",
        )
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Identity chain verified" in out
    assert agent_did in out
    assert issuer_did in out
    assert "Acme" in out


def test_verify_chain_wrong_root_rejected(temp_keystore, capsys):
    root_out = str(temp_keystore / "root-of-trust.json")
    recognition_out = str(temp_keystore / "recognition.json")
    identity_out = str(temp_keystore / "identity.json")
    issuer_out = str(temp_keystore / "issuer-root.json")

    # Build a valid chain first.
    assert (
        cli.cmd_root_init(
            types.SimpleNamespace(
                name="Root", scope=None, domain=None, out=root_out, reference=False, yes=True
            )
        )
        == 0
    )
    root_did = _read(root_out)["issuer"]
    assert (
        cli.cmd_root_init(
            types.SimpleNamespace(
                name="Issuer", scope=None, domain=None, out=issuer_out, reference=False, yes=True
            )
        )
        == 0
    )
    issuer_did = _read(issuer_out)["issuer"]

    assert (
        cli.cmd_root_recognize(
            types.SimpleNamespace(
                issuer=issuer_did, actions=None, root_did=root_did, out=recognition_out
            )
        )
        == 0
    )
    assert (
        cli.cmd_root_issue_identity(
            types.SimpleNamespace(
                subject="did:key:z6MkagentSubjectPlaceholderDidForTest000000000000",
                attr=["owner=Acme"],
                issuer_did=issuer_did,
                out=identity_out,
            )
        )
        == 0
    )
    capsys.readouterr()

    # Pin the WRONG root DID: verification must fail with a non-zero exit and a
    # clear reason on stderr.
    wrong_root = "did:key:z6MkNotTheRealRootDidPinnedByAnHonestVerifier00"
    rc = cli.cmd_root_verify_chain(
        types.SimpleNamespace(
            identity=identity_out,
            recognition=recognition_out,
            root=wrong_root,
            action=None,
            root_cred=None,
            action_required="issueAgentIdentity",
        )
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "rejected" in err.lower()
    assert "recognized_issuer_not_from_root" in err


def test_verify_chain_full_via_main(temp_keystore):
    """Drive the happy path through `cli.main` with argv lists, end to end."""
    root_out = str(temp_keystore / "r.json")
    issuer_out = str(temp_keystore / "i.json")
    recognition_out = str(temp_keystore / "rec.json")
    identity_out = str(temp_keystore / "id.json")

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
    assert (
        cli.main(
            [
                "root",
                "issue-identity",
                "--subject",
                "did:key:z6MkagentSubjectPlaceholderDidForTest000000000000",
                "--attr",
                "owner=Acme",
                "--issuer-did",
                issuer_did,
                "--out",
                identity_out,
            ]
        )
        == 0
    )
    assert (
        cli.main(
            [
                "root",
                "verify-chain",
                "--identity",
                identity_out,
                "--recognition",
                recognition_out,
                "--root",
                root_did,
            ]
        )
        == 0
    )
