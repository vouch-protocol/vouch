"""
Tests for the Root of Trust for Machine Identity (vouch.root_of_trust).

Covers the happy-path chain (root -> recognized issuer -> agent identity ->
action) plus the forgery vectors the model is designed to stop: a fake root,
self-recognition, tampering, an unrecognized issuer, an unauthorized action,
revocation, and expiry. Everything runs offline with did:key identities.
"""

import copy

import pytest

from vouch.signer import Signer
from vouch.vc import VC_CONTEXT_V2, VOUCH_CONTEXT_V1, VC_TYPE
from vouch.root_of_trust import (
    ACTION_ISSUE_AGENT_IDENTITY,
    ACTION_ISSUE_ROBOT_IDENTITY,
    RECOGNIZED_ISSUER_TYPE,
    _sign,
    build_agent_identity,
    build_recognized_issuer,
    build_root_of_trust,
    generate_did_key_identity,
    register_recognized_issuer,
    verify_identity_chain,
)


def _signer():
    """A fresh did:key signer."""
    return Signer.from_keypair(generate_did_key_identity())


@pytest.fixture
def chain():
    """A valid root -> recognized issuer -> agent identity -> action chain."""
    root = _signer()
    issuer = _signer()
    agent = _signer()

    root_cred = build_root_of_trust(root, name="Vouch Machine Identity Root")
    recognition = build_recognized_issuer(
        root,
        issuer_did=issuer.did,
        recognized_actions=[ACTION_ISSUE_AGENT_IDENTITY],
    )
    identity = build_agent_identity(
        issuer,
        subject_did=agent.did,
        attributes={"owner": "Acme", "model": "gpt-x", "capabilityClass": "shopping"},
    )
    action = agent.sign(
        intent={"action": "buy", "target": "store", "resource": "https://store.example/item/1"}
    )
    return {
        "root": root,
        "issuer": issuer,
        "agent": agent,
        "root_cred": root_cred,
        "recognition": recognition,
        "identity": identity,
        "action": action,
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_full_chain_verifies(chain):
    result = verify_identity_chain(
        chain["identity"],
        chain["recognition"],
        trusted_root=chain["root"].did,
        action_credential=chain["action"],
        root_credential=chain["root_cred"],
    )
    assert result.ok, result.reason
    assert result.agent_did == chain["agent"].did
    assert result.issuer_did == chain["issuer"].did
    assert result.root_did == chain["root"].did
    assert result.attributes["owner"] == "Acme"
    assert result.action is not None
    assert result.action.action == "buy"


def test_identity_only_without_action(chain):
    result = verify_identity_chain(
        chain["identity"],
        chain["recognition"],
        trusted_root=chain["root"].did,
    )
    assert result.ok, result.reason
    assert result.action is None


def test_robot_issuer_scope(chain):
    """An issuer recognized for robot identity verifies for that action."""
    root = chain["root"]
    issuer = chain["issuer"]
    robot = _signer()
    recognition = build_recognized_issuer(
        root, issuer_did=issuer.did, recognized_actions=[ACTION_ISSUE_ROBOT_IDENTITY]
    )
    identity = build_agent_identity(
        issuer, subject_did=robot.did, attributes={"owner": "Acme", "hardwareRoot": "se-050"}
    )
    result = verify_identity_chain(
        identity,
        recognition,
        trusted_root=root.did,
        required_action=ACTION_ISSUE_ROBOT_IDENTITY,
    )
    assert result.ok, result.reason


# ---------------------------------------------------------------------------
# Forgery vectors
# ---------------------------------------------------------------------------


def test_fake_root_rejected(chain):
    """A recognition signed by a different root does not anchor to the pin."""
    fake_root = _signer()
    forged = build_recognized_issuer(fake_root, issuer_did=chain["issuer"].did)
    result = verify_identity_chain(chain["identity"], forged, trusted_root=chain["root"].did)
    assert not result.ok
    assert result.reason == "recognized_issuer_not_from_root"


def test_self_recognition_rejected(chain):
    """An issuer recognizing itself is not the pinned root."""
    issuer = chain["issuer"]
    self_reco = build_recognized_issuer(issuer, issuer_did=issuer.did)
    result = verify_identity_chain(chain["identity"], self_reco, trusted_root=chain["root"].did)
    assert not result.ok
    assert result.reason == "recognized_issuer_not_from_root"


def test_wrong_pinned_root_rejected(chain):
    """Pinning an unrelated root DID rejects a legitimate recognition."""
    result = verify_identity_chain(
        chain["identity"], chain["recognition"], trusted_root="did:key:zSomeoneElse"
    )
    assert not result.ok
    assert result.reason == "recognized_issuer_not_from_root"


def test_tampered_identity_attributes_rejected(chain):
    """Editing identity attributes after signing breaks the proof."""
    tampered = copy.deepcopy(chain["identity"])
    tampered["credentialSubject"]["identity"]["capabilityClass"] = "admin"
    result = verify_identity_chain(tampered, chain["recognition"], trusted_root=chain["root"].did)
    assert not result.ok
    assert result.reason == "identity_proof_invalid"


def test_tampered_recognition_rejected(chain):
    """Adding an action to a signed recognition breaks the proof."""
    tampered = copy.deepcopy(chain["recognition"])
    tampered["credentialSubject"]["recognizedActions"].append(ACTION_ISSUE_ROBOT_IDENTITY)
    result = verify_identity_chain(chain["identity"], tampered, trusted_root=chain["root"].did)
    assert not result.ok
    assert result.reason == "recognized_issuer_proof_invalid"


def test_identity_from_unrecognized_issuer_rejected(chain):
    """An identity signed by an issuer the root never recognized is rejected."""
    other_issuer = _signer()
    identity = build_agent_identity(
        other_issuer,
        subject_did=chain["agent"].did,
        attributes={"owner": "Impostor"},
    )
    result = verify_identity_chain(identity, chain["recognition"], trusted_root=chain["root"].did)
    assert not result.ok
    assert result.reason == "identity_not_from_recognized_issuer"


def test_issuer_not_recognized_for_action(chain):
    """An issuer recognized only for robots cannot mint an agent identity."""
    recognition = build_recognized_issuer(
        chain["root"],
        issuer_did=chain["issuer"].did,
        recognized_actions=[ACTION_ISSUE_ROBOT_IDENTITY],
    )
    result = verify_identity_chain(
        chain["identity"],
        recognition,
        trusted_root=chain["root"].did,
        required_action=ACTION_ISSUE_AGENT_IDENTITY,
    )
    assert not result.ok
    assert result.reason == "issuer_not_recognized_for_action"


def test_action_from_different_agent_rejected(chain):
    """An action signed by an agent other than the identity subject is rejected."""
    other_agent = _signer()
    foreign_action = other_agent.sign(
        intent={"action": "buy", "target": "store", "resource": "https://store.example/item/9"}
    )
    result = verify_identity_chain(
        chain["identity"],
        chain["recognition"],
        trusted_root=chain["root"].did,
        action_credential=foreign_action,
    )
    assert not result.ok
    assert result.reason == "action_not_from_agent"


def test_revoked_recognition_rejected(chain):
    revoked_ids = {chain["recognition"]["id"]}
    result = verify_identity_chain(
        chain["identity"],
        chain["recognition"],
        trusted_root=chain["root"].did,
        is_revoked=lambda cred: cred.get("id") in revoked_ids,
    )
    assert not result.ok
    assert result.reason == "recognized_issuer_revoked"


def test_revoked_identity_rejected(chain):
    revoked_ids = {chain["identity"]["id"]}
    result = verify_identity_chain(
        chain["identity"],
        chain["recognition"],
        trusted_root=chain["root"].did,
        is_revoked=lambda cred: cred.get("id") in revoked_ids,
    )
    assert not result.ok
    assert result.reason == "identity_revoked"


def test_expired_recognition_rejected(chain):
    """A recognition whose validity window has passed is rejected."""
    root = chain["root"]
    issuer = chain["issuer"]
    expired = _sign(
        root,
        {
            "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
            "id": "urn:uuid:expired-recognition",
            "type": [VC_TYPE, RECOGNIZED_ISSUER_TYPE],
            "issuer": root.did,
            "validFrom": "2020-01-01T00:00:00Z",
            "validUntil": "2020-01-02T00:00:00Z",
            "credentialSubject": {
                "id": issuer.did,
                "recognizedActions": [ACTION_ISSUE_AGENT_IDENTITY],
                "recognizedIn": root.did,
            },
        },
    )
    result = verify_identity_chain(chain["identity"], expired, trusted_root=root.did)
    assert not result.ok
    assert result.reason == "recognized_issuer_expired"


def test_root_credential_self_consistency_checked(chain):
    """A root credential whose subject is not the pinned root is rejected."""
    forged_root_cred = copy.deepcopy(chain["root_cred"])
    forged_root_cred["credentialSubject"]["id"] = "did:key:zNotTheRoot"
    result = verify_identity_chain(
        chain["identity"],
        chain["recognition"],
        trusted_root=chain["root"].did,
        root_credential=forged_root_cred,
    )
    assert not result.ok
    # Editing the subject also breaks the self-issued proof; either reason is a
    # correct rejection of a non-self-issued root.
    assert result.reason in ("root_proof_invalid", "root_not_self_issued")


# ---------------------------------------------------------------------------
# TrustRegistry wiring
# ---------------------------------------------------------------------------


class _FakeRegistry:
    def __init__(self):
        self.trusted = []

    def trust(self, did):
        self.trusted.append(did)


def test_register_recognized_issuer(chain):
    reg = _FakeRegistry()
    did = register_recognized_issuer(reg, chain["recognition"])
    assert did == chain["issuer"].did
    assert chain["issuer"].did in reg.trusted
