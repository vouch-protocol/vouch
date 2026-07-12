"""Tests for Reasoned Action Proofs (justification bound to the action)."""

from datetime import datetime, timedelta, timezone

import pytest

from vouch import Signer, generate_identity
from vouch.reasoning import (
    ESCROW_RECEIPT_TYPE,
    REASON_ESCROW_AFTER_EXECUTION,
    REASON_ESCROW_DIGEST_MISMATCH,
    REASON_EVIDENCE_HASH_MISMATCH,
    REASON_EVIDENCE_UNRESOLVED,
    REASON_INVALID_PROOF,
    REASON_JUSTIFICATION_DIGEST_MISMATCH,
    REASON_MISSING_ESCROW,
    REASON_UNANCHORED_CLAIM,
    REASONED_ACTION_TYPE,
    LocalEscrow,
    ReasonedActionError,
    artifact_digest,
    build_escrow_receipt,
    build_justification,
    check_reasoned_action,
    evidence_anchor,
    justification_digest,
    sign_reasoned_action,
    verify_escrow_receipt,
    verify_justification,
    verify_reasoned_action,
)


def _identity(domain: str = "agent.example.com"):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


USER_MSG = {"from": "did:web:alice.example", "text": "clean up /tmp"}
INTENT = {"action": "delete", "target": "/tmp/cache", "resource": "/tmp/cache/*"}


def _justification():
    return build_justification(
        INTENT,
        [
            evidence_anchor(
                "user asked", ref="msg:1", evidence=USER_MSG, anchor_type="user_message"
            ),
        ],
        commitment_level=3,
    )


def _resolver():
    return {"msg:1": USER_MSG}.get


class TestEvidenceAnchor:
    def test_hash_from_evidence(self):
        a = evidence_anchor("c", ref="r", evidence=USER_MSG)
        assert a["evidenceHash"] == artifact_digest(USER_MSG)
        assert a["claim"] == "c" and a["ref"] == "r"

    def test_explicit_hash(self):
        h = artifact_digest(USER_MSG)
        a = evidence_anchor("c", ref="r", evidence_hash=h)
        assert a["evidenceHash"] == h

    def test_requires_evidence_or_hash(self):
        with pytest.raises(ReasonedActionError):
            evidence_anchor("c", ref="r")

    def test_artifact_digest_str_and_dict_differ(self):
        assert artifact_digest("hello") != artifact_digest({"x": "hello"})


class TestJustification:
    def test_digest_is_deterministic(self):
        j1, j2 = _justification(), _justification()
        assert justification_digest(j1) == justification_digest(j2)

    def test_digest_changes_with_intent(self):
        j = _justification()
        other = build_justification(
            {"action": "delete", "target": "/etc/passwd", "resource": "/etc/*"},
            j["evidenceAnchors"],
        )
        assert justification_digest(j) != justification_digest(other)

    def test_empty_anchors_rejected(self):
        with pytest.raises(ReasonedActionError):
            build_justification(INTENT, [])

    def test_intent_must_have_action_target(self):
        with pytest.raises(ReasonedActionError):
            build_justification({"action": "delete"}, [evidence_anchor("c", ref="r", evidence={})])


class TestEscrowReceipt:
    def test_build_and_verify(self):
        kp, escrow_signer = _identity("escrow.example.com")
        digest = justification_digest(_justification())
        receipt = build_escrow_receipt(
            escrow_signer, agent_did="did:web:agent", committed_digest=digest
        )
        assert ESCROW_RECEIPT_TYPE in receipt["type"]
        ok, subject = verify_escrow_receipt(receipt, kp.public_key_jwk)
        assert ok is True
        assert subject["committedDigest"] == digest

    def test_wrong_key_fails(self):
        _, escrow_signer = _identity("escrow.example.com")
        other_kp, _ = _identity("other.example.com")
        receipt = build_escrow_receipt(escrow_signer, agent_did="a", committed_digest="ux")
        ok, _ = verify_escrow_receipt(receipt, other_kp.public_key_jwk)
        assert ok is False

    def test_local_escrow_wrapper(self):
        kp, escrow_signer = _identity("escrow.example.com")
        escrow = LocalEscrow(escrow_signer)
        receipt = escrow.deposit(agent_did="did:web:agent", committed_digest="uabc")
        ok, subject = verify_escrow_receipt(receipt, kp.public_key_jwk)
        assert ok and subject["committedDigest"] == "uabc"


class TestReasonedAction:
    def test_sign_and_verify_full_flow(self):
        agent_kp, agent = _identity("agent.example.com")
        escrow_kp, escrow_signer = _identity("escrow.example.com")
        just = _justification()
        committed = datetime.now(timezone.utc)
        receipt = build_escrow_receipt(
            escrow_signer,
            agent_did=agent.get_did(),
            committed_digest=justification_digest(just),
            deposited_at=committed,
        )
        cred = sign_reasoned_action(
            agent,
            intent=INTENT,
            justification=just,
            escrow_receipt=receipt,
            valid_from=committed + timedelta(seconds=1),
        )
        assert REASONED_ACTION_TYPE in cred["type"]
        assert (
            check_reasoned_action(
                cred,
                agent_kp.public_key_jwk,
                escrow_public_key=escrow_kp.public_key_jwk,
                require_escrow=True,
            )
            is None
        )
        ok, subject = verify_reasoned_action(
            cred,
            agent_kp.public_key_jwk,
            escrow_public_key=escrow_kp.public_key_jwk,
        )
        assert ok and subject["intent"] == INTENT

    def test_justification_resolves(self):
        agent_kp, agent = _identity()
        just = _justification()
        cred = sign_reasoned_action(agent, intent=INTENT, justification=just)
        _, subject = verify_reasoned_action(cred, agent_kp.public_key_jwk)
        ok, reason = verify_justification(just, subject, resolver=_resolver())
        assert ok is True and reason is None

    def test_tampered_credential_fails(self):
        agent_kp, agent = _identity()
        cred = sign_reasoned_action(agent, intent=INTENT, justification=_justification())
        cred["credentialSubject"]["intent"]["target"] = "/etc/passwd"
        assert check_reasoned_action(cred, agent_kp.public_key_jwk) == REASON_INVALID_PROOF

    def test_require_escrow_without_receipt(self):
        agent_kp, agent = _identity()
        cred = sign_reasoned_action(agent, intent=INTENT, justification=_justification())
        assert (
            check_reasoned_action(cred, agent_kp.public_key_jwk, require_escrow=True)
            == REASON_MISSING_ESCROW
        )

    def test_escrow_after_execution_rejected(self):
        agent_kp, agent = _identity("agent.example.com")
        escrow_kp, escrow_signer = _identity("escrow.example.com")
        just = _justification()
        executed = datetime.now(timezone.utc)
        # Deposit AFTER execution: temporal ordering violated.
        receipt = build_escrow_receipt(
            escrow_signer,
            agent_did=agent.get_did(),
            committed_digest=justification_digest(just),
            deposited_at=executed + timedelta(seconds=5),
        )
        cred = sign_reasoned_action(
            agent,
            intent=INTENT,
            justification=just,
            escrow_receipt=receipt,
            valid_from=executed,
        )
        assert (
            check_reasoned_action(
                cred,
                agent_kp.public_key_jwk,
                escrow_public_key=escrow_kp.public_key_jwk,
            )
            == REASON_ESCROW_AFTER_EXECUTION
        )

    def test_escrow_digest_mismatch_rejected(self):
        agent_kp, agent = _identity("agent.example.com")
        escrow_kp, escrow_signer = _identity("escrow.example.com")
        just = _justification()
        receipt = build_escrow_receipt(
            escrow_signer,
            agent_did=agent.get_did(),
            committed_digest="udifferent",
        )
        cred = sign_reasoned_action(
            agent, intent=INTENT, justification=just, escrow_receipt=receipt
        )
        assert (
            check_reasoned_action(
                cred,
                agent_kp.public_key_jwk,
                escrow_public_key=escrow_kp.public_key_jwk,
            )
            == REASON_ESCROW_DIGEST_MISMATCH
        )


class TestAttacksDefeated:
    def test_fabricated_evidence_rejected(self):
        agent_kp, agent = _identity()
        just = _justification()
        cred = sign_reasoned_action(agent, intent=INTENT, justification=just)
        _, subject = verify_reasoned_action(cred, agent_kp.public_key_jwk)
        # A justification whose anchor points at a non-resolvable artifact.
        forged = build_justification(
            INTENT, [evidence_anchor("cfo approved", ref="call:none", evidence={"fake": True})]
        )
        ok, reason = verify_justification(forged, subject, resolver=_resolver())
        # Fails first on digest mismatch (it is not what was committed).
        assert ok is False and reason == REASON_JUSTIFICATION_DIGEST_MISMATCH

    def test_unresolvable_evidence_on_matching_digest(self):
        # Commit a justification whose evidence cannot later be resolved.
        agent_kp, agent = _identity()
        bad = build_justification(
            INTENT, [evidence_anchor("ghost", ref="ghost:1", evidence={"x": 1})]
        )
        cred = sign_reasoned_action(agent, intent=INTENT, justification=bad)
        _, subject = verify_reasoned_action(cred, agent_kp.public_key_jwk)
        ok, reason = verify_justification(bad, subject, resolver={}.get)
        assert ok is False and reason == REASON_EVIDENCE_UNRESOLVED

    def test_evidence_hash_mismatch(self):
        agent_kp, agent = _identity()
        just = _justification()
        cred = sign_reasoned_action(agent, intent=INTENT, justification=just)
        _, subject = verify_reasoned_action(cred, agent_kp.public_key_jwk)
        # Resolver returns a DIFFERENT artifact than the one hashed at commit.
        ok, reason = verify_justification(just, subject, resolver={"msg:1": {"tampered": True}}.get)
        assert ok is False and reason == REASON_EVIDENCE_HASH_MISMATCH

    def test_post_hoc_rewrite_rejected(self):
        agent_kp, agent = _identity()
        just = _justification()
        cred = sign_reasoned_action(agent, intent=INTENT, justification=just)
        _, subject = verify_reasoned_action(cred, agent_kp.public_key_jwk)
        rewritten = build_justification(
            {"action": "delete", "target": "/etc/passwd", "resource": "/etc/*"},
            just["evidenceAnchors"],
        )
        ok, reason = verify_justification(rewritten, subject, resolver=_resolver())
        assert ok is False and reason == REASON_JUSTIFICATION_DIGEST_MISMATCH
