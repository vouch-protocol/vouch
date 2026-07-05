"""Tests for Proof of Deliberation (two-phase deliberated execution)."""

from datetime import datetime, timedelta, timezone

import pytest

from vouch import Signer, generate_identity
from vouch.deliberation import (
    CLASS_IRREVERSIBLE_FINANCIAL,
    CLASS_REVERSIBLE,
    EXECUTE_TYPE,
    INTENT_TYPE,
    REASON_INTENT_MISMATCH,
    REASON_INVALID_PROOF,
    REASON_UNAUTHORIZED_EXECUTOR,
    REASON_VETOED,
    REASON_WINDOW_NOT_ELAPSED,
    VETO_TYPE,
    DeliberationError,
    action_digest,
    check_execution,
    commit_intent,
    execute,
    requires_window,
    veto_intent,
    verify_execution,
    verify_intent,
)

WIRE = {"action": "transfer_funds", "target": "acct:vendor-1", "resource": "usd:5000"}


def _identity(domain="agent.example.com"):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def _committed(agent, controller_did, opened, min_seconds=900):
    return commit_intent(
        agent,
        intent=WIRE,
        reversibility_class=CLASS_IRREVERSIBLE_FINANCIAL,
        min_seconds=min_seconds,
        veto_authorities=[controller_did],
        opens_at=opened,
    )


class TestClasses:
    def test_reversible_needs_no_window(self):
        assert requires_window(CLASS_REVERSIBLE) is False
        assert requires_window(CLASS_IRREVERSIBLE_FINANCIAL) is True

    def test_irreversible_requires_positive_window(self):
        _, agent = _identity()
        with pytest.raises(DeliberationError):
            commit_intent(
                agent, intent=WIRE, reversibility_class=CLASS_IRREVERSIBLE_FINANCIAL, min_seconds=0
            )

    def test_unknown_class_rejected(self):
        _, agent = _identity()
        with pytest.raises(DeliberationError):
            commit_intent(agent, intent=WIRE, reversibility_class="whatever", min_seconds=10)

    def test_intent_needs_action_target(self):
        _, agent = _identity()
        with pytest.raises(DeliberationError):
            commit_intent(agent, intent={"action": "x"}, reversibility_class=CLASS_REVERSIBLE)


class TestIntentAndVeto:
    def test_commit_and_verify_intent(self):
        akp, agent = _identity()
        _, ctrl = _identity("controller.example.com")
        intent = _committed(agent, ctrl.get_did(), datetime.now(timezone.utc))
        assert INTENT_TYPE in intent["type"]
        ok, subject = verify_intent(intent, akp.public_key_jwk)
        assert ok and subject["actionDigest"]["digest"] == action_digest(WIRE)

    def test_veto_binds_to_intent(self):
        _, agent = _identity()
        _, ctrl = _identity("controller.example.com")
        intent = _committed(agent, ctrl.get_did(), datetime.now(timezone.utc))
        veto = veto_intent(ctrl, intent_credential=intent, reason="no")
        assert VETO_TYPE in veto["type"]
        assert veto["credentialSubject"]["intentDigest"]["digest"] == action_digest(WIRE)


class TestExecution:
    def test_clean_window_accepted(self):
        akp, agent = _identity()
        _, ctrl = _identity("controller.example.com")
        opened = datetime.now(timezone.utc)
        intent = _committed(agent, ctrl.get_did(), opened)
        ex = execute(agent, intent_credential=intent, closed_at=opened + timedelta(seconds=901))
        assert EXECUTE_TYPE in ex["type"]
        assert check_execution(ex, intent, akp.public_key_jwk) is None
        ok, subject = verify_execution(ex, intent, akp.public_key_jwk)
        assert ok and subject["intent"] == WIRE

    def test_execute_too_early_rejected(self):
        akp, agent = _identity()
        _, ctrl = _identity("controller.example.com")
        opened = datetime.now(timezone.utc)
        intent = _committed(agent, ctrl.get_did(), opened)
        ex = execute(agent, intent_credential=intent, closed_at=opened + timedelta(seconds=60))
        assert check_execution(ex, intent, akp.public_key_jwk) == REASON_WINDOW_NOT_ELAPSED

    def test_veto_blocks_even_after_window(self):
        akp, agent = _identity()
        ckp, ctrl = _identity("controller.example.com")
        opened = datetime.now(timezone.utc)
        intent = _committed(agent, ctrl.get_did(), opened)
        veto = veto_intent(ctrl, intent_credential=intent, reason="over threshold")
        ex = execute(agent, intent_credential=intent, closed_at=opened + timedelta(seconds=1200))
        reason = check_execution(
            ex,
            intent,
            akp.public_key_jwk,
            vetoes=[veto],
            veto_public_keys={ctrl.get_did(): ckp.public_key_jwk},
        )
        assert reason == REASON_VETOED

    def test_veto_from_unlisted_authority_ignored(self):
        akp, agent = _identity()
        _, ctrl = _identity("controller.example.com")
        rkp, rogue = _identity("rogue.example.com")
        opened = datetime.now(timezone.utc)
        intent = _committed(agent, ctrl.get_did(), opened)  # only ctrl may veto
        rogue_veto = veto_intent(rogue, intent_credential=intent, reason="I object")
        ex = execute(agent, intent_credential=intent, closed_at=opened + timedelta(seconds=1000))
        reason = check_execution(
            ex,
            intent,
            akp.public_key_jwk,
            vetoes=[rogue_veto],
            veto_public_keys={rogue.get_did(): rkp.public_key_jwk},
        )
        assert reason is None  # rogue is not in vetoAuthorities

    def test_unauthorized_executor_rejected(self):
        akp, agent = _identity()
        _, ctrl = _identity("controller.example.com")
        bkp, bob = _identity("bob.example.com")
        opened = datetime.now(timezone.utc)
        intent = _committed(agent, ctrl.get_did(), opened)
        # Bob (not the intent issuer) signs an execute for the same intent.
        ex = execute(bob, intent_credential=intent, closed_at=opened + timedelta(seconds=1000))
        assert check_execution(ex, intent, bkp.public_key_jwk) == REASON_UNAUTHORIZED_EXECUTOR

    def test_tampered_action_rejected(self):
        akp, agent = _identity()
        _, ctrl = _identity("controller.example.com")
        opened = datetime.now(timezone.utc)
        intent = _committed(agent, ctrl.get_did(), opened)
        ex = execute(agent, intent_credential=intent, closed_at=opened + timedelta(seconds=1000))
        # Re-sign an execute whose embedded intent was changed to a bigger amount.
        ex["credentialSubject"]["intent"] = {
            "action": "transfer_funds",
            "target": "acct:vendor-1",
            "resource": "usd:999999",
        }
        from vouch import data_integrity  # noqa: PLC0415

        ex["proof"] = data_integrity.build_proof(
            ex, agent._raw_priv, agent.verification_method_id()
        )
        assert check_execution(ex, intent, akp.public_key_jwk) == REASON_INTENT_MISMATCH

    def test_wrong_executor_key_fails_proof(self):
        akp, agent = _identity()
        okp, _ = _identity("other.example.com")
        _, ctrl = _identity("controller.example.com")
        opened = datetime.now(timezone.utc)
        intent = _committed(agent, ctrl.get_did(), opened)
        ex = execute(agent, intent_credential=intent, closed_at=opened + timedelta(seconds=1000))
        assert check_execution(ex, intent, okp.public_key_jwk) == REASON_INVALID_PROOF
