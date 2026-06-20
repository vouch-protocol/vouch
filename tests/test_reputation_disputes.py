"""Tests for reputation disputes and ledger exclusion (Phase 5)."""

import pytest

from vouch import Signer, generate_identity
from vouch.receipts import RELIABILITY, build_state_receipt
from vouch.reputation_disputes import (
    DISPUTE_RESOLUTION_TYPE,
    DISPUTE_TYPE,
    build_dispute,
    build_dispute_resolution,
    verify_dispute,
    verify_dispute_resolution,
)
from vouch.reputation_ledger import LedgerError, ReputationLedger

AGENT = "did:web:agent.example.com"


def _id(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def test_build_and_verify_dispute_and_resolution():
    _, rp = _id("rp.example.com")
    ch_kp, challenger = _id("challenger.example.com")
    ar_kp, arbiter = _id("arbiter.example.com")

    receipt = build_state_receipt(rp, agent=AGENT, interaction_id="1", action="x", result="success")
    dispute = build_dispute(challenger, receipt=receipt, reason="receipt was fabricated")
    assert DISPUTE_TYPE in dispute["type"]
    ok, dsub = verify_dispute(dispute, ch_kp.public_key_jwk)
    assert ok is True
    assert dsub["receipt"]["id"] == receipt["id"]

    res = build_dispute_resolution(arbiter, dispute=dispute, upheld=True, rationale="confirmed")
    assert DISPUTE_RESOLUTION_TYPE in res["type"]
    ok, rsub = verify_dispute_resolution(res, ar_kp.public_key_jwk)
    assert ok is True
    assert rsub["upheld"] is True


def test_upheld_resolution_excludes_receipt():
    rp_kp, rp = _id("rp.example.com")
    ch_kp, challenger = _id("challenger.example.com")
    ar_kp, arbiter = _id("arbiter.example.com")
    keymap = {rp.get_did(): rp_kp.public_key_jwk}
    ledger = ReputationLedger(resolver=lambda d: keymap.get(d))

    receipt = build_state_receipt(rp, agent=AGENT, interaction_id="1", action="x", result="success")
    ledger.append(receipt)
    assert ledger.score(AGENT).dimensions[RELIABILITY] == 100.0

    dispute = build_dispute(challenger, receipt=receipt, reason="fabricated")
    res = build_dispute_resolution(arbiter, dispute=dispute, upheld=True)
    excluded = ledger.apply_resolution(res, ar_kp.public_key_jwk)
    assert excluded is True

    # the receipt no longer counts
    assert ledger.count(AGENT) == 0
    assert RELIABILITY not in ledger.score(AGENT).dimensions


def test_dismissed_resolution_keeps_receipt():
    rp_kp, rp = _id("rp.example.com")
    _, challenger = _id("challenger.example.com")
    ar_kp, arbiter = _id("arbiter.example.com")
    keymap = {rp.get_did(): rp_kp.public_key_jwk}
    ledger = ReputationLedger(resolver=lambda d: keymap.get(d))

    receipt = build_state_receipt(rp, agent=AGENT, interaction_id="1", action="x", result="success")
    ledger.append(receipt)
    dispute = build_dispute(challenger, receipt=receipt, reason="nope")
    res = build_dispute_resolution(arbiter, dispute=dispute, upheld=False)
    assert ledger.apply_resolution(res, ar_kp.public_key_jwk) is False
    assert ledger.count(AGENT) == 1


def test_resolution_wrong_arbiter_key_rejected():
    rp_kp, rp = _id("rp.example.com")
    _, challenger = _id("challenger.example.com")
    _, arbiter = _id("arbiter.example.com")
    impostor_kp, _ = _id("impostor.example.com")
    keymap = {rp.get_did(): rp_kp.public_key_jwk}
    ledger = ReputationLedger(resolver=lambda d: keymap.get(d))

    receipt = build_state_receipt(rp, agent=AGENT, interaction_id="1", action="x", result="success")
    ledger.append(receipt)
    dispute = build_dispute(challenger, receipt=receipt, reason="x")
    res = build_dispute_resolution(arbiter, dispute=dispute, upheld=True)
    with pytest.raises(LedgerError):
        ledger.apply_resolution(res, impostor_kp.public_key_jwk)
