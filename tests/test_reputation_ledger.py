"""Tests for the reputation ledger and signed snapshot (Phase 3a)."""

import pytest

from vouch import Signer, generate_identity
from vouch.jcs import canonicalize
from vouch.merkle import verify_inclusion
from vouch.receipts import RELIABILITY, build_state_receipt
from vouch.reputation_ledger import (
    REPUTATION_CREDENTIAL_TYPE,
    LedgerError,
    ReputationLedger,
    verify_reputation_credential,
)

AGENT = "did:web:agent.example.com"


def _id(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def _ledger_with(*signers_kp):
    keymap = {s.get_did(): kp.public_key_jwk for kp, s in signers_kp}
    return ReputationLedger(resolver=lambda did: keymap.get(did)), keymap


def test_append_and_score():
    rp_kp, rp = _id("rp.example.com")
    ledger, _ = _ledger_with((rp_kp, rp))
    for i in (1, 2):
        ledger.append(
            build_state_receipt(
                rp, agent=AGENT, interaction_id=str(i), action="x", result="success"
            )
        )
    assert ledger.count(AGENT) == 2
    assert ledger.score(AGENT).dimensions[RELIABILITY] == 100.0


def test_append_rejects_unknown_issuer():
    rp_kp, rp = _id("rp.example.com")
    ledger = ReputationLedger(resolver=lambda did: None)  # resolves nothing
    with pytest.raises(LedgerError):
        ledger.append(
            build_state_receipt(rp, agent=AGENT, interaction_id="1", action="x", result="success")
        )


def test_append_rejects_tampered_receipt():
    rp_kp, rp = _id("rp.example.com")
    ledger, _ = _ledger_with((rp_kp, rp))
    r = build_state_receipt(rp, agent=AGENT, interaction_id="1", action="x", result="failure")
    r["credentialSubject"]["result"] = "success"  # flip after signing
    with pytest.raises(LedgerError):
        ledger.append(r)


def test_root_and_inclusion_proof():
    rp_kp, rp = _id("rp.example.com")
    ledger, _ = _ledger_with((rp_kp, rp))
    receipts = [
        build_state_receipt(rp, agent=AGENT, interaction_id=str(i), action="x", result="success")
        for i in range(3)
    ]
    for r in receipts:
        ledger.append(r)

    assert ledger.root(AGENT) is not None
    tree = ledger.merkle(AGENT)
    leaf = canonicalize(receipts[1])
    assert verify_inclusion(leaf=leaf, proof=tree.proof(1), root=tree.root()) is True


def test_snapshot_signs_and_verifies():
    rp_kp, rp = _id("rp.example.com")
    svc_kp, svc = _id("registry.example.com")
    ledger, _ = _ledger_with((rp_kp, rp))
    ledger.append(
        build_state_receipt(rp, agent=AGENT, interaction_id="1", action="x", result="success")
    )

    snap = ledger.snapshot(svc, AGENT)
    assert REPUTATION_CREDENTIAL_TYPE in snap["type"]
    assert snap["issuer"] == svc.get_did()

    ok, subject = verify_reputation_credential(snap, svc_kp.public_key_jwk)
    assert ok is True
    assert subject["score"]["dimensions"][RELIABILITY] == 100.0
    assert subject["receiptCount"] == 1
    assert subject["evidenceRoot"] == ledger.root(AGENT)


def test_snapshot_tamper_fails():
    rp_kp, rp = _id("rp.example.com")
    svc_kp, svc = _id("registry.example.com")
    ledger, _ = _ledger_with((rp_kp, rp))
    ledger.append(
        build_state_receipt(rp, agent=AGENT, interaction_id="1", action="x", result="success")
    )
    snap = ledger.snapshot(svc, AGENT)
    snap["credentialSubject"]["score"]["composite"] = 99.0  # inflate after signing
    ok, _ = verify_reputation_credential(snap, svc_kp.public_key_jwk)
    assert ok is False
