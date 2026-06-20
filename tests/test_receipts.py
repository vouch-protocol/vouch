"""Tests for reputation receipts and normalization (Phase 1)."""

from vouch import Signer, generate_identity
from vouch.accountability import attest_outcome, commit_outcome
from vouch.receipts import (
    COMPLIANCE,
    PERFORMANCE,
    RELIABILITY,
    SATISFACTION,
    build_penalty_receipt,
    build_state_receipt,
    normalize_receipt,
    receipt_subject,
    verify_penalty_receipt,
    verify_state_receipt,
)

AGENT = "did:web:agent.example.com"
SETTLEMENT = {"method": "oracle", "resolutionCriteria": "x"}


def _id(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def test_state_receipt_success_and_sla():
    kp, rp = _id("relying-party.example.com")
    r = build_state_receipt(
        rp, agent=AGENT, interaction_id="s1", action="charge", result="success", sla_met=True
    )
    ok, subj = verify_state_receipt(r, kp.public_key_jwk)
    assert ok is True
    assert subj["result"] == "success"
    assert receipt_subject(r) == AGENT

    sigs = {(s.dimension, s.value) for s in normalize_receipt(r)}
    assert (RELIABILITY, 1.0) in sigs
    assert (PERFORMANCE, 1.0) in sigs


def test_state_receipt_failure():
    _, rp = _id("relying-party.example.com")
    r = build_state_receipt(
        rp, agent=AGENT, interaction_id="s1", action="charge", result="failure", sla_met=False
    )
    sigs = {(s.dimension, s.value) for s in normalize_receipt(r)}
    assert (RELIABILITY, -1.0) in sigs
    assert (PERFORMANCE, -1.0) in sigs


def test_state_receipt_wrong_key_fails():
    _, rp = _id("relying-party.example.com")
    other, _ = _id("other.example.com")
    r = build_state_receipt(rp, agent=AGENT, interaction_id="s1", action="a", result="success")
    ok, _ = verify_state_receipt(r, other.public_key_jwk)
    assert ok is False


def test_penalty_receipt():
    kp, authority = _id("validator.example.com")
    r = build_penalty_receipt(
        authority, agent=AGENT, interaction_id="s1", kind="policy-violation", severity=0.8
    )
    ok, subj = verify_penalty_receipt(r, kp.public_key_jwk)
    assert ok is True
    assert subj["kind"] == "policy-violation"

    sigs = normalize_receipt(r)
    assert len(sigs) == 1
    assert sigs[0].dimension == COMPLIANCE
    assert sigs[0].value == -0.8


def test_outcome_attestation_normalizes_positive():
    kp, agent = _id("agent.example.com")
    commitment, secret = commit_outcome(agent, claim={"x": 1}, settlement=SETTLEMENT, private=True)
    att = attest_outcome(
        agent, commitment=commitment, outcome={"result": "x"}, secret=secret, matches=True
    )
    sigs = normalize_receipt(att)
    assert len(sigs) == 1
    assert sigs[0].dimension == RELIABILITY
    assert sigs[0].value == 1.0


def test_outcome_attestation_normalizes_negative():
    _, agent = _id("agent.example.com")
    commitment, secret = commit_outcome(agent, claim={"x": 1}, settlement=SETTLEMENT, private=True)
    att = attest_outcome(
        agent, commitment=commitment, outcome={"result": "y"}, secret=secret, matches=False
    )
    sigs = normalize_receipt(att)
    assert sigs[0].value == -1.0


def test_review_normalizes():
    review = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://vouch-protocol.com/contexts/v1",
        ],
        "type": ["VerifiableCredential", "ReviewCredential"],
        "id": "urn:uuid:1",
        "issuer": "did:web:rater.example.com",
        "validFrom": "2026-06-17T00:00:00Z",
        "credentialSubject": {
            "id": AGENT,
            "rater": "did:web:rater.example.com",
            "interactionId": "s1",
            "ratings": {"performance": 5, "satisfaction": 1, "vibe": 3},
        },
    }
    bydim = {(s.dimension, s.value) for s in normalize_receipt(review)}
    assert (PERFORMANCE, 1.0) in bydim
    assert (SATISFACTION, -1.0) in bydim
    assert (SATISFACTION, 0.0) in bydim  # unknown "vibe" maps to satisfaction


def test_unknown_type_yields_no_signal():
    cred = {"type": ["VerifiableCredential", "VouchCredential"], "credentialSubject": {"id": AGENT}}
    assert normalize_receipt(cred) == []
