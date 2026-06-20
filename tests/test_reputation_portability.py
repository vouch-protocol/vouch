"""Tests for privacy-preserving reputation threshold proofs (Phase 5)."""

import json

from vouch import Signer, generate_identity
from vouch.reputation_aggregate import ReputationScore
from vouch.reputation_portability import build_reputation_proof, verify_reputation_proof

AGENT = "did:web:agent.example.com"


def _svc():
    kp = generate_identity(domain="registry.example.com")
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def _score():
    return ReputationScore(
        version="1.0", dimensions={"reliability": 92.0}, composite=83.0, support={}, count=5
    )


def test_proof_asserts_predicate_without_revealing_score():
    kp, svc = _svc()
    proof = build_reputation_proof(
        svc,
        AGENT,
        _score(),
        predicates=[
            {"path": "composite", "op": ">=", "value": 75},
            {"path": "dimensions.reliability", "op": ">=", "value": 90},
        ],
    )
    ok, assertions = verify_reputation_proof(proof, kp.public_key_jwk)
    assert ok is True
    assert all(a["satisfied"] for a in assertions)

    # The actual score and dimension are not disclosed, only the thresholds.
    dumped = json.dumps(proof["credentialSubject"])
    assert "83" not in dumped
    assert "92" not in dumped


def test_require_satisfied_predicate_passes():
    kp, svc = _svc()
    proof = build_reputation_proof(
        svc, AGENT, _score(), predicates=[{"path": "composite", "op": ">=", "value": 75}]
    )
    ok, _ = verify_reputation_proof(
        proof, kp.public_key_jwk, require=[{"path": "composite", "op": ">=", "value": 75}]
    )
    assert ok is True


def test_require_unsatisfied_predicate_fails():
    kp, svc = _svc()
    # composite is 83, so ">= 90" is asserted but not satisfied
    proof = build_reputation_proof(
        svc, AGENT, _score(), predicates=[{"path": "composite", "op": ">=", "value": 90}]
    )
    ok, _ = verify_reputation_proof(
        proof, kp.public_key_jwk, require=[{"path": "composite", "op": ">=", "value": 90}]
    )
    assert ok is False


def test_require_absent_predicate_fails():
    kp, svc = _svc()
    proof = build_reputation_proof(
        svc, AGENT, _score(), predicates=[{"path": "composite", "op": ">=", "value": 75}]
    )
    ok, _ = verify_reputation_proof(
        proof,
        kp.public_key_jwk,
        require=[{"path": "dimensions.compliance", "op": ">=", "value": 50}],
    )
    assert ok is False


def test_audience_binding():
    kp, svc = _svc()
    proof = build_reputation_proof(
        svc,
        AGENT,
        _score(),
        predicates=[{"path": "composite", "op": ">=", "value": 75}],
        audience="did:web:verifier-a.example.com",
    )
    ok_right, _ = verify_reputation_proof(
        proof, kp.public_key_jwk, audience="did:web:verifier-a.example.com"
    )
    ok_wrong, _ = verify_reputation_proof(
        proof, kp.public_key_jwk, audience="did:web:verifier-b.example.com"
    )
    assert ok_right is True
    assert ok_wrong is False


def test_tampered_proof_fails():
    kp, svc = _svc()
    proof = build_reputation_proof(
        svc, AGENT, _score(), predicates=[{"path": "composite", "op": ">=", "value": 90}]
    )
    proof["credentialSubject"]["assertions"][0]["satisfied"] = True  # flip after signing
    ok, _ = verify_reputation_proof(proof, kp.public_key_jwk)
    assert ok is False
