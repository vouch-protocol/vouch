"""
Security regression tests for the delegation parentProofValue binding:
  1. The builder stores the FULL parent proofValue (no 64-char truncation).
  2. The verifier rejects a delegation link with a missing/empty
     parentProofValue (a forged or spliced chain).
"""
from jwcrypto import jwk

from vouch.signer import Signer
from vouch.verifier import Verifier


def _new_signer(did: str) -> Signer:
    key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    return Signer(private_key=key.export_private(), did=did)


def _delegated_pair():
    parent = _new_signer("did:web:alice.example.com")
    child = _new_signer("did:web:assistant.example.com")
    parent_cred = parent.sign_credential(
        intent={"action": "read", "target": "users",
                "resource": "https://api.example.com/v1/users"}
    )
    child_cred = child.sign_credential(
        intent={"action": "read", "target": "users",
                "resource": "https://api.example.com/v1/users/42"},
        parent_credential=parent_cred,
    )
    return parent_cred, child_cred


def test_delegation_link_stores_full_parent_proof_value():
    parent_cred, child_cred = _delegated_pair()
    link = child_cred["credentialSubject"]["delegationChain"][0]
    full = parent_cred["proof"]["proofValue"]
    assert link["parentProofValue"] == full
    assert len(link["parentProofValue"]) > 64  # not truncated


def test_verify_rejects_link_missing_parent_proof_value():
    _, child_cred = _delegated_pair()
    # Structural-mode verification (no key) isolates the chain check; this is
    # the path an attacker who re-signs a forged chain with their own key hits.
    del child_cred["credentialSubject"]["delegationChain"][0]["parentProofValue"]
    valid, _ = Verifier.verify_credential(child_cred)
    assert valid is False


def test_verify_accepts_well_formed_delegation():
    _, child_cred = _delegated_pair()
    valid, _ = Verifier.verify_credential(child_cred)
    assert valid is True
