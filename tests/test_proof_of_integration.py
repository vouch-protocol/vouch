"""Tests for the proof-of-integration recognition primitive (PAD-072)."""

import pytest

from vouch import generate_identity
from vouch.proof_of_integration import (
    CHALLENGE_TYPE,
    RESPONSE_TYPE,
    ProofOfIntegrationError,
    answer_integration_challenge,
    build_integration_challenge,
    proof_of_integration_block,
    verify_integration_response,
)


def _identity(domain: str = "agent.example.com"):
    return generate_identity(domain=domain)


SURFACE = "https://agent.example.com/vouch/challenge"
CAPABILITY = "sign-vouch-credential"
ARTIFACT = {"action": "read", "target": "inbox", "resource": "https://mail/api/inbox"}


class TestChallenge:
    def test_build_challenge(self):
        ch = build_integration_challenge(SURFACE, CAPABILITY)
        assert ch["surface"] == SURFACE
        assert ch["capability"] == CAPABILITY
        assert isinstance(ch["nonce"], str)
        assert len(ch["nonce"]) == 64  # 32 bytes hex

    def test_default_nonce_is_fresh(self):
        a = build_integration_challenge(SURFACE, CAPABILITY)
        b = build_integration_challenge(SURFACE, CAPABILITY)
        assert a["nonce"] != b["nonce"]

    def test_explicit_nonce_preserved(self):
        ch = build_integration_challenge(SURFACE, CAPABILITY, nonce="deadbeef")
        assert ch["nonce"] == "deadbeef"

    def test_empty_surface_rejected(self):
        with pytest.raises(ProofOfIntegrationError):
            build_integration_challenge("", CAPABILITY)

    def test_empty_capability_rejected(self):
        with pytest.raises(ProofOfIntegrationError):
            build_integration_challenge(SURFACE, "")


class TestResponseRoundtrip:
    def test_valid_answer_verifies(self):
        kp = _identity()
        ch = build_integration_challenge(SURFACE, CAPABILITY)
        resp = answer_integration_challenge(ch, private_key=kp.private_key_jwk, did=kp.did)

        assert RESPONSE_TYPE in resp["type"]
        assert resp["issuer"] == kp.did
        assert resp["credentialSubject"]["id"] == kp.did
        assert resp["credentialSubject"]["nonce"] == ch["nonce"]

        ok, details = verify_integration_response(resp, ch, public_key=kp.public_key_jwk)
        assert ok is True
        assert details["nonce"] == ch["nonce"]
        assert details["did"] == kp.did
        assert details["surface"] == SURFACE
        assert details["capability"] == CAPABILITY

    def test_tampered_nonce_rejected(self):
        kp = _identity()
        ch = build_integration_challenge(SURFACE, CAPABILITY)
        resp = answer_integration_challenge(ch, private_key=kp.private_key_jwk, did=kp.did)
        other = build_integration_challenge(SURFACE, CAPABILITY)
        # The response answers `ch`, but is checked against a different challenge.
        ok, _ = verify_integration_response(resp, other, public_key=kp.public_key_jwk)
        assert ok is False

    def test_wrong_public_key_rejected(self):
        kp = _identity()
        other = _identity("other.example.com")
        ch = build_integration_challenge(SURFACE, CAPABILITY)
        resp = answer_integration_challenge(ch, private_key=kp.private_key_jwk, did=kp.did)
        ok, _ = verify_integration_response(resp, ch, public_key=other.public_key_jwk)
        assert ok is False

    def test_tampered_subject_breaks_proof(self):
        kp = _identity()
        ch = build_integration_challenge(SURFACE, CAPABILITY)
        resp = answer_integration_challenge(ch, private_key=kp.private_key_jwk, did=kp.did)
        resp["credentialSubject"]["capability"] = "forged-capability"
        ok, _ = verify_integration_response(resp, ch, public_key=kp.public_key_jwk)
        assert ok is False


class TestArtifactDigest:
    def test_artifact_digest_match(self):
        kp = _identity()
        ch = build_integration_challenge(SURFACE, CAPABILITY)
        resp = answer_integration_challenge(
            ch, private_key=kp.private_key_jwk, did=kp.did, artifact=ARTIFACT
        )
        ok, details = verify_integration_response(
            resp, ch, public_key=kp.public_key_jwk, artifact=ARTIFACT
        )
        assert ok is True
        assert details["artifactMatch"] is True
        assert details["artifactDigest"] == resp["credentialSubject"]["artifactDigest"]

    def test_artifact_digest_mismatch_rejected(self):
        kp = _identity()
        ch = build_integration_challenge(SURFACE, CAPABILITY)
        resp = answer_integration_challenge(
            ch, private_key=kp.private_key_jwk, did=kp.did, artifact=ARTIFACT
        )
        tampered = {"action": "delete", "target": "inbox", "resource": "https://mail/api/inbox"}
        ok, details = verify_integration_response(
            resp, ch, public_key=kp.public_key_jwk, artifact=tampered
        )
        assert ok is False
        assert details["artifactMatch"] is False

    def test_artifact_optional_at_verify(self):
        kp = _identity()
        ch = build_integration_challenge(SURFACE, CAPABILITY)
        resp = answer_integration_challenge(
            ch, private_key=kp.private_key_jwk, did=kp.did, artifact=ARTIFACT
        )
        # Verifying without the artifact still succeeds (digest just not rechecked).
        ok, details = verify_integration_response(resp, ch, public_key=kp.public_key_jwk)
        assert ok is True
        assert "artifactMatch" not in details


class TestBlock:
    def test_block_shape(self):
        kp = _identity()
        ch = build_integration_challenge(SURFACE, CAPABILITY)
        resp = answer_integration_challenge(ch, private_key=kp.private_key_jwk, did=kp.did)
        block = proof_of_integration_block(resp, ch)

        assert set(block) == {
            "nonce",
            "responseDigest",
            "surface",
            "verificationMethod",
            "observedAt",
        }
        assert block["nonce"] == ch["nonce"]
        assert block["surface"] == SURFACE
        assert block["verificationMethod"] == f"{kp.did}#key-1"
        assert block["responseDigest"].startswith("u")


class TestExports:
    def test_type_constants_exported(self):
        import vouch

        assert vouch.CHALLENGE_TYPE == CHALLENGE_TYPE
        assert vouch.RESPONSE_TYPE == RESPONSE_TYPE
        assert vouch.build_integration_challenge is build_integration_challenge
