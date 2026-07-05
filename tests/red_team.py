"""
Vouch Protocol Security Test Suite.

Tests end-to-end signing and verification to ensure cryptographic integrity.
"""

import base64
import json
import os
import sys

# Add parent directory to path for local development
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto import jwk

from vouch import Signer, Verifier, Auditor, generate_identity


def _ed_pub(public_key_jwk: str) -> Ed25519PublicKey:
    """Ed25519PublicKey from a public JWK JSON string."""
    x = json.loads(public_key_jwk)["x"]
    raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    return Ed25519PublicKey.from_public_bytes(raw)


def test_signer_verifier_roundtrip():
    """Test that signed credentials can be verified."""
    print("> Test 1: Signer/Verifier Roundtrip...", end=" ")

    keys = generate_identity(domain="test-agent.com")
    signer = Signer(private_key=keys.private_key_jwk, did=keys.did)

    intent = {"action": "read_database", "target": "users", "resource": "db:users"}
    credential = signer.sign(intent=intent)

    is_valid, passport = Verifier.verify(credential, public_key=_ed_pub(keys.public_key_jwk))

    assert is_valid, "Credential should be valid"
    assert passport.sub == keys.did, f"Subject should match DID: {passport.sub} != {keys.did}"
    assert passport.intent.get("action") == "read_database", "Intent should be preserved"

    print("PASSED ✅")


def test_auditor_verification():
    """Test Auditor certificate issuance and verification."""
    print("> Test 2: Auditor Certificate...", end=" ")

    authority_key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    authority_private = authority_key.export_private()
    authority_public = authority_key.export_public()

    auditor = Auditor(private_key_json=authority_private, issuer_did="did:web:vouch-authority")

    cert = auditor.issue_vouch(
        {"did": "did:web:test-agent.com", "integrity_hash": "sha256:abc123", "reputation_score": 85}
    )

    assert "certificate" in cert, "Should return certificate"

    is_valid, passport = Verifier.verify(cert["certificate"], public_key=_ed_pub(authority_public))

    assert is_valid, "Certificate should be valid"
    assert passport.intent["target"] == "did:web:test-agent.com", "Certified agent should match"

    print("PASSED ✅")


def test_expired_credential_rejection():
    """Test that expired credentials are rejected."""
    print("> Test 3: Expired Credential Rejection...", end=" ")

    keys = generate_identity(domain="test-agent.com")
    signer = Signer(
        private_key=keys.private_key_jwk,
        did=keys.did,
        default_expiry_seconds=-60,  # Expired 60 seconds ago
    )

    credential = signer.sign(intent={"action": "test", "target": "svc", "resource": "svc"})

    is_valid, _ = Verifier.verify(credential, public_key=_ed_pub(keys.public_key_jwk))

    assert not is_valid, "Expired credential should be rejected"

    print("PASSED ✅")


def test_invalid_signature_rejection():
    """Test that credentials with wrong signature are rejected."""
    print("> Test 4: Invalid Signature Rejection...", end=" ")

    keys1 = generate_identity(domain="agent1.com")
    keys2 = generate_identity(domain="agent2.com")

    signer = Signer(private_key=keys1.private_key_jwk, did=keys1.did)
    credential = signer.sign(intent={"action": "test", "target": "svc", "resource": "svc"})

    # Verify with keys2's public key (should fail)
    is_valid, _ = Verifier.verify(credential, public_key=_ed_pub(keys2.public_key_jwk))

    assert not is_valid, "Credential signed with a different key should be rejected"

    print("PASSED ✅")


def test_verifier_with_supplied_key():
    """Test static verification with a supplied public key."""
    print("> Test 5: Supplied-Key Verification...", end=" ")

    keys = generate_identity(domain="trusted-agent.com")
    signer = Signer(private_key=keys.private_key_jwk, did=keys.did)
    credential = signer.sign(
        intent={"action": "trusted_action", "target": "svc", "resource": "svc"}
    )

    is_valid, passport = Verifier.verify(credential, public_key=_ed_pub(keys.public_key_jwk))

    assert is_valid, "Credential from a supplied trusted key should be valid"
    assert passport.sub == keys.did, "Subject should match"

    print("PASSED ✅")


def main():
    """Run all tests."""
    print("\n⚔️  VOUCH PROTOCOL SECURITY TEST SUITE")
    print("=" * 40)

    tests = [
        test_signer_verifier_roundtrip,
        test_auditor_verification,
        test_expired_credential_rejection,
        test_invalid_signature_rejection,
        test_verifier_with_supplied_key,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"FAILED ❌: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR ❌: {e}")
            failed += 1

    print("=" * 40)
    print(f"Results: {passed} passed, {failed} failed")

    if failed > 0:
        sys.exit(1)
    else:
        print("\n✅ All Security Tests Passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
