"""
Vouch Protocol Security Test Suite.

Tests end-to-end signing and verification to ensure cryptographic integrity.
"""

import sys
import os

# Add parent directory to path for local development
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from jwcrypto import jwk

from vouch import Signer, Verifier, Auditor, generate_identity


def test_signer_verifier_roundtrip():
    """Test that signed tokens can be verified."""
    print("> Test 1: Signer/Verifier Roundtrip...", end=" ")

    # Generate keys
    keys = generate_identity(domain="test-agent.com")

    # Create signer
    signer = Signer(private_key=keys.private_key_jwk, did=keys.did)

    # Sign a payload
    payload = {"action": "read_database", "target": "users"}
    token = signer.sign(payload)

    # Verify with public key
    is_valid, passport = Verifier.verify(token, public_key_jwk=keys.public_key_jwk)

    assert is_valid, "Token should be valid"
    assert passport.sub == keys.did, f"Subject should match DID: {passport.sub} != {keys.did}"
    assert passport.payload.get("action") == "read_database", "Payload should be preserved"

    print("PASSED ✅")


def test_auditor_verification():
    """Test Auditor certificate issuance and verification."""
    print("> Test 2: Auditor Certificate...", end=" ")

    # Generate authority keys
    authority_key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    authority_private = authority_key.export_private()
    authority_public = authority_key.export_public()

    # Create auditor
    auditor = Auditor(private_key_json=authority_private, issuer_did="did:web:vouch-authority")

    # Issue certificate
    cert = auditor.issue_vouch(
        {"did": "did:web:test-agent.com", "integrity_hash": "sha256:abc123", "reputation_score": 85}
    )

    assert "certificate" in cert, "Should return certificate"

    # Verify the certificate
    is_valid, passport = Verifier.verify(cert["certificate"], public_key_jwk=authority_public)

    assert is_valid, "Certificate should be valid"
    assert passport.sub == "did:web:test-agent.com", "Subject should match"

    print("PASSED ✅")


def test_expired_token_rejection():
    """Test that expired tokens are rejected."""
    print("> Test 3: Expired Token Rejection...", end=" ")

    keys = generate_identity(domain="test-agent.com")

    # Create signer with negative expiry (already expired)
    signer = Signer(
        private_key=keys.private_key_jwk,
        did=keys.did,
        default_expiry_seconds=-60,  # Expired 60 seconds ago
    )

    # Sign a payload (will already be expired)
    token = signer.sign({"action": "test"})

    # Verify (should fail due to expiry)
    is_valid, passport = Verifier.verify(token, public_key_jwk=keys.public_key_jwk)

    assert not is_valid, "Expired token should be rejected"

    print("PASSED ✅")


def test_invalid_signature_rejection():
    """Test that tokens with wrong signature are rejected."""
    print("> Test 4: Invalid Signature Rejection...", end=" ")

    # Generate two different key pairs
    keys1 = generate_identity(domain="agent1.com")
    keys2 = generate_identity(domain="agent2.com")

    # Sign with keys1
    signer = Signer(private_key=keys1.private_key_jwk, did=keys1.did)
    token = signer.sign({"action": "test"})

    # Try to verify with keys2's public key (should fail)
    is_valid, passport = Verifier.verify(token, public_key_jwk=keys2.public_key_jwk)

    assert not is_valid, "Token signed with different key should be rejected"

    print("PASSED ✅")


def test_verifier_with_trusted_roots():
    """Test instance-based verification with trusted roots."""
    print("> Test 5: Trusted Roots Verification...", end=" ")

    keys = generate_identity(domain="trusted-agent.com")

    # Create verifier with trusted roots
    verifier = Verifier(trusted_roots={keys.did: keys.public_key_jwk}, allow_did_resolution=False)

    # Sign a message
    signer = Signer(private_key=keys.private_key_jwk, did=keys.did)
    token = signer.sign({"action": "trusted_action"})

    # Verify using check_vouch (instance method)
    is_valid, passport = verifier.check_vouch(token)

    assert is_valid, "Token from trusted root should be valid"
    assert passport.sub == keys.did, "Subject should match"

    print("PASSED ✅")


def main():
    """Run all tests."""
    print("\n⚔️  VOUCH PROTOCOL SECURITY TEST SUITE")
    print("=" * 40)

    tests = [
        test_signer_verifier_roundtrip,
        test_auditor_verification,
        test_expired_token_rejection,
        test_invalid_signature_rejection,
        test_verifier_with_trusted_roots,
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
