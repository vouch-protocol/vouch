"""
Example: Verify a Vouch Credential (v1.6+, W3C VC + Data Integrity).

Mirrors 01a_sign_credential.py for the verifier side. Demonstrates:
1. Full verification with a Node-style public key (Ed25519PublicKey).
2. Tamper detection.
3. Extraction of the CredentialPassport (issuer, intent, validity).

For the legacy v0.x JWS path, see 02_verify_token.py.
"""

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto.common import base64url_decode

from vouch import Signer, Verifier, generate_keypair


def public_key_from_jwk(jwk_str: str) -> Ed25519PublicKey:
    """Helper: extract Ed25519PublicKey from a JWK string."""
    jwk = json.loads(jwk_str)
    return Ed25519PublicKey.from_public_bytes(base64url_decode(jwk["x"]))


def main() -> None:
    # Setup: issuer + a verifier-side copy of the issuer's public key.
    # In production the verifier would resolve the public key via did:web
    # (see 03_did_resolution.py).
    keypair = generate_keypair()
    signer = Signer(
        private_key=keypair["private_key_jwk"],
        did="did:web:agent.example.com",
    )
    public_key = public_key_from_jwk(keypair["public_key_jwk"])

    # Issue a credential.
    credential = signer.sign_credential(
        intent={
            "action": "read_patient_record",
            "target": "patient:12345",
            "resource": "https://ehr.example.com/api/v1/patients/12345",
        }
    )

    # ------------------------------------------------------------------
    # Case 1: Valid credential -> verification succeeds, returns Passport.
    # ------------------------------------------------------------------
    is_valid, passport = Verifier.verify_credential(credential, public_key=public_key)

    print(f"Case 1 (untampered): valid={is_valid}")
    if passport:
        print(f"  issuer:     {passport.iss}")
        print(f"  subject:    {passport.sub}")
        print(f"  validUntil: {passport.valid_until}")
        print(f"  intent:     {passport.intent}")
        print(f"  reputation: {passport.reputation_score}")
        print(f"  chain:      {len(passport.delegation_chain)} link(s)")

    # ------------------------------------------------------------------
    # Case 2: Tampered credential -> verification fails, no Passport.
    # ------------------------------------------------------------------
    tampered = json.loads(json.dumps(credential))  # deep copy
    tampered["credentialSubject"]["intent"]["resource"] = "https://attacker.example.com/api/users"

    is_valid, passport = Verifier.verify_credential(tampered, public_key=public_key)
    print(f"\nCase 2 (tampered):   valid={is_valid}")
    print(
        "  The proof binds the entire credential including the resource URL."
        " A single-byte change anywhere in the canonical form breaks"
        " verification."
    )

    # ------------------------------------------------------------------
    # Case 3: Multikey-format public key also works.
    # The same verify_credential() accepts: Ed25519PublicKey, a
    # multibase-encoded Multikey string, a JWK string, or a JWK dict.
    # ------------------------------------------------------------------
    multikey = signer.get_public_key_multikey()
    is_valid, _ = Verifier.verify_credential(credential, public_key=multikey)
    print(f"\nCase 3 (Multikey):   valid={is_valid}")
    print(f"  Multikey:    {multikey[:20]}... (z-prefixed base58btc)")


if __name__ == "__main__":
    main()
