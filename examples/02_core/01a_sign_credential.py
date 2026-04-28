"""
Example: Sign a Vouch Credential (v1.6+, W3C VC + Data Integrity).

This is the modern issuance path. The credential travels in the HTTP
request body with content-type application/vouch+credential+json and
verifies via Verifier.verify_credential() (see 02a_verify_credential.py).

The credential is human-readable JSON. The Data Integrity proof attaches
as a sibling object, no JOSE, no Base64-wrapped opaque payload.

For the legacy v0.x JWS path, see 01_sign_request.py.
"""

import json

from vouch import Signer, generate_keypair


def main() -> None:
    # 1. Generate a fresh agent identity. In production you would load a
    # key that was provisioned ahead of time, see 02_key_generation.py.
    keypair = generate_keypair()
    private_key_jwk = keypair["private_key_jwk"]
    did = "did:web:agent.example.com"

    signer = Signer(private_key=private_key_jwk, did=did)

    # 2. Construct the intent. action, target, and resource are REQUIRED
    # in v1.0 (W3C CG Report §5.4.1). The resource binding prevents
    # confused-deputy attacks: the credential proves the agent is
    # authorized for THIS resource, not a different one.
    intent = {
        "action": "read_patient_record",
        "target": "patient:12345",
        "resource": "https://ehr.example.com/api/v1/patients/12345",
    }

    # 3. Issue the credential. Returns a dict you can JSON-serialize.
    credential = signer.sign_credential(
        intent=intent,
        valid_seconds=300,  # 5-minute validity, default
        reputation_score=87,  # Optional, [0, 100]
    )

    print("Issued Vouch Credential:")
    print(json.dumps(credential, indent=2))

    # 4. The credential's `proof` object is the Data Integrity proof.
    print("\nProof structure:")
    proof = credential["proof"]
    print(f"  type:                {proof['type']}")
    print(f"  cryptosuite:         {proof['cryptosuite']}")
    print(f"  verificationMethod:  {proof['verificationMethod']}")
    print(f"  proofValue length:   {len(proof['proofValue'])} chars (base58btc)")

    # 5. Send to your API. Suggested transport:
    #    POST /api/resource HTTP/1.1
    #    Content-Type: application/vouch+credential+json
    #    <credential JSON as the body>
    #
    # The verifier extracts the credential from the body, validates the
    # Data Integrity proof, checks temporal claims, and returns a
    # CredentialPassport. See 02a_verify_credential.py.


if __name__ == "__main__":
    main()
