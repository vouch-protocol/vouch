"""
Vouch integrations: issue, verify, and delegate.

Shows the v1.0 path the framework wrappers now use under the hood:

  1. A supervisor agent issues a Verifiable Credential (eddsa-jcs-2022).
  2. A verifier confirms it cryptographically.
  3. A worker agent narrows that authority via capability attenuation
     (v1.7) by passing the supervisor's credential as parent_credential.
  4. The verifier confirms the delegated, attenuated credential.

Run:
    python examples/integrations_delegation.py
"""

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto.common import base64url_decode

from vouch import Signer, generate_identity
from vouch.integrations._common import sign_tool_call, verify_tool_call


def public_key_from_jwk(jwk_str: str) -> Ed25519PublicKey:
    """Extract an Ed25519PublicKey from a JWK string."""
    jwk = json.loads(jwk_str)
    return Ed25519PublicKey.from_public_bytes(base64url_decode(jwk["x"]))


def main() -> None:
    # Two independent agent identities.
    sup_kp = generate_identity()
    wrk_kp = generate_identity()

    supervisor = Signer(private_key=sup_kp.private_key_jwk, did="did:web:supervisor.example.com")
    worker = Signer(private_key=wrk_kp.private_key_jwk, did="did:web:worker.example.com")

    sup_pub = public_key_from_jwk(sup_kp.public_key_jwk)
    wrk_pub = public_key_from_jwk(wrk_kp.public_key_jwk)

    # 1. Supervisor authorizes a broad CRM task. The resource is a path
    # prefix; children may only narrow under it (see _is_sub_resource).
    parent = sign_tool_call(supervisor, action="manage", target="crm", resource="account:acme")
    ok, _ = verify_tool_call(parent, public_key=sup_pub)
    print(f"supervisor credential valid: {ok}")

    # 2. Worker narrows it: read-only, a single sub-resource. Never broader.
    leaf = sign_tool_call(
        worker,
        action="read",
        target="crm",
        resource="account:acme/contacts",
        parent_credential=parent,
    )
    ok, passport = verify_tool_call(leaf, public_key=wrk_pub)
    print(f"delegated credential valid: {ok}")

    chain = (leaf.get("credentialSubject", {}) or {}).get("delegationChain") or leaf.get(
        "delegationChain"
    )
    print(f"delegation links present: {bool(chain)}")


if __name__ == "__main__":
    main()
