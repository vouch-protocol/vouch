"""
Deterministic generator for the Root of Trust interop test vector.

Produces the three authority-layer credential types (VouchRootOfTrust,
RecognizedIssuerCredential, AgentIdentityCredential) from fixed Ed25519 seeds
and fixed timestamps, so every language SDK can reproduce byte-identical
proofValues and verify the same chain.

Run:  python test-vectors/root-of-trust/generate.py   # rewrites vector.json
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vouch import multikey
from vouch.signer import Signer
from vouch.root_of_trust import (
    ACTION_ISSUE_AGENT_IDENTITY,
    build_agent_identity,
    build_recognized_issuer,
    build_root_of_trust,
)

# Fixed 32-byte Ed25519 seeds (test material only, never for production).
ROOT_SEED = bytes([1]) * 32
ISSUER_SEED = bytes([2]) * 32
AGENT_SEED = bytes([3]) * 32

# Fixed issuance time and a very long validity so the vector never expires.
FIXED_TIME = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
CENTURY_SECONDS = 100 * 365 * 24 * 3600

ROOT_ID = "urn:uuid:11111111-1111-1111-1111-111111111111"
RECOGNITION_ID = "urn:uuid:22222222-2222-2222-2222-222222222222"
IDENTITY_ID = "urn:uuid:33333333-3333-3333-3333-333333333333"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _signer_from_seed(seed: bytes) -> Signer:
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk = json.dumps({"kty": "OKP", "crv": "Ed25519", "d": _b64url(seed), "x": _b64url(pub)})
    did = "did:key:" + multikey.encode_ed25519_public(pub)
    return Signer(jwk, did)


def build_vectors() -> dict:
    """Build the full vector object deterministically."""
    root = _signer_from_seed(ROOT_SEED)
    issuer = _signer_from_seed(ISSUER_SEED)
    agent = _signer_from_seed(AGENT_SEED)

    root_cred = build_root_of_trust(
        root,
        name="Vouch Machine Identity Root",
        valid_seconds=CENTURY_SECONDS,
        valid_from=FIXED_TIME,
        created=FIXED_TIME,
        credential_id=ROOT_ID,
    )
    recognition = build_recognized_issuer(
        root,
        issuer_did=issuer.did,
        recognized_actions=[ACTION_ISSUE_AGENT_IDENTITY],
        valid_seconds=CENTURY_SECONDS,
        valid_from=FIXED_TIME,
        created=FIXED_TIME,
        credential_id=RECOGNITION_ID,
    )
    identity = build_agent_identity(
        issuer,
        subject_did=agent.did,
        attributes={"owner": "Acme", "model": "gpt-x", "capabilityClass": "shopping"},
        valid_seconds=CENTURY_SECONDS,
        valid_from=FIXED_TIME,
        created=FIXED_TIME,
        credential_id=IDENTITY_ID,
    )

    return {
        "description": (
            "Vouch Protocol Root of Trust interop vector. Built from fixed Ed25519 "
            "seeds and a fixed timestamp. Every SDK must reproduce identical "
            "proofValues and verify the chain (agent identity anchored to the root)."
        ),
        "trustedRoot": root.did,
        "seeds": {"root": "0x01 x32", "issuer": "0x02 x32", "agent": "0x03 x32"},
        "rootOfTrust": root_cred,
        "recognizedIssuer": recognition,
        "agentIdentity": identity,
        "expected": {
            "verifyIdentityChain": True,
            "agentDid": agent.did,
            "issuerDid": issuer.did,
        },
    }


if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(__file__), "vector.json")
    with open(out_path, "w") as handle:
        json.dump(build_vectors(), handle, indent=2)
        handle.write("\n")
    print(f"wrote {out_path}")
