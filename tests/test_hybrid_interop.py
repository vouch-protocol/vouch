"""
Cross-implementation interop test for hybrid-eddsa-mldsa44-jcs-2026.

Reads the shared vector at test-vectors/hybrid-eddsa-mldsa44/vector.json
and asserts:
  1. JCS canonicalization of the signed credential (with proofValue
     stripped) produces the documented SHA-256 digest.
  2. The Python verifier accepts the signature in the vector.

The TypeScript and Go suites have parallel tests against the same vector.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

pqcrypto = pytest.importorskip("pqcrypto.sign.ml_dsa_44")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vouch import data_integrity_hybrid, jcs


VECTOR_PATH = (
    Path(__file__).resolve().parent.parent / "test-vectors" / "hybrid-eddsa-mldsa44" / "vector.json"
)


def _load():
    return json.loads(VECTOR_PATH.read_text())


def test_hybrid_interop_canonical_digest():
    vec = _load()

    cred = json.loads(json.dumps(vec["signed_credential"]))
    proof = cred["proof"]
    proof.pop("proofValue", None)

    canonical = jcs.canonicalize(cred)
    digest = hashlib.sha256(canonical).digest()
    expected = base64.b64decode(vec["expected_canonical_sha256_b64"])

    assert digest == expected, (
        f"\n  expected: {vec['expected_canonical_sha256_b64']}\n"
        f"  got:      {base64.b64encode(digest).decode()}"
    )


def test_hybrid_interop_python_verifies_python_signature():
    vec = _load()

    ed_pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(vec["ed25519"]["public_key_b64"]))
    ml_pub = base64.b64decode(vec["mldsa44"]["public_key_b64"])

    ok = data_integrity_hybrid.verify_hybrid_proof(
        vec["signed_credential"],
        ed25519_public_key=ed_pub,
        mldsa44_public_key=ml_pub,
    )
    assert ok is True
