"""
Data Integrity proof builder and verifier — `eddsa-jcs-2022` cryptosuite.

Implements §3.1 of [VC-DI-EDDSA]:
 https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022

The cryptosuite produces a `DataIntegrityProof` object that attaches alongside
the credential payload as a sibling `proof` property. No JWS, no JOSE, no Base64
wrapping of the payload — the credential remains human-readable JSON.

Signing flow (Specification §7.1):
  1. Build credential with unsigned proof (no proofValue).
  2. JCS-canonicalize the entire object.
  3. SHA-256 the canonical bytes.
  4. Ed25519-sign the digest.
  5. Multibase-encode the signature into proof.proofValue.

Verification reverses these steps.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import jcs
from .multikey import _b58decode, _b58encode


CRYPTOSUITE_ID = "eddsa-jcs-2022"
PROOF_TYPE = "DataIntegrityProof"


def build_proof(
    credential: Dict[str, Any],
    private_key: Ed25519PrivateKey,
    verification_method: str,
    proof_purpose: str = "assertionMethod",
    created: datetime | None = None,
) -> Dict[str, Any]:
    """
    Generate a Data Integrity proof object for `credential` using the given
    Ed25519 private key. Returns the proof dict (caller attaches it to the
    credential).

    Conforms to eddsa-jcs-2022 §3.1.
    """
    proof = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE_ID,
        "created": _format_iso8601(created or datetime.now(timezone.utc)),
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }

    # Attach the unsigned proof to a copy of the credential and canonicalize.
    cred_with_unsigned_proof = dict(credential)
    cred_with_unsigned_proof["proof"] = proof
    canonical = jcs.canonicalize(cred_with_unsigned_proof)
    digest = hashlib.sha256(canonical).digest()

    signature = private_key.sign(digest)
    proof["proofValue"] = "z" + _b58encode(signature)
    return proof


def verify_proof(credential: Dict[str, Any], public_key: Ed25519PublicKey) -> bool:
    """
    Verify a Data Integrity proof attached to `credential`.

    Returns True on success, False on signature failure.
    Raises ValueError on malformed proof structure.
    """
    proof = credential.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("Credential has no proof object")

    if proof.get("type") != PROOF_TYPE:
        raise ValueError(f"Unexpected proof type: {proof.get('type')}")
    if proof.get("cryptosuite") != CRYPTOSUITE_ID:
        raise ValueError(f"Unexpected cryptosuite: {proof.get('cryptosuite')}")

    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        raise ValueError("Missing or malformed proofValue")

    signature = _b58decode(proof_value[1:])

    # Reconstruct the canonical form by removing proofValue from the proof
    # (keeping all other proof fields) and canonicalizing the credential.
    proof_without_value = {k: v for k, v in proof.items() if k != "proofValue"}
    cred_without_value = dict(credential)
    cred_without_value["proof"] = proof_without_value
    canonical = jcs.canonicalize(cred_without_value)
    digest = hashlib.sha256(canonical).digest()

    try:
        public_key.verify(signature, digest)
        return True
    except InvalidSignature:
        return False


def _format_iso8601(dt: datetime) -> str:
    # VC requires XML Schema dateTime — RFC 3339 with `Z` suffix is acceptable.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
