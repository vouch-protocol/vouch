"""
Hybrid Ed25519 + ML-DSA-44 Data Integrity proofs.

Implements the hybrid-eddsa-mldsa44-jcs-2026 cryptosuite (W3C CG Report
§13.2), an additive optional profile that pairs the classical Ed25519
signature with a post-quantum ML-DSA-44 signature over the same
JCS-canonicalized payload. Verification REQUIRES both signatures to
validate.

Mirrors go-sidecar/signer/data_integrity_hybrid.go and
typescript/src/data-integrity-hybrid.ts. Wire format is identical across
all three implementations so that a credential signed by one can be
verified by another.

Wire format:
    proofValue = "z" + base58btc( ed25519_sig (64 bytes) || mldsa44_sig (2420 bytes) )

DID Document layout:
    verificationMethod[]:
        - id: did:..#key-1, type: Multikey, publicKeyMultibase: z<Ed25519>
        - id: did:..#key-2, type: Multikey, publicKeyMultibase: z<ML-DSA-44>
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import jcs
from .multikey import _b58decode, _b58encode


# Cryptosuite identifier. Provisional, will be coordinated with the W3C
# Data Integrity WG before final publication.
CRYPTOSUITE_HYBRID_EDDSA_MLDSA44 = "hybrid-eddsa-mldsa44-jcs-2026"
PROOF_TYPE = "DataIntegrityProof"

# Fixed signature sizes for splitting the concatenated proofValue.
ED25519_SIGNATURE_SIZE = 64
MLDSA44_SIGNATURE_SIZE = 2420
HYBRID_SIGNATURE_SIZE = ED25519_SIGNATURE_SIZE + MLDSA44_SIGNATURE_SIZE


def _import_pqcrypto():
    """Import pqcrypto.sign.ml_dsa_44 lazily so the rest of the package
    keeps working when the optional dependency is missing."""
    try:
        from pqcrypto.sign import ml_dsa_44  # type: ignore[import-untyped]

        return ml_dsa_44
    except ImportError as e:
        raise ImportError(
            "Hybrid post-quantum cryptosuite requires the 'pqcrypto' package. "
            "Install it with: pip install pqcrypto"
        ) from e


def generate_mldsa44_keypair() -> Tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-44 keypair. Returns (public_key, secret_key)."""
    ml_dsa_44 = _import_pqcrypto()
    return ml_dsa_44.generate_keypair()


def build_hybrid_proof(
    credential: Dict[str, Any],
    *,
    ed25519_private_key: Ed25519PrivateKey,
    mldsa44_secret_key: bytes,
    verification_method: str,
    proof_purpose: str = "assertionMethod",
    created: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Generate a hybrid Data Integrity proof for `credential`.

    Both Ed25519 and ML-DSA-44 sign the SHA-256 of the JCS-canonicalized
    credential (with the unsigned proof attached). Returns the proof dict
    (caller attaches it to the credential).
    """
    ml_dsa_44 = _import_pqcrypto()

    proof: Dict[str, Any] = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE_HYBRID_EDDSA_MLDSA44,
        "created": _format_iso8601(created or datetime.now(timezone.utc)),
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }

    # Build canonical form with the unsigned proof attached.
    cred_with_unsigned_proof = dict(credential)
    cred_with_unsigned_proof["proof"] = proof
    canonical = jcs.canonicalize(cred_with_unsigned_proof)
    digest = hashlib.sha256(canonical).digest()

    # Classical Ed25519 signature.
    ed_sig = ed25519_private_key.sign(digest)
    if len(ed_sig) != ED25519_SIGNATURE_SIZE:
        raise RuntimeError(
            f"unexpected Ed25519 sig size {len(ed_sig)}, want {ED25519_SIGNATURE_SIZE}"
        )

    # Post-quantum ML-DSA-44 signature.
    ml_sig = ml_dsa_44.sign(mldsa44_secret_key, digest)
    if len(ml_sig) != MLDSA44_SIGNATURE_SIZE:
        raise RuntimeError(
            f"unexpected ML-DSA-44 sig size {len(ml_sig)}, want {MLDSA44_SIGNATURE_SIZE}"
        )

    combined = ed_sig + ml_sig
    proof["proofValue"] = "z" + _b58encode(combined)
    return proof


def verify_hybrid_proof(
    credential: Dict[str, Any],
    *,
    ed25519_public_key: Ed25519PublicKey,
    mldsa44_public_key: bytes,
) -> bool:
    """Verify a hybrid composite proof.

    Both signatures MUST validate. Returns True on success, False on
    signature failure. Raises ValueError on malformed proof structure.
    """
    ml_dsa_44 = _import_pqcrypto()

    proof = credential.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("Credential has no proof object")
    if proof.get("type") != PROOF_TYPE:
        raise ValueError(f"Unexpected proof type: {proof.get('type')}")
    if proof.get("cryptosuite") != CRYPTOSUITE_HYBRID_EDDSA_MLDSA44:
        raise ValueError(f"Unexpected cryptosuite: {proof.get('cryptosuite')}")

    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        raise ValueError("Missing or malformed proofValue")

    combined = _b58decode(proof_value[1:])
    if len(combined) != HYBRID_SIGNATURE_SIZE:
        raise ValueError(
            f"hybrid signature length {len(combined)}, expected {HYBRID_SIGNATURE_SIZE}"
        )

    ed_sig = combined[:ED25519_SIGNATURE_SIZE]
    ml_sig = combined[ED25519_SIGNATURE_SIZE:]

    # Reconstruct the canonical form.
    proof_without_value = {k: v for k, v in proof.items() if k != "proofValue"}
    cred_for_check = dict(credential)
    cred_for_check["proof"] = proof_without_value
    canonical = jcs.canonicalize(cred_for_check)
    digest = hashlib.sha256(canonical).digest()

    # Classical Ed25519 verification.
    try:
        ed25519_public_key.verify(ed_sig, digest)
    except InvalidSignature:
        return False

    # Post-quantum ML-DSA-44 verification. pqcrypto's verify raises on
    # invalid sig in some builds; we treat any exception as failure.
    try:
        ok = ml_dsa_44.verify(mldsa44_public_key, digest, ml_sig)
    except Exception:
        return False
    return bool(ok)


def hybrid_verification_method_pair(verification_method: str) -> Tuple[str, str]:
    """Derive the (Ed25519, ML-DSA-44) verificationMethod URL pair from a
    single identifier. The convention is that the proof's verificationMethod
    points at the Ed25519 key (#key-1) and the ML-DSA-44 key sits at the
    parallel slot (#key-2) on the same DID."""
    if verification_method.endswith("#key-1"):
        base = verification_method[: -len("#key-1")]
        return verification_method, base + "#key-2"
    if "#" in verification_method:
        idx = verification_method.index("#")
        return verification_method, verification_method[:idx] + "#key-2"
    return verification_method, verification_method + "#key-2"


def _format_iso8601(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
