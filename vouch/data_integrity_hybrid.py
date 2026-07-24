"""
Post-quantum credentials: Ed25519 + ML-DSA-44 Data Integrity proofs.

Two shapes live here.

Proof set (the current design, per Manu Sporny's review of the W3C CG
Report, entries 9-10 of the Editor Review Queue at the top of
docs/specs/w3c-cg-report.md). The credential carries a `proof` ARRAY of two
independent proofs, `eddsa-jcs-2022` and `mldsa44-jcs-2024`. Each proof is
computed over the same unsecured document with only its own proof
configuration, and each verifies on its own, so a verifier that understands
only one of the two cryptosuites can still check that proof. Both must
verify for :func:`verify_dual` to succeed. See PAD-040 §3.3a for the
dual-proof carrier embodiment.

Composite (the v1.6.x transitional `hybrid-eddsa-mldsa44-jcs-2026`): a
single proof whose proofValue is base58btc(ed25519_sig || mldsa44_sig),
signed over the pre-alignment 32-byte digest. Verify-only: it is retained so
credentials already issued under that wire format keep verifying and so the
shared interop vector can be reproduced for regression checks. New
credentials use the proof set.

Signing input (proof set): the 64-byte W3C Data Integrity hashData,
SHA-256(canonical proof configuration) || SHA-256(canonical document). See
:func:`vouch.data_integrity.hash_data`.

Encodings:
  - `eddsa-jcs-2022` proofValue is "z" + base58btc(signature).
  - `mldsa44-jcs-2024` proofValue is "u" + base64url-nopad(signature), the
    Multibase encoding the Quantum-Resistant Cryptosuites specification uses.
    Verification also accepts the pre-alignment "z" + base58btc form and the
    pre-alignment `mldsa44-jcs-2026` identifier.

Mirrors core/vouch-core/src/hybrid.rs.

DID Document layout:
  verificationMethod[]:
    - id: did:..#key-1, type: Multikey, publicKeyMultibase: z<Ed25519>
    - id: did:..#key-2, type: Multikey, publicKeyMultibase: z<ML-DSA-44>
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import data_integrity
from .multikey import _b58decode, _b58encode


# The classical cryptosuite carried alongside the post-quantum one.
CRYPTOSUITE_EDDSA = data_integrity.CRYPTOSUITE_ID
# The W3C Quantum-Resistant Cryptosuites identifier for ML-DSA-44 over JCS.
CRYPTOSUITE_MLDSA44 = "mldsa44-jcs-2024"
# Pre-alignment identifier, accepted on verification only.
CRYPTOSUITE_MLDSA44_LEGACY = "mldsa44-jcs-2026"
# The v1.6.x composite. Accepted on verification only; never emitted for new
# credentials.
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


def build_dual_proof(
    credential: Dict[str, Any],
    *,
    ed25519_private_key: Ed25519PrivateKey,
    mldsa44_secret_key: bytes,
    ed25519_verification_method: str,
    mldsa44_verification_method: Optional[str] = None,
    proof_purpose: str = "assertionMethod",
    created: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Build a proof set for `credential`: a list of two independent Data
    Integrity proofs, one `eddsa-jcs-2022` and one `mldsa44-jcs-2024`.

    Each proof is computed over the same unsecured document with only its own
    proof configuration, so either can be checked on its own. When
    `mldsa44_verification_method` is omitted it is derived from the Ed25519
    identifier by :func:`hybrid_verification_method_pair`.
    """
    ml_dsa_44 = _import_pqcrypto()

    base = data_integrity.unsecured_document(credential)
    created_at = created or datetime.now(timezone.utc)
    if mldsa44_verification_method is None:
        _, mldsa44_verification_method = hybrid_verification_method_pair(
            ed25519_verification_method
        )

    ed_proof = data_integrity.build_proof(
        base,
        ed25519_private_key,
        verification_method=ed25519_verification_method,
        proof_purpose=proof_purpose,
        created=created_at,
    )

    ml_proof: Dict[str, Any] = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE_MLDSA44,
        "created": _format_iso8601(created_at),
        "verificationMethod": mldsa44_verification_method,
        "proofPurpose": proof_purpose,
    }
    ml_signing_input = data_integrity.hash_data(base, ml_proof)
    ml_sig = ml_dsa_44.sign(mldsa44_secret_key, ml_signing_input)
    if len(ml_sig) != MLDSA44_SIGNATURE_SIZE:
        raise RuntimeError(
            f"unexpected ML-DSA-44 sig size {len(ml_sig)}, want {MLDSA44_SIGNATURE_SIZE}"
        )
    # The Quantum-Resistant Cryptosuites specification encodes proofValue as a
    # base64url-nopad Multibase value ("u"). The classical eddsa-jcs-2022 suite
    # is specified separately and keeps base58btc ("z").
    ml_proof["proofValue"] = "u" + _b64u_encode(ml_sig)

    return [ed_proof, ml_proof]


def sign_dual(
    credential: Dict[str, Any],
    *,
    ed25519_private_key: Ed25519PrivateKey,
    mldsa44_secret_key: bytes,
    ed25519_verification_method: str,
    mldsa44_verification_method: Optional[str] = None,
    proof_purpose: str = "assertionMethod",
    created: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build a proof set and return the credential with it attached under
    `proof`, replacing any existing proof."""
    proofs = build_dual_proof(
        credential,
        ed25519_private_key=ed25519_private_key,
        mldsa44_secret_key=mldsa44_secret_key,
        ed25519_verification_method=ed25519_verification_method,
        mldsa44_verification_method=mldsa44_verification_method,
        proof_purpose=proof_purpose,
        created=created,
    )
    signed = data_integrity.unsecured_document(credential)
    signed["proof"] = proofs
    return signed


def verify_dual(
    credential: Dict[str, Any],
    *,
    ed25519_public_key: Ed25519PublicKey,
    mldsa44_public_key: bytes,
) -> bool:
    """Verify a proof set: both the Ed25519 and the ML-DSA-44 proof in the
    `proof` array MUST validate. Returns True only if both are present and
    valid. Raises ValueError on a malformed proof structure."""
    ml_dsa_44 = _import_pqcrypto()

    proofs = credential.get("proof")
    if not isinstance(proofs, list):
        raise ValueError("A dual proof requires a proof array")
    base = data_integrity.unsecured_document(credential)

    # Every recognized proof in the set must verify, not just one of each kind,
    # so a set carrying a good proof next to a bad one is rejected.
    ed_ok = False
    ml_ok = False
    for proof in proofs:
        if not isinstance(proof, dict):
            continue
        cryptosuite = proof.get("cryptosuite")
        if cryptosuite == CRYPTOSUITE_EDDSA:
            candidate = dict(base)
            candidate["proof"] = proof
            if not data_integrity.verify_proof(candidate, ed25519_public_key):
                return False
            ed_ok = True
        elif cryptosuite in (CRYPTOSUITE_MLDSA44, CRYPTOSUITE_MLDSA44_LEGACY):
            proof_value = proof.get("proofValue")
            if not isinstance(proof_value, str):
                raise ValueError("ML-DSA proof missing proofValue")
            # Accept the specified base64url-nopad encoding, and the
            # pre-alignment base58btc encoding for credentials already issued.
            if proof_value.startswith("u"):
                ml_sig = _b64u_decode(proof_value[1:])
            elif proof_value.startswith("z"):
                ml_sig = _b58decode(proof_value[1:])
            else:
                raise ValueError("proofValue must be multibase base64url (u) or base58btc (z)")
            unsigned = {k: v for k, v in proof.items() if k != "proofValue"}
            verified = _mldsa44_verify(
                ml_dsa_44,
                mldsa44_public_key,
                data_integrity.hash_data(base, unsigned),
                ml_sig,
            )
            if not verified:
                # Fall back to the pre-alignment signing input.
                verified = _mldsa44_verify(
                    ml_dsa_44,
                    mldsa44_public_key,
                    data_integrity.legacy_proof_digest(base, unsigned),
                    ml_sig,
                )
            if not verified:
                return False
            ml_ok = True
    # Both members must be PRESENT: a set carrying only the classical proof does
    # not verify, so a credential cannot silently drop the post-quantum proof.
    return ed_ok and ml_ok


def build_hybrid_proof(
    credential: Dict[str, Any],
    *,
    ed25519_private_key: Ed25519PrivateKey,
    mldsa44_secret_key: bytes,
    verification_method: str,
    proof_purpose: str = "assertionMethod",
    created: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build a v1.6.x composite proof (a single proof whose proofValue is
    base58btc(ed25519_sig || mldsa44_sig)) for `credential`, using the
    pre-alignment signing input that format was issued under.

    Verify-only wire format: retained so the older shape can be reproduced for
    regression checks against credentials issued under v1.6.x. New credentials
    use :func:`build_dual_proof`, which emits a proof set.
    """
    ml_dsa_44 = _import_pqcrypto()

    proof: Dict[str, Any] = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE_HYBRID_EDDSA_MLDSA44,
        "created": _format_iso8601(created or datetime.now(timezone.utc)),
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }

    # The composite format signs the pre-alignment 32-byte digest.
    digest = data_integrity.legacy_proof_digest(credential, proof)

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
    """Verify a v1.6.x composite proof (single proof, concatenated proofValue)
    against the pre-alignment signing input that format was issued under.

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

    # Reconstruct the pre-alignment signing input.
    proof_without_value = {k: v for k, v in proof.items() if k != "proofValue"}
    digest = data_integrity.legacy_proof_digest(credential, proof_without_value)

    # Classical Ed25519 verification.
    try:
        ed25519_public_key.verify(ed_sig, digest)
    except InvalidSignature:
        return False

    # Post-quantum ML-DSA-44 verification.
    return _mldsa44_verify(ml_dsa_44, mldsa44_public_key, digest, ml_sig)


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


def _b64u_encode(raw: bytes) -> str:
    """Multibase base64url-nopad body."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode(body: str) -> bytes:
    padding = "=" * (-len(body) % 4)
    try:
        return base64.urlsafe_b64decode(body + padding)
    except Exception as exc:
        raise ValueError(f"bad base64url proofValue: {exc}") from exc


def _mldsa44_verify(ml_dsa_44: Any, public_key: bytes, message: bytes, signature: bytes) -> bool:
    # pqcrypto's verify raises on an invalid signature in some builds; treat
    # any exception as a verification failure.
    try:
        return bool(ml_dsa_44.verify(public_key, message, signature))
    except Exception:
        return False


def _format_iso8601(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
