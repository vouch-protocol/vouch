"""
Post-quantum signing for robot credentials.

A robot fielded today lives for ten to twenty years, longer than classical
Ed25519 is expected to stay safe, so a robot identity signed now could be forged
once a quantum computer arrives. This module makes the hybrid post-quantum
cryptosuite (`hybrid-eddsa-mldsa44-jcs-2026`, a classical Ed25519 signature
alongside an ML-DSA-44 signature) the recommended default for robot credentials,
so they stay unforgeable across the robot's whole service life.

  - sign_pq: attach a hybrid proof to a robot credential.
  - verify_robot_credential: verify a robot credential whether it carries a
    classical or a hybrid proof, auto-detected from the proof, so a fleet can move
    to PQ gradually without breaking the classical credentials already in the field.
  - migrate_to_pq: re-sign a fielded robot's classical credential under PQ.

This is the open layer: hybrid signing, backward-compatible verification, and a
software re-signing migration path. Managed PQ key custody and fleet-wide PQ
migration orchestration are out of scope for the open layer.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .. import data_integrity, data_integrity_hybrid, multikey
from ..verifier import _coerce_ed25519_public_key
from .identity import RoboticsError

CLASSICAL_CRYPTOSUITE = "eddsa-jcs-2022"
HYBRID_CRYPTOSUITE = data_integrity_hybrid.CRYPTOSUITE_HYBRID_EDDSA_MLDSA44


def _mldsa44_secret(signer: Any) -> bytes:
    # public_key_mldsa44() lazily generates the ML-DSA-44 keypair if needed.
    signer.public_key_mldsa44()
    secret = getattr(signer, "_mldsa44_secret", None)
    if secret is None:
        raise RoboticsError("PQ signing requires a Signer with an ML-DSA-44 key")
    return secret


def _coerce_mldsa44_public(public_key: Any) -> bytes:
    if isinstance(public_key, (bytes, bytearray)):
        return bytes(public_key)
    if isinstance(public_key, str):
        alg, raw = multikey.decode(public_key)
        if "mldsa" not in alg.lower() and "ml-dsa" not in alg.lower():
            raise RoboticsError(f"expected an ML-DSA-44 multikey, got {alg}")
        return raw
    raise RoboticsError("ML-DSA-44 public key must be raw bytes or a Multikey string")


def sign_pq(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    """
    Attach a hybrid (classical Ed25519 plus post-quantum ML-DSA-44) Data Integrity
    proof to a pre-built robot `credential`. Any existing proof is replaced.
    """
    raw_priv = getattr(signer, "_raw_priv", None)
    if raw_priv is None:
        raise RoboticsError("PQ signing requires a Signer with an Ed25519 key")
    body = {k: v for k, v in credential.items() if k != "proof"}
    proof = data_integrity_hybrid.build_hybrid_proof(
        body,
        ed25519_private_key=raw_priv,
        mldsa44_secret_key=_mldsa44_secret(signer),
        verification_method=signer.verification_method_id(),
    )
    body["proof"] = proof
    return body


def is_pq(credential: Dict[str, Any]) -> bool:
    """Return True if `credential` carries a hybrid post-quantum proof."""
    proof = credential.get("proof") or {}
    return proof.get("cryptosuite") == HYBRID_CRYPTOSUITE


def verify_pq(
    credential: Dict[str, Any],
    ed25519_public_key: Any,
    mldsa44_public_key: Any,
) -> bool:
    """
    Verify a hybrid robot credential. Both the Ed25519 and the ML-DSA-44 signature
    must validate. `mldsa44_public_key` is raw bytes or a Multikey string.
    """
    resolved_ed = _coerce_ed25519_public_key(ed25519_public_key)
    if resolved_ed is None:
        return False
    try:
        resolved_ml = _coerce_mldsa44_public(mldsa44_public_key)
    except RoboticsError:
        return False
    try:
        return data_integrity_hybrid.verify_hybrid_proof(
            credential,
            ed25519_public_key=resolved_ed,
            mldsa44_public_key=resolved_ml,
        )
    except ValueError:
        return False


def verify_robot_credential(
    credential: Dict[str, Any],
    ed25519_public_key: Any,
    *,
    mldsa44_public_key: Optional[Any] = None,
) -> bool:
    """
    Verify a robot credential whether it carries a classical or a hybrid proof,
    auto-detected from the proof cryptosuite. A hybrid credential requires
    `mldsa44_public_key`; a classical credential ignores it. This is the
    backward-compatible verify a fleet uses while migrating to PQ.
    """
    if is_pq(credential):
        if mldsa44_public_key is None:
            return False
        return verify_pq(credential, ed25519_public_key, mldsa44_public_key)
    resolved_ed = _coerce_ed25519_public_key(ed25519_public_key)
    if resolved_ed is None:
        return False
    try:
        return data_integrity.verify_proof(credential, resolved_ed)
    except ValueError:
        return False


def migrate_to_pq(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    """
    Re-sign a fielded robot's classical `credential` under the hybrid PQ
    cryptosuite, preserving its body. The signer holds the robot's current key.
    """
    return sign_pq(credential, signer)


__all__ = [
    "CLASSICAL_CRYPTOSUITE",
    "HYBRID_CRYPTOSUITE",
    "sign_pq",
    "is_pq",
    "verify_pq",
    "verify_robot_credential",
    "migrate_to_pq",
]
