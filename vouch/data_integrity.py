"""
Data Integrity proof builder and verifier, `eddsa-jcs-2022` cryptosuite.

Implements §3.1 of [VC-DI-EDDSA]:
 https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022

The cryptosuite produces a `DataIntegrityProof` object that attaches alongside
the credential payload as a sibling `proof` property. No JWS, no JOSE, no Base64
wrapping of the payload, so the credential remains human-readable JSON.

Signing flow (the W3C Data Integrity hashing algorithm, so proofs issued here
verify under any conformant `eddsa-jcs-2022` implementation):
  1. Build the proof configuration: the unsigned proof (no proofValue) plus the
     document's `@context`, and JCS-canonicalize it (RFC 8785).
  2. JCS-canonicalize the unsecured document (the credential with no proof).
  3. hashData = SHA-256(canonical proof configuration)
                || SHA-256(canonical document)   (64 bytes, config first).
  4. Ed25519-sign hashData.
  5. proofValue = "z" + base58btc(signature).

Verification recomputes hashData, and also accepts the pre-alignment signing
input (a single SHA-256 over the JCS form of the credential with the unsigned
proof attached) so credentials issued before this alignment keep verifying.
See :func:`legacy_proof_digest`.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import jcs
from .multikey import _b58decode, _b58encode


CRYPTOSUITE_ID = "eddsa-jcs-2022"
PROOF_TYPE = "DataIntegrityProof"

# A signer is either a raw Ed25519 private key (signs in process) or any callable
# that takes the signing input bytes and returns the 64-byte Ed25519 signature.
# The callable form lets the actual key live somewhere the process cannot read
# it: an OS secure element, a sidecar, a cloud KMS/HSM, or an MPC quorum.
Signer = Union[Ed25519PrivateKey, Callable[[bytes], bytes]]


def unsecured_document(credential: Dict[str, Any]) -> Dict[str, Any]:
    """Strip any `proof` member, yielding the unsecured document."""
    if not isinstance(credential, dict):
        raise ValueError("credential must be a JSON object")
    return {k: v for k, v in credential.items() if k != "proof"}


def proof_configuration(document: Dict[str, Any], unsigned_proof: Dict[str, Any]) -> Dict[str, Any]:
    """Build the proof configuration: the unsigned proof carrying the document's
    `@context`, per the Data Integrity proof configuration algorithm."""
    config = {k: v for k, v in unsigned_proof.items() if k != "proofValue"}
    if "@context" in document:
        config["@context"] = document["@context"]
    return config


def hash_data(credential: Dict[str, Any], unsigned_proof: Dict[str, Any]) -> bytes:
    """Compute the 64-byte W3C Data Integrity signing input for a JCS
    cryptosuite: SHA-256 of the canonical proof configuration, joined with
    SHA-256 of the canonical unsecured document. This is the value that gets
    signed."""
    document = unsecured_document(credential)
    config = proof_configuration(document, unsigned_proof)
    config_hash = hashlib.sha256(jcs.canonicalize(config)).digest()
    document_hash = hashlib.sha256(jcs.canonicalize(document)).digest()
    return config_hash + document_hash


def legacy_proof_digest(credential: Dict[str, Any], unsigned_proof: Dict[str, Any]) -> bytes:
    """The pre-alignment signing input: a single SHA-256 over the JCS canonical
    form of the credential with the unsigned proof attached. Retained so
    credentials issued before the Data Integrity alignment continue to verify.
    Never used for new proofs."""
    if not isinstance(credential, dict):
        raise ValueError("credential must be a JSON object")
    with_proof = dict(credential)
    with_proof["proof"] = {k: v for k, v in unsigned_proof.items() if k != "proofValue"}
    return hashlib.sha256(jcs.canonicalize(with_proof)).digest()


def build_proof(
    credential: Dict[str, Any],
    private_key: Signer,
    verification_method: str,
    proof_purpose: str = "assertionMethod",
    created: datetime | None = None,
) -> Dict[str, Any]:
    """
    Generate a Data Integrity proof object for `credential`.

    `private_key` is either an Ed25519 private key (signed in process) or a
    callable `sign(signing_input: bytes) -> bytes` that produces the Ed25519
    signature over the signing input without exposing the key to this process.
    Returns the proof dict (caller attaches it to the credential).

    Conforms to eddsa-jcs-2022 §3.1.
    """
    proof = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE_ID,
        "created": _format_iso8601(created or datetime.now(timezone.utc)),
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }

    # The 64-byte Data Integrity signing input: SHA-256 of the canonical proof
    # configuration, then SHA-256 of the canonical unsecured document.
    signing_input = hash_data(credential, proof)

    if isinstance(private_key, Ed25519PrivateKey):
        signature = private_key.sign(signing_input)
    elif callable(private_key):
        signature = private_key(signing_input)
    else:
        raise TypeError(
            "private_key must be an Ed25519PrivateKey or a sign(signing_input) callable"
        )

    proof["proofValue"] = "z" + _b58encode(signature)
    return proof


def verify_proof(credential: Dict[str, Any], public_key: Ed25519PublicKey) -> bool:
    """
    Verify a Data Integrity proof attached to `credential`.

    Checks the signature against the 64-byte Data Integrity signing input, and
    falls back to the pre-alignment 32-byte digest so credentials issued before
    the alignment still verify.

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

    # Reconstruct the signing input by removing proofValue from the proof
    # (keeping all other proof fields).
    proof_without_value = {k: v for k, v in proof.items() if k != "proofValue"}

    try:
        public_key.verify(signature, hash_data(credential, proof_without_value))
        return True
    except InvalidSignature:
        pass

    # Fall back to the pre-alignment signing input so credentials issued before
    # the Data Integrity alignment still verify.
    try:
        public_key.verify(signature, legacy_proof_digest(credential, proof_without_value))
        return True
    except InvalidSignature:
        return False


def _format_iso8601(dt: datetime) -> str:
    # VC requires XML Schema dateTime, and RFC 3339 with a `Z` suffix is acceptable.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
