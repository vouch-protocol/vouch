"""
Inference provenance: bind an agent's output to the model and context that
produced it.

Reasoned Action Proofs (vouch.reasoning) prove an agent stated *why* it acted.
This proves the action actually *came from* this model processing this context,
the closest the protocol gets to verifying the computation behind a decision.
Alongside its output, an agent commits to:

  - ``modelWeightsHash``: a fingerprint of the exact model weights (PAD-043). A
    fine-tuned, quantized, or swapped model produces a different hash.
  - ``contextRoot``: a Merkle root over the full retrieved context or prompt
    (PAD-045), so a verifier can re-fetch the sources and confirm the agent did
    not fabricate, cherry-pick, or silently substitute them.
  - ``sampler``: the seed and decoding parameters, so the run is reproducible.
  - ``runtimeAttestation``: optional evidence (for example a TEE quote) of the
    runtime that executed the model.

A verifier can then (a) recompute the context root from the presented context
and confirm it matches, catching confabulation and substitution, and (b) with
the model, context, and seed, re-execute and byte-compare the output
(deterministic replay). This does not read the model's mind; it makes the
provenance of a decision reproducible and its inputs non-repudiable. It is the
on-protocol form of the methods disclosed in PAD-043 and PAD-045, and the anchor
point for zero-knowledge proofs of inference later. Everything here is an ordinary
``eddsa-jcs-2022`` Verifiable Credential and verifies across the language SDKs.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import data_integrity
from .jcs import canonicalize
from .merkle import compute_action_merkle_root

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"

PROVENANCE_TYPE = "InferenceProvenanceCredential"
DIGEST_ALGORITHM = "sha-256-jcs"

# Structured verification reasons (stable strings, mirrored by the SDKs).
REASON_INVALID_PROOF = "invalid_proof"
REASON_NOT_PROVENANCE = "not_inference_provenance"
REASON_MISSING_BINDING = "missing_binding"
REASON_CONTEXT_ROOT_MISMATCH = "context_root_mismatch"
REASON_OUTPUT_MISMATCH = "output_mismatch"
REASON_WEIGHTS_MISMATCH = "weights_mismatch"


class ProvenanceError(Exception):
    """Raised on malformed inference-provenance input."""


# ---------------------------------------------------------------------------
# Low-level helpers (kept local so the module stands alone, matching the other
# accountable-autonomy modules)
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mb64(b: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise ProvenanceError("signing requires a Signer with an Ed25519 key")
    return raw


def _attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    credential["proof"] = data_integrity.build_proof(
        credential, _raw_priv(signer), signer.verification_method_id()
    )
    return credential


def _type_list(credential: Dict[str, Any]) -> list:
    t = credential.get("type") or []
    return [t] if isinstance(t, str) else list(t)


def _to_bytes(value: Any) -> bytes:
    """Canonical bytes of an output or context chunk, for content addressing."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, dict):
        return canonicalize(value)
    raise ProvenanceError("output and context chunks must be a dict, str, or bytes")


def output_digest(output: Any) -> str:
    """Multibase SHA-256 of an output (the generated text or the decided action)."""
    return _mb64(hashlib.sha256(_to_bytes(output)).digest())


def context_root(chunks: Sequence[Any]) -> str:
    """
    Multibase Merkle root over the ordered context chunks (retrieved documents,
    prompt segments). A verifier that re-fetches the same sources recomputes the
    identical root; a fabricated or substituted chunk changes it.
    """
    if not chunks:
        raise ProvenanceError("context_root needs at least one chunk")
    return compute_action_merkle_root([_to_bytes(c) for c in chunks])


def weights_hash(weights: Any) -> str:
    """Multibase SHA-256 of a model's weight bytes. For large models the caller
    typically computes this once at load time and passes the string directly."""
    return _mb64(hashlib.sha256(_to_bytes(weights)).digest())


# ---------------------------------------------------------------------------
# Issue an inference-provenance credential
# ---------------------------------------------------------------------------


def sign_inference_provenance(
    signer: Any,
    *,
    output: Any,
    model_weights_hash: Optional[str] = None,
    context_chunks: Optional[Sequence[Any]] = None,
    context_root_value: Optional[str] = None,
    sampler: Optional[Dict[str, Any]] = None,
    runtime_attestation: Optional[Dict[str, Any]] = None,
    include_output: bool = True,
    valid_from: Optional[datetime] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Issue an ``InferenceProvenanceCredential`` binding an output to its model and
    context.

    Args:
        signer: The acting agent's ``Signer``.
        output: The generated output or decided action (dict, str, or bytes). Its
            digest is always recorded; the plaintext is included unless
            ``include_output`` is False.
        model_weights_hash: Multibase fingerprint of the model weights (PAD-043).
        context_chunks: The ordered context; its Merkle root is computed and
            recorded (PAD-045). Supply this or ``context_root_value``.
        context_root_value: A precomputed context root, when the chunks are large
            or already content-addressed.
        sampler: Decoding parameters (``seed``, ``temperature``, ``topP``, ...)
            that make the run reproducible.
        runtime_attestation: Optional evidence of the executing runtime.
        include_output: If False, publish only the output digest.
        valid_from: Issuance time (defaults to now, UTC).
        credential_id: Optional credential id (defaults to a ``urn:uuid``).

    At least one binding (model weights hash or context root) is required.
    """
    root = context_root_value
    if context_chunks is not None:
        root = context_root(context_chunks)
    if not model_weights_hash and not root:
        raise ProvenanceError("provide model_weights_hash and/or a context root")

    provenance: Dict[str, Any] = {}
    if model_weights_hash:
        provenance["modelWeightsHash"] = model_weights_hash
    if root:
        provenance["contextRoot"] = {"algorithm": "merkle-sha-256", "root": root}
    if sampler:
        provenance["sampler"] = dict(sampler)
    if runtime_attestation:
        provenance["runtimeAttestation"] = dict(runtime_attestation)

    subject: Dict[str, Any] = {
        "outputDigest": {"algorithm": DIGEST_ALGORITHM, "digest": output_digest(output)},
        "provenance": provenance,
    }
    if include_output:
        # Store an independent snapshot so the credential is not aliased to the
        # caller's object (and its digest and output can never drift apart).
        subject["output"] = copy.deepcopy(output)

    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", PROVENANCE_TYPE],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    return _attach_proof(credential, signer)


def verify_inference_provenance(
    credential: Dict[str, Any], public_key: Any
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Verify an inference-provenance credential's proof and structure. Returns
    ``(ok, credentialSubject)``. Structural validity requires an output digest and
    at least one binding (model weights hash or context root).
    """
    from vouch.verifier import _coerce_ed25519_public_key

    if PROVENANCE_TYPE not in _type_list(credential):
        return False, None
    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return False, None
    except ValueError:
        return False, None

    subject = credential.get("credentialSubject") or {}
    if not (subject.get("outputDigest") or {}).get("digest"):
        return False, None
    prov = subject.get("provenance") or {}
    if not prov.get("modelWeightsHash") and not (prov.get("contextRoot") or {}).get("root"):
        return False, None
    return True, subject


def verify_context(
    context_chunks: Sequence[Any], credential_subject: Dict[str, Any]
) -> Tuple[bool, Optional[str]]:
    """
    Recompute the context root from re-fetched context and confirm it matches the
    committed root, so a fabricated, cherry-picked, or substituted context is
    detectable. Returns ``(True, None)`` or ``(False, reason)``.
    """
    committed = ((credential_subject.get("provenance") or {}).get("contextRoot") or {}).get("root")
    if not committed:
        return False, REASON_MISSING_BINDING
    try:
        if context_root(context_chunks) != committed:
            return False, REASON_CONTEXT_ROOT_MISMATCH
    except ProvenanceError:
        return False, REASON_CONTEXT_ROOT_MISMATCH
    return True, None


def check_replay(
    credential_subject: Dict[str, Any],
    *,
    output: Any = None,
    model_weights_hash: Optional[str] = None,
) -> Optional[str]:
    """
    Compare an auditor's re-execution against the committed provenance; return None
    if every supplied check passes, else a structured reason.

    Pass ``output`` (the output produced by re-running the model on the same
    context and seed) to confirm it byte-matches the committed output digest, and
    ``model_weights_hash`` (recomputed from the model in hand) to confirm the model
    is the one that was committed.
    """
    subject = credential_subject or {}
    if output is not None:
        committed = (subject.get("outputDigest") or {}).get("digest")
        if output_digest(output) != committed:
            return REASON_OUTPUT_MISMATCH
    if model_weights_hash is not None:
        committed_w = (subject.get("provenance") or {}).get("modelWeightsHash")
        if model_weights_hash != committed_w:
            return REASON_WEIGHTS_MISMATCH
    return None


__all__ = [
    "ProvenanceError",
    "PROVENANCE_TYPE",
    "output_digest",
    "context_root",
    "weights_hash",
    "sign_inference_provenance",
    "verify_inference_provenance",
    "verify_context",
    "check_replay",
]
