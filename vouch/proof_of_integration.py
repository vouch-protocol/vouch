"""
Proof-of-Integration recognition primitive (PAD-072).

A recognition credential, for example a badge attesting that an independent
system integrates a protocol, is normally issued on the issuer's assertion or on
a one-time manual review. Such a credential says an integration exists but does
not prove that the recognized party operates a working, keyed deployment. This
module supplies the challenge-response primitive that gates issuance on
demonstrated capability instead.

Before recognizing a candidate, the authority generates a fresh nonce
(:func:`build_integration_challenge`) naming the live surface and the capability
to demonstrate. The candidate answers over its own protocol surface
(:func:`answer_integration_challenge`) with an eddsa-jcs-2022 Verifiable
Credential whose subject binds the nonce, the responder DID, and a digest of the
probed artifact, signed by the key bound to the candidate's claimed DID. The
authority verifies the response against the candidate's key
(:func:`verify_integration_response`), confirms the nonce and DID, and, when an
artifact was probed, recomputes and compares its digest.

:func:`proof_of_integration_block` distils a verified response into a small
block (nonce, response digest, surface, verification method, observation time)
that a recognition credential can embed in its subject, so the capability proof
stays independently re-verifiable long after issuance against the candidate's
own DID.

The challenge, response, and embedded block all use the shared RFC 8785 JCS
canonicalization and the same digest helper the rest of the SDK uses, so the
same proof verifies across the language SDKs.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import data_integrity
from .accountability import _mb64, commitment_digest

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"

CHALLENGE_TYPE = "IntegrationChallenge"
RESPONSE_TYPE = "IntegrationResponseCredential"


class ProofOfIntegrationError(Exception):
    """Raised on malformed proof-of-integration input."""


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _raw_priv_from_jwk(private_key: str) -> Ed25519PrivateKey:
    """Derive the raw Ed25519 private key from a JWK JSON string.

    The response is signed by the candidate's own DID-bound key, so this module
    accepts the private JWK directly rather than a constructed Signer.
    """
    if not private_key or not isinstance(private_key, str):
        raise ProofOfIntegrationError("private_key must be a JWK JSON string")
    from jwcrypto import jwk
    from jwcrypto.common import base64url_decode

    try:
        key = jwk.JWK.from_json(private_key)
        if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
            raise ProofOfIntegrationError("private_key must be an Ed25519 JWK (OKP, crv=Ed25519)")
        seed = key.get("d")
        if not seed:
            raise ProofOfIntegrationError("private_key JWK has no private component 'd'")
        return Ed25519PrivateKey.from_private_bytes(base64url_decode(seed))
    except ProofOfIntegrationError:
        raise
    except Exception as exc:
        raise ProofOfIntegrationError(f"invalid Ed25519 private JWK: {exc}") from exc


def _artifact_digest(artifact: Optional[Dict[str, Any]]) -> str:
    """Multibase SHA-256 over the JCS-canonical form of `artifact`.

    Uses the same digest helper the rest of the SDK uses so the digest is
    reproducible across languages. Returns the empty-object digest when no
    artifact is probed, so the field is always present and checkable.
    """
    subject = artifact if artifact is not None else {}
    if not isinstance(subject, dict):
        raise ProofOfIntegrationError("artifact must be a JSON object")
    return _mb64(commitment_digest(subject))


def _verification_method_id(did: str) -> str:
    return f"{did}#key-1"


# ---------------------------------------------------------------------------
# Challenge
# ---------------------------------------------------------------------------


def build_integration_challenge(
    surface: str,
    capability: str,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an integration challenge.

    Args:
        surface: The expected live-surface locator the candidate answers from.
        capability: The capability descriptor the candidate must demonstrate.
        nonce: Optional explicit nonce. A fresh 32-byte CSPRNG hex nonce is
            generated when none is supplied.

    Returns:
        ``{"nonce", "surface", "capability"}``.
    """
    if not surface or not isinstance(surface, str):
        raise ProofOfIntegrationError("surface is required")
    if not capability or not isinstance(capability, str):
        raise ProofOfIntegrationError("capability is required")
    return {
        "nonce": nonce or secrets.token_hex(32),
        "surface": surface,
        "capability": capability,
    }


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------


def answer_integration_challenge(
    challenge: Dict[str, Any],
    *,
    private_key: str,
    did: str,
    artifact: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Answer an integration challenge with a signed response credential.

    The candidate returns an eddsa-jcs-2022 Verifiable Credential whose subject
    binds the challenge nonce, the responder DID, and a digest of the probed
    artifact, signed by the key bound to the candidate's claimed DID.

    Args:
        challenge: The challenge from :func:`build_integration_challenge`.
        private_key: The candidate's Ed25519 private key as a JWK JSON string.
        did: The candidate's claimed DID.
        artifact: Optional protocol artifact of the recognized type. Its
            multibase SHA-256 (over the JCS form) is bound into the response.

    Returns:
        The signed IntegrationResponseCredential.
    """
    if not isinstance(challenge, dict):
        raise ProofOfIntegrationError("challenge must be a JSON object")
    nonce = challenge.get("nonce")
    if not nonce:
        raise ProofOfIntegrationError("challenge is missing a nonce")
    if not did or not isinstance(did, str):
        raise ProofOfIntegrationError("did is required")

    raw_priv = _raw_priv_from_jwk(private_key)
    issued = datetime.now(timezone.utc)

    subject: Dict[str, Any] = {
        "id": did,
        "nonce": nonce,
        "surface": challenge.get("surface"),
        "capability": challenge.get("capability"),
        "artifactDigest": _artifact_digest(artifact),
    }

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", RESPONSE_TYPE],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuer": did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    credential["proof"] = data_integrity.build_proof(
        credential,
        private_key=raw_priv,
        verification_method=_verification_method_id(did),
    )
    return credential


def verify_integration_response(
    response: Dict[str, Any],
    challenge: Dict[str, Any],
    *,
    public_key: str,
    artifact: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Verify an integration response against a challenge.

    Verifies the Data Integrity proof against `public_key`, confirms the
    embedded nonce matches the challenge, confirms the responder DID is
    consistent between the subject and the proof's verification method, and,
    when an artifact is supplied, recomputes and compares its digest.

    Args:
        response: The IntegrationResponseCredential to verify.
        challenge: The originating challenge.
        public_key: The candidate's public key (Multikey or JWK string).
        artifact: Optional probed artifact to recompute the digest against.

    Returns:
        ``(ok, details)``. `details` carries ``nonce``, ``did``, ``surface``,
        ``capability``, ``artifactDigest``, and ``artifactMatch`` when known.
    """
    from vouch.verifier import _coerce_ed25519_public_key

    details: Dict[str, Any] = {}
    if not isinstance(response, dict) or not isinstance(challenge, dict):
        return False, details

    t = response.get("type") or []
    types = [t] if isinstance(t, str) else list(t)
    if RESPONSE_TYPE not in types:
        return False, details

    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, details
    try:
        if not data_integrity.verify_proof(response, resolved):
            return False, details
    except ValueError:
        return False, details

    subject = response.get("credentialSubject") or {}
    if not isinstance(subject, dict):
        return False, details

    nonce = subject.get("nonce")
    did = subject.get("id")
    surface = subject.get("surface")
    capability = subject.get("capability")
    artifact_digest = subject.get("artifactDigest")

    details = {
        "nonce": nonce,
        "did": did,
        "surface": surface,
        "capability": capability,
        "artifactDigest": artifact_digest,
    }

    # The embedded nonce must match the challenge nonce (freshness / anti-replay).
    if not nonce or nonce != challenge.get("nonce"):
        return False, details

    # The responder DID must be consistent with the proof's verification method,
    # so the response proves control of the claimed DID's key.
    proof = response.get("proof") or {}
    vm = proof.get("verificationMethod") if isinstance(proof, dict) else None
    if not did or not isinstance(vm, str) or vm.split("#", 1)[0] != did:
        return False, details

    # The response is signed over the issuer field too; keep it consistent.
    issuer = response.get("issuer")
    if issuer != did:
        return False, details

    # When the artifact is supplied, recompute and compare the bound digest.
    if artifact is not None:
        expected = _artifact_digest(artifact)
        details["artifactMatch"] = expected == artifact_digest
        if not details["artifactMatch"]:
            return False, details

    return True, details


# ---------------------------------------------------------------------------
# Embeddable recognition block
# ---------------------------------------------------------------------------


def proof_of_integration_block(
    response: Dict[str, Any],
    challenge: Dict[str, Any],
) -> Dict[str, Any]:
    """Distil a verified response into a block for a recognition credential.

    The returned block carries the challenge nonce, a multibase digest of the
    signed response, the probed surface locator, the verification-method
    identifier used, and the observation time, so the capability proof stays
    independently re-verifiable against the candidate's DID after issuance.

    Args:
        response: The IntegrationResponseCredential (should be verified first).
        challenge: The originating challenge.

    Returns:
        ``{"nonce", "responseDigest", "surface", "verificationMethod",
        "observedAt"}``.
    """
    if not isinstance(response, dict) or not isinstance(challenge, dict):
        raise ProofOfIntegrationError("response and challenge must be JSON objects")

    proof = response.get("proof") or {}
    vm = proof.get("verificationMethod") if isinstance(proof, dict) else None
    subject = response.get("credentialSubject") or {}

    return {
        "nonce": challenge.get("nonce"),
        "responseDigest": _mb64(commitment_digest(response)),
        "surface": subject.get("surface") or challenge.get("surface"),
        "verificationMethod": vm,
        "observedAt": _iso(datetime.now(timezone.utc)),
    }


__all__ = [
    "CHALLENGE_TYPE",
    "RESPONSE_TYPE",
    "ProofOfIntegrationError",
    "build_integration_challenge",
    "answer_integration_challenge",
    "verify_integration_response",
    "proof_of_integration_block",
]
