"""Client for the signing sidecar.

The sidecar holds the agent's signing key. This process never sees it. This
module shapes intents, asks the sidecar to sign them, and verifies what comes
back against the sidecar's published DID document before anything is acted on.
"""

from __future__ import annotations

import hashlib
from typing import Any

import httpx

from vouch import Verifier, multikey

from .config import CONFIG

ALLOWED_ACTIONS = frozenset({"answer_question", "generate_starter", "sign_sample"})


class SignerError(RuntimeError):
    pass


def validate_intent(intent: dict[str, Any]) -> None:
    for key in ("action", "target", "resource"):
        if not intent.get(key):
            raise SignerError(f"intent.{key} is required")
    if intent["action"] not in ALLOWED_ACTIONS:
        raise SignerError(f"action {intent['action']!r} not in allow-list")


def digest(text: str) -> str:
    """SHA-256 digest of UTF-8 text, in the form carried in an intent."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


async def sign_intent(
    intent: dict[str, Any], *, valid_seconds: int | None = None
) -> dict[str, Any]:
    validate_intent(intent)
    payload: dict[str, Any] = {"intent": intent}
    if valid_seconds is not None:
        payload["valid_seconds"] = valid_seconds
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(f"{CONFIG.sidecar_url}/sign", json=payload)
    except httpx.HTTPError as exc:
        raise SignerError(f"sidecar unreachable: {exc}") from exc
    if resp.status_code >= 400:
        raise SignerError(f"sidecar returned {resp.status_code}: {resp.text}")
    return resp.json()


async def did_document() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{CONFIG.sidecar_url}/did-document")
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPError as exc:
        raise SignerError(f"sidecar unreachable: {exc}") from exc


def _public_key_from_document(document: dict[str, Any], vm_id: str | None) -> Any:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    for vm in document.get("verificationMethod", []):
        if vm_id and vm.get("id") != vm_id:
            continue
        alg, raw = multikey.decode(vm["publicKeyMultibase"])
        if alg == "Ed25519":
            return Ed25519PublicKey.from_public_bytes(raw)
    raise SignerError("no Ed25519 verification method matches the proof")


async def verify(credential: dict[str, Any], expected_intent: dict[str, Any]) -> None:
    """Verify a credential from the sidecar before acting on it.

    Checks the proof against the key in the sidecar's DID document, that the
    issuer is the agent's DID, and that the signed intent is exactly the
    intent that was requested.

    Raises:
        SignerError: if any check fails.
    """
    document = await did_document()
    if credential.get("issuer") != document.get("id"):
        raise SignerError("credential issuer is not the agent DID")
    proof = credential.get("proof") or {}
    key = _public_key_from_document(document, proof.get("verificationMethod"))
    ok, _ = Verifier.verify(credential, public_key=key)
    if not ok:
        raise SignerError("credential failed verification")
    if credential.get("credentialSubject", {}).get("intent") != expected_intent:
        raise SignerError("signed intent differs from the requested intent")


async def sign_and_verify(
    intent: dict[str, Any], *, valid_seconds: int | None = None
) -> dict[str, Any]:
    credential = await sign_intent(intent, valid_seconds=valid_seconds)
    await verify(credential, intent)
    return credential


async def sidecar_did() -> str:
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(f"{CONFIG.sidecar_url}/did")
        resp.raise_for_status()
        return resp.json().get("did", CONFIG.agent_did)


async def sidecar_healthy() -> bool:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{CONFIG.sidecar_url}/health")
            return resp.status_code == 200
    except httpx.HTTPError:
        return False
