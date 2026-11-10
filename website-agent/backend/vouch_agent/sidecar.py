"""Signing sidecar for the Vouch website agent.

This process holds the agent's signing key. The chat process, which talks
to the language model, never has it: it asks this process to sign an
intent over localhost HTTP and gets back a credential.

Endpoints:
    GET  /health        liveness plus the agent DID
    GET  /did           the agent DID
    GET  /did-document  the DID document (Multikey), served publicly by the
                        chat process at /.well-known/did.json
    POST /sign          sign an intent that passes this process's own policy

The sidecar enforces policy itself (allowed actions, resource prefix,
validity window) rather than trusting the caller. A compromised chat process
can ask for signatures, but only for the narrow set of intents this process
is willing to sign.

Key handling:
    Production reads a private Ed25519 JWK from VOUCH_AGENT_SIGNING_KEY and
    refuses to start without one. ``--dev`` generates an ephemeral key for
    local development. ``--generate-key`` prints a fresh private JWK to
    stdout for storing as a deployment secret. ``--did-document`` prints the
    public DID document for the key in VOUCH_AGENT_SIGNING_KEY, for
    publishing where the DID resolves (for the default DID,
    https://vouch-protocol.com/assistant/did.json). It never prints the
    private key.

Run:
    python -m vouch_agent.sidecar                 # production, key from env
    python -m vouch_agent.sidecar --dev           # local, ephemeral key
    python -m vouch_agent.sidecar --generate-key  # print a new key and exit
    python -m vouch_agent.sidecar --did-document  # print the public DID document
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from vouch import Signer, multikey
from vouch.keys import generate_identity

SIGNING_KEY_ENV = "VOUCH_AGENT_SIGNING_KEY"

# Policy owned by the sidecar. Keep in step with vouch_agent.actions.
ALLOWED_ACTIONS = frozenset({"answer_question", "generate_starter", "sign_sample"})
DEFAULT_RESOURCE_PREFIX = "https://vouch-protocol.com/"
MAX_VALID_SECONDS = 3600
MIN_VALID_SECONDS = 10
MAX_INTENT_BYTES = 4096

app = FastAPI(title="Vouch Agent Sidecar", version="0.2.0")

_state: dict[str, Any] = {}


class SignRequest(BaseModel):
    intent: dict[str, Any]
    valid_seconds: int | None = Field(default=None, ge=MIN_VALID_SECONDS, le=MAX_VALID_SECONDS)


def check_intent(intent: dict[str, Any], resource_prefix: str) -> None:
    """Apply the sidecar's signing policy to an intent.

    Raises:
        ValueError: if the intent is outside what this agent may sign.
    """
    for key in ("action", "target", "resource"):
        value = intent.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"intent.{key} is required and must be a string")
    if intent["action"] not in ALLOWED_ACTIONS:
        raise ValueError(f"action {intent['action']!r} is not one this agent signs")
    if not intent["resource"].startswith(resource_prefix):
        raise ValueError(f"resource must start with {resource_prefix}")
    if len(json.dumps(intent, separators=(",", ":"))) > MAX_INTENT_BYTES:
        raise ValueError("intent is too large")


def did_document(did: str, public_jwk: dict[str, Any]) -> dict[str, Any]:
    """Build a Multikey DID document for an Ed25519 public JWK."""
    from jwcrypto.common import base64url_decode

    raw = base64url_decode(public_jwk["x"])
    vm_id = f"{did}#key-1"
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multikey.encode_ed25519_public(raw),
            }
        ],
        "assertionMethod": [vm_id],
        "authentication": [vm_id],
    }


def configure(did: str, private_jwk: str, resource_prefix: str, mode: str) -> None:
    """Load a key into the sidecar's state."""
    priv = json.loads(private_jwk)
    if priv.get("kty") != "OKP" or priv.get("crv") != "Ed25519" or not priv.get("d"):
        raise ValueError(f"{SIGNING_KEY_ENV} must be a private Ed25519 JWK")
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": priv["x"]}
    _state.clear()
    _state.update(
        signer=Signer(private_key=private_jwk, did=did),
        did=did,
        document=did_document(did, public_jwk),
        resource_prefix=resource_prefix,
        mode=mode,
    )


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "did": _state.get("did"), "mode": _state.get("mode")}


@app.get("/did")
async def did() -> dict[str, Any]:
    return {"did": _state.get("did")}


@app.get("/did-document")
async def document() -> dict[str, Any]:
    return _state["document"]


@app.post("/sign")
async def sign(req: SignRequest) -> dict[str, Any]:
    try:
        check_intent(req.intent, _state["resource_prefix"])
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    signer: Signer = _state["signer"]
    return signer.sign(intent=req.intent, valid_seconds=req.valid_seconds)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Vouch website agent signing sidecar")
    parser.add_argument(
        "--did", default=os.getenv("VOUCH_AGENT_DID", "did:web:vouch-protocol.com:assistant")
    )
    parser.add_argument("--host", default=os.getenv("VOUCH_SIDECAR_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("VOUCH_SIDECAR_PORT", "8877")))
    parser.add_argument(
        "--resource-prefix",
        default=os.getenv("VOUCH_RESOURCE_PREFIX", DEFAULT_RESOURCE_PREFIX),
    )
    parser.add_argument("--dev", action="store_true", help="use an ephemeral key (local only)")
    parser.add_argument(
        "--generate-key", action="store_true", help="print a new private JWK and exit"
    )
    parser.add_argument(
        "--did-document",
        action="store_true",
        help="print the public DID document for the key in the environment and exit",
    )
    args = parser.parse_args(argv)

    if args.generate_key:
        print(generate_identity().private_key_jwk)
        return

    key = os.environ.pop(SIGNING_KEY_ENV, None)
    if args.did_document:
        if not key:
            sys.exit(f"{SIGNING_KEY_ENV} is not set.")
        configure(args.did, key, args.resource_prefix, "print")
        print(json.dumps(_state["document"], indent=2))
        return
    if key:
        mode = "persistent"
    elif args.dev:
        key = generate_identity().private_key_jwk
        mode = "dev-ephemeral"
    else:
        sys.exit(f"{SIGNING_KEY_ENV} is not set. Set it, or pass --dev for an ephemeral key.")

    configure(args.did, key, args.resource_prefix, mode)
    print(f"vouch-agent-sidecar on {args.host}:{args.port}, did={args.did}, mode={mode}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
