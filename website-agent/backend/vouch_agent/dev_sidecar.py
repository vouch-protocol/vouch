"""Tiny dev sidecar that signs Vouch credentials over HTTP.

Purpose: stand-in for the production Go sidecar during local development.
It generates an ephemeral Ed25519 keypair on startup, exposes /sign,
/did, and /health, and matches the request/response shape expected by
vouch_agent.signer.

NOT FOR PRODUCTION. The key is ephemeral and lives in this process's
memory. Production deployments must use the Go sidecar with a key
loaded from KMS/HSM/file.

Run with:
    python -m vouch_agent.dev_sidecar --did did:web:agent.vouch-protocol.org --port 8877
"""

from __future__ import annotations

import argparse
import os
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from vouch import Signer
from vouch.keys import generate_identity


app = FastAPI(title="Vouch Dev Sidecar", version="0.1.0")

_state: dict[str, Any] = {}


class SignRequest(BaseModel):
    intent: dict[str, Any]
    scope: list[str] | None = None
    valid_seconds: int | None = Field(default=None, ge=10, le=3600)


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "did": _state.get("did"), "mode": "dev-ephemeral"}


@app.get("/did")
async def did() -> dict[str, Any]:
    return {"did": _state.get("did")}


@app.get("/.well-known/did.json")
async def did_document() -> dict[str, Any]:
    signer: Signer = _state["signer"]
    pub = _state["public_jwk"]
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": signer.did,
        "verificationMethod": [
            {
                "id": f"{signer.did}#key-1",
                "type": "JsonWebKey2020",
                "controller": signer.did,
                "publicKeyJwk": pub,
            }
        ],
        "assertionMethod": [f"{signer.did}#key-1"],
        "authentication": [f"{signer.did}#key-1"],
    }


@app.post("/sign")
async def sign(req: SignRequest) -> dict[str, Any]:
    intent = req.intent
    for key in ("action", "target", "resource"):
        if not intent.get(key):
            raise HTTPException(status_code=400, detail=f"intent.{key} is required")
    signer: Signer = _state["signer"]
    try:
        credential = signer.sign(
            intent=intent,
            valid_seconds=req.valid_seconds,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return credential


def main() -> None:
    parser = argparse.ArgumentParser(description="Vouch dev sidecar")
    parser.add_argument("--did", default=os.getenv("VOUCH_AGENT_DID", "did:web:agent.vouch-protocol.org"))
    parser.add_argument("--port", type=int, default=int(os.getenv("VOUCH_SIDECAR_PORT", "8877")))
    parser.add_argument("--host", default=os.getenv("VOUCH_SIDECAR_HOST", "127.0.0.1"))
    args = parser.parse_args()

    keypair = generate_identity()
    import json as _json
    _state["public_jwk"] = _json.loads(keypair.public_key_jwk)
    _state["signer"] = Signer(private_key=keypair.private_key_jwk, did=args.did)
    _state["did"] = args.did

    print(f"vouch-dev-sidecar listening on {args.host}:{args.port}, did={args.did}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
