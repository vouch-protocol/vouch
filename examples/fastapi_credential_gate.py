"""
FastAPI Credential Gate - Reject unsigned agent requests (Vouch v1.0).

A minimal gatekeeper for the modern credential path: one endpoint that reads a
`Vouch-Credential` header, verifies it as a W3C Verifiable Credential with
`Verifier.verify_credential()`, and returns 401 when the header is missing or invalid.

(For the legacy JWS `Vouch-Token` path, see fastapi_server.py.)

Run & verify:
  1. Mint a public key + a signed credential:
       from vouch import Signer, generate_identity
       import json
       ident = generate_identity(domain="example.com")
       print("PUBKEY:", ident.public_key_jwk)
       cred = Signer(private_key=ident.private_key_jwk, did=ident.did).sign_credential(
           intent={"action": "read", "target": "inbox",
                   "resource": "https://example.com/api/inbox"})
       print("CRED:", json.dumps(cred))
  2. export VOUCH_PUBLIC_KEY='<PUBKEY>'
     uvicorn fastapi_credential_gate:app --port 8000
  3. curl -X POST localhost:8000/api/resource -H "Vouch-Credential: <CRED>"   # 200
     curl -X POST localhost:8000/api/resource                                 # 401
"""

import os
from typing import Optional

from fastapi import FastAPI, Header, HTTPException

from vouch import Verifier

app = FastAPI(title="Vouch Credential Gate")

# The trusted issuer's public key (Multikey or JWK string). verify_credential
# coerces either form. Set it before launching the server.
PUBLIC_KEY = os.getenv("VOUCH_PUBLIC_KEY")


@app.post("/api/resource")
async def protected_resource(
    vouch_credential: Optional[str] = Header(default=None, alias="Vouch-Credential"),
):
    """Require a valid Vouch credential; reject everything else with 401."""
    if not PUBLIC_KEY:
        raise RuntimeError("Set VOUCH_PUBLIC_KEY to the trusted issuer's public key")
    if not vouch_credential:
        raise HTTPException(status_code=401, detail="Missing Vouch-Credential header")

    is_valid, passport = Verifier.verify_credential(vouch_credential, public_key=PUBLIC_KEY)
    if not is_valid or passport is None:
        raise HTTPException(status_code=401, detail="Invalid Vouch credential")

    return {"status": "verified", "agent": passport.sub, "intent": passport.intent}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
