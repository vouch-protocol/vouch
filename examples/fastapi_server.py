"""
FastAPI Gatekeeper Example - Verify incoming agent requests.

This example demonstrates how to protect API endpoints using Vouch-Token verification.
"""

from fastapi import FastAPI, Header, HTTPException
from typing import Optional
import os

from vouch import Verifier


app = FastAPI(
    title="Vouch Protected API", description="Example API protected with Vouch-Token verification"
)

# Initialize verifier with optional trusted roots
# In production, you would load public keys from a trusted source
TRUSTED_PUBLIC_KEY = os.getenv("VOUCH_PUBLIC_KEY")

verifier = Verifier(
    trusted_roots={},
    allow_did_resolution=True,  # Attempt to resolve DIDs from the web
    clock_skew_seconds=60,
)


@app.post("/api/resource")
async def protected_resource(vouch_token: Optional[str] = Header(None, alias="Vouch-Token")):
    """
    Protected endpoint requiring a valid Vouch-Token.

    The agent must include a Vouch-Token header with a valid signed JWT.
    """
    if not vouch_token:
        raise HTTPException(status_code=400, detail="Missing Vouch-Token header")

    # Verify the token
    if TRUSTED_PUBLIC_KEY:
        # If we have a known public key, use it
        is_valid, passport = Verifier.verify(vouch_token, public_key_jwk=TRUSTED_PUBLIC_KEY)
    else:
        # Otherwise, try to resolve the DID
        is_valid, passport = verifier.check_vouch(vouch_token)

    if not is_valid or not passport:
        raise HTTPException(status_code=401, detail="Invalid or expired Vouch-Token")

    return {
        "status": "Verified",
        "agent": passport.sub,
        "issuer": passport.iss,
        "payload": passport.payload,
    }


@app.post("/agent/connect")
async def agent_connect(vouch_token: Optional[str] = Header(None, alias="Vouch-Token")):
    """Agent connection endpoint with reputation checking."""
    if not vouch_token:
        raise HTTPException(status_code=400, detail="Missing Vouch-Token header")

    is_valid, passport = (
        Verifier.verify(vouch_token, public_key_jwk=TRUSTED_PUBLIC_KEY)
        if TRUSTED_PUBLIC_KEY
        else verifier.check_vouch(vouch_token)
    )

    if not is_valid or not passport:
        raise HTTPException(status_code=401, detail="Agent Verification Failed")

    return {"status": "Connected", "agent": passport.sub, "token_id": passport.jti}


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "vouch_enabled": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
