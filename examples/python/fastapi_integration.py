#!/usr/bin/env python3
"""
Example: FastAPI Integration

Shows how to integrate Vouch SDK with FastAPI for building
authenticated APIs where all responses are signed.
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import json

from vouch_sdk import AsyncVouchClient, VouchConnectionError, NoKeysConfiguredError


# ============================================================================
# FastAPI App Setup
# ============================================================================

app = FastAPI(
    title="Vouch-Signed API",
    description="All responses are cryptographically signed with Vouch",
    version="1.0.0",
)


# ============================================================================
# Vouch Client Dependency
# ============================================================================

async def get_vouch_client() -> AsyncVouchClient:
    """Dependency that provides a Vouch client."""
    return AsyncVouchClient()


async def get_vouch_optional() -> Optional[AsyncVouchClient]:
    """Optional Vouch client - returns None if daemon is offline."""
    client = AsyncVouchClient()
    try:
        await client.connect()
        return client
    except VouchConnectionError:
        return None


# ============================================================================
# Models
# ============================================================================

class Message(BaseModel):
    content: str
    author: Optional[str] = None


class SignedResponse(BaseModel):
    data: dict
    signature: Optional[str] = None
    signed_by: Optional[str] = None


# ============================================================================
# Middleware: Sign All Responses
# ============================================================================

@app.middleware("http")
async def sign_responses(request: Request, call_next):
    """Middleware that signs all JSON responses."""
    response = await call_next(request)
    
    # Only sign JSON responses
    if response.headers.get("content-type", "").startswith("application/json"):
        # Get the response body
        body = b""
        async for chunk in response.body_iterator:
            body += chunk
        
        # Try to sign
        try:
            client = AsyncVouchClient()
            await client.connect()
            
            sign_result = await client.sign(
                body.decode(),
                origin=f"api:{request.url.path}",
            )
            
            # Add signature header
            response.headers["X-Vouch-Signature"] = sign_result["signature"]
            response.headers["X-Vouch-DID"] = sign_result.get("did", "")
            
        except (VouchConnectionError, NoKeysConfiguredError):
            # Proceed without signature
            response.headers["X-Vouch-Signature"] = "unsigned"
        
        # Return modified response
        return JSONResponse(
            content=json.loads(body),
            headers=dict(response.headers),
            status_code=response.status_code,
        )
    
    return response


# ============================================================================
# Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint - response will be signed by middleware."""
    return {"message": "Welcome to the Vouch-signed API!"}


@app.get("/status")
async def api_status(client: Optional[AsyncVouchClient] = Depends(get_vouch_optional)):  # noqa: B008
    """Check API and Vouch status."""
    vouch_online = client is not None
    
    vouch_info = None
    if vouch_online:
        try:
            key_info = await client.get_public_key()
            vouch_info = {
                "did": key_info.get("did"),
                "fingerprint": key_info.get("fingerprint"),
            }
        except NoKeysConfiguredError:
            vouch_info = {"status": "no_keys"}
    
    return {
        "api": "online",
        "vouch": "online" if vouch_online else "offline",
        "identity": vouch_info,
    }


@app.post("/messages", response_model=SignedResponse)
async def create_message(
    message: Message,
    client: AsyncVouchClient = Depends(get_vouch_client),  # noqa: B008
):
    """Create a signed message."""
    content_to_sign = json.dumps({
        "content": message.content,
        "author": message.author or "anonymous",
    })
    
    try:
        result = await client.sign(content_to_sign, origin="api:messages")
        
        return SignedResponse(
            data={"content": message.content, "author": message.author},
            signature=result["signature"],
            signed_by=result.get("did"),
        )
        
    except NoKeysConfiguredError:
        raise HTTPException(
            status_code=503,
            detail="Vouch identity not configured. Cannot sign messages.",
        )


@app.post("/sign")
async def sign_content(
    request: Request,
    client: AsyncVouchClient = Depends(get_vouch_client),  # noqa: B008
):
    """Sign arbitrary content."""
    body = await request.body()
    
    try:
        result = await client.sign(
            body.decode("utf-8"),
            origin="api:sign",
            content_type=request.headers.get("content-type", "text/plain"),
        )
        
        return {
            "signature": result["signature"],
            "timestamp": result["timestamp"],
            "did": result.get("did"),
        }
        
    except VouchConnectionError:
        raise HTTPException(status_code=503, detail="Vouch daemon offline")


# ============================================================================
# Run with: uvicorn fastapi_integration:app --reload
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
