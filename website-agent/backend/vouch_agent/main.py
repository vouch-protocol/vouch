"""FastAPI entry point for the Vouch website agent."""

from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import audit, followups, interactions, signer
from .config import CONFIG
from .llm import stream_answer
from .rag import get_index

app = FastAPI(title="Vouch Website Agent", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(CONFIG.cors_allow_origins),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_index = get_index()


class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    intent: dict[str, Any] | None = None
    # If this question came from clicking a follow-up chip below an earlier
    # answer, the client sends the parent `interaction_id` so we can later
    # query "which suggested follow-ups actually got clicked".
    from_followup_of: str | None = Field(default=None, max_length=64)


class SignRequest(BaseModel):
    intent: dict[str, Any]
    scope: list[str] | None = None


class FeedbackRequest(BaseModel):
    interaction_id: str = Field(..., min_length=8, max_length=64)
    rating: int = Field(..., description="1 for helpful, -1 for unhelpful")
    comment: str | None = Field(default=None, max_length=2000)


def _client_ip(request: Request) -> str | None:
    """Best-effort client IP extraction across Fly + Cloudflare + direct."""
    for hdr in ("Fly-Client-IP", "CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"):
        value = request.headers.get(hdr)
        if value:
            return value
    if request.client:
        return request.client.host
    return None


def _client_country(request: Request) -> str | None:
    """Country code from upstream proxies; both Fly and Cloudflare expose one."""
    for hdr in ("Fly-Client-Country", "CF-IPCountry"):
        value = request.headers.get(hdr)
        if value and len(value) == 2:
            return value.upper()
    return None


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    sidecar_ok = await signer.sidecar_healthy()
    return {
        "ok": True,
        "sidecar_ok": sidecar_ok,
        "knowledge_chunks": len(_index.chunks),
    }


@app.post("/chat")
async def chat(payload: ChatMessage, request: Request) -> StreamingResponse:
    retrieved_pairs = _index.search(payload.message, top_k=CONFIG.max_context_chunks)
    retrieved = [(c.text, c.source, score) for c, score in retrieved_pairs]
    sources = [{"source": c.source, "score": round(score, 3)} for c, score in retrieved_pairs]

    signed_credential: dict[str, Any] | None = None
    if payload.intent:
        try:
            signed_credential = await signer.sign_intent(payload.intent)
            audit.record(signed_credential)
        except signer.SignerError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Open a log row for this interaction. The id is returned in the meta event
    # so the client can later POST /feedback with it. IP is /24-truncated.
    interaction_id = interactions.log().start_interaction(
        question=payload.message,
        ip=_client_ip(request),
        country=_client_country(request),
        user_agent=request.headers.get("user-agent"),
        from_followup_of=payload.from_followup_of,
    )

    async def emit():
        meta = {"sources": sources, "interaction_id": interaction_id}
        if signed_credential:
            meta["credential"] = signed_credential
        yield "event: meta\ndata: " + json.dumps(meta) + "\n\n"
        collected = []
        try:
            async for piece in stream_answer(payload.message, retrieved):
                collected.append(piece)
                yield "event: token\ndata: " + json.dumps({"text": piece}) + "\n\n"
        except Exception as exc:
            yield "event: error\ndata: " + json.dumps({"error": str(exc)}) + "\n\n"
            interactions.log().complete_interaction(
                interaction_id, response=f"[error] {exc}", sources=sources,
            )
            return
        # Extract follow-ups from the LLM's own tail; fall back to a
        # per-source bank if it forgot the marker but the answer was
        # substantive. Emitting via a structured SSE event (rather than
        # leaving it to the frontend to re-parse) keeps the chip list
        # robust against odd bullet characters, missing dashes, etc.
        full_response = "".join(collected)
        suggested, cleaned_body = followups.extract_followups(full_response)
        if not suggested and followups.is_substantive(cleaned_body):
            suggested = followups.fallback_followups(sources)
        if suggested:
            yield "event: followups\ndata: " + json.dumps({"questions": suggested}) + "\n\n"

        # Persist the cleaned reply (without the marker block).
        interactions.log().complete_interaction(
            interaction_id, response=cleaned_body, sources=sources,
        )
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(emit(), media_type="text/event-stream")


@app.post("/feedback")
async def feedback(payload: FeedbackRequest) -> dict[str, Any]:
    """Receive a thumbs-up / thumbs-down (and optional comment) on a chat reply."""
    ok = interactions.log().record_feedback(
        payload.interaction_id,
        rating=payload.rating,
        comment=payload.comment,
    )
    if not ok:
        raise HTTPException(
            status_code=404,
            detail="interaction_id not found, or rating must be -1 or 1",
        )
    return {"ok": True}


@app.get("/interactions")
async def interactions_endpoint(
    request: Request,
    limit: int = 50,
    only_with_feedback: bool = False,
) -> dict[str, Any]:
    """Read recent interactions. Gated by Bearer token (set VOUCH_ADMIN_TOKEN)."""
    admin_token = os.getenv("VOUCH_ADMIN_TOKEN")
    if not admin_token:
        raise HTTPException(status_code=503, detail="admin endpoint disabled (no VOUCH_ADMIN_TOKEN set)")
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer ") or auth.removeprefix("Bearer ").strip() != admin_token:
        raise HTTPException(status_code=401, detail="bad or missing bearer token")
    return {
        "summary": interactions.log().summary(),
        "entries": interactions.log().recent(
            limit=limit, only_with_feedback=only_with_feedback,
        ),
    }


@app.post("/sign")
async def sign(payload: SignRequest) -> dict[str, Any]:
    try:
        credential = await signer.sign_intent(payload.intent, scope=payload.scope)
    except signer.SignerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    summary = audit.record(credential)
    return {"credential": credential, "audit": summary}


@app.get("/audit")
async def audit_endpoint(limit: int = 50) -> dict[str, Any]:
    return {"entries": audit.recent(limit=limit)}


@app.get("/")
async def root() -> dict[str, Any]:
    return {
        "name": "Vouch Website Agent",
        "agent_did": CONFIG.agent_did,
        "endpoints": [
            "/chat", "/sign", "/audit", "/feedback", "/interactions",
            "/healthz", "/.well-known/did.json",
        ],
    }


@app.get("/.well-known/did.json")
async def did_document() -> JSONResponse:
    """Serve the DID document so `did:web:agent.vouch-protocol.com` resolves.

    The document is generated once by deploy/keygen.py and baked into the
    container at /app/did.json (overridable via VOUCH_DID_DOCUMENT_PATH).
    Content-Type is application/did+json per the DID spec, with a vanilla
    application/json fallback for resolvers that do not negotiate.
    """
    path = CONFIG.did_document_path
    if path is None or not path.exists():
        raise HTTPException(status_code=404, detail="DID document not configured")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"DID document unreadable: {exc}") from exc
    return JSONResponse(
        content=document,
        media_type="application/did+json",
        headers={"Cache-Control": "public, max-age=300"},
    )
