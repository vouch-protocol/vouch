"""FastAPI entry point for the Vouch website agent."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import actions, audit, followups, interactions, signer
from .config import CONFIG
from .llm import stream_answer
from .rag import get_index

logger = logging.getLogger("vouch_agent")

app = FastAPI(title="Vouch Website Agent", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(CONFIG.cors_allow_origins),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_index = get_index()


class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    # If this question came from clicking a follow-up chip below an earlier
    # answer, the client sends the parent `interaction_id` so we can later
    # query "which suggested follow-ups actually got clicked".
    from_followup_of: str | None = Field(default=None, max_length=64)


class ActRequest(BaseModel):
    action: str = Field(..., max_length=64)
    params: dict[str, str] = Field(default_factory=dict, max_length=4)


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
        proposal, full_response = actions.extract_proposal(full_response)
        suggested, cleaned_body = followups.extract_followups(full_response)
        if not suggested and followups.is_substantive(cleaned_body):
            suggested = followups.fallback_followups(sources)
        if suggested:
            yield "event: followups\ndata: " + json.dumps({"questions": suggested}) + "\n\n"

        if proposal:
            yield "event: action\ndata: " + json.dumps(
                {"action": proposal.action, "params": proposal.params, "label": proposal.label}
            ) + "\n\n"

        # Sign the reply: the credential carries a digest of the exact text
        # the visitor sees (the cleaned body), so the answer is attributable
        # to the agent's DID. A signing failure never blocks the answer.
        answer_intent = {
            "action": "answer_question",
            "target": f"interaction:{interaction_id}",
            "resource": actions.ASK_URL,
            "outputDigest": signer.digest(cleaned_body),
        }
        try:
            credential = await signer.sign_and_verify(
                answer_intent, valid_seconds=actions.CREDENTIAL_VALID_SECONDS,
            )
            audit.record(credential)
            yield "event: credential\ndata: " + json.dumps(
                {"credential": credential, "signed_text": cleaned_body}
            ) + "\n\n"
        except signer.SignerError as exc:
            logger.warning("answer not signed: %s", exc)

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


@app.post("/act")
async def act(payload: ActRequest) -> dict[str, Any]:
    """Run an action the visitor confirmed: build, sign, verify, then release.

    The intent is built here from a fixed list of actions and parameters, so
    a caller cannot get the agent's key to sign an arbitrary statement. The
    output is released only after the credential verifies against the
    agent's DID document.
    """
    try:
        intent, result, covered = actions.build(payload.action, payload.params)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    intent["outputDigest"] = signer.digest(covered)
    try:
        credential = await signer.sign_and_verify(
            intent, valid_seconds=actions.CREDENTIAL_VALID_SECONDS,
        )
    except signer.SignerError as exc:
        logger.error("action %s not signed: %s", payload.action, exc)
        raise HTTPException(status_code=503, detail="signing is unavailable, so the action did not run") from exc
    summary = audit.record(credential)
    return {"credential": credential, "verified": True, "result": result, "audit": summary}


@app.get("/audit")
async def audit_endpoint(limit: int = 50) -> dict[str, Any]:
    return {"entries": audit.recent(limit=limit)}


@app.get("/")
async def root() -> dict[str, Any]:
    return {
        "name": "Vouch Website Agent",
        "agent_did": CONFIG.agent_did,
        "endpoints": [
            "/chat", "/act", "/audit", "/feedback", "/interactions",
            "/healthz", "/.well-known/did.json",
        ],
    }


@app.get("/.well-known/did.json")
async def did_document() -> JSONResponse:
    """Serve the DID document for the key the signing sidecar holds.

    The document comes from the sidecar, which derives it from its key, so
    it always matches the signing key. The DID itself resolves wherever its
    did:web points (for the default DID, https://vouch-protocol.com/assistant/did.json);
    this copy lets an operator compare the two. Returns 404 when no signing
    sidecar is configured.
    """
    try:
        document = await signer.did_document()
    except signer.SignerError as exc:
        raise HTTPException(status_code=404, detail="no signing key is configured") from exc
    return JSONResponse(
        content=document,
        media_type="application/did+json",
        headers={"Cache-Control": "public, max-age=300"},
    )
