"""FastAPI entry point for the Vouch website agent."""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import audit, signer
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


class SignRequest(BaseModel):
    intent: dict[str, Any]
    scope: list[str] | None = None


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    sidecar_ok = await signer.sidecar_healthy()
    return {
        "ok": True,
        "sidecar_ok": sidecar_ok,
        "knowledge_chunks": len(_index.chunks),
    }


@app.post("/chat")
async def chat(payload: ChatMessage) -> StreamingResponse:
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

    async def emit():
        meta = {"sources": sources}
        if signed_credential:
            meta["credential"] = signed_credential
        yield "event: meta\ndata: " + json.dumps(meta) + "\n\n"
        try:
            async for piece in stream_answer(payload.message, retrieved):
                yield "event: token\ndata: " + json.dumps({"text": piece}) + "\n\n"
        except Exception as exc:
            yield "event: error\ndata: " + json.dumps({"error": str(exc)}) + "\n\n"
            return
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(emit(), media_type="text/event-stream")


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
        "endpoints": ["/chat", "/sign", "/audit", "/healthz"],
    }
