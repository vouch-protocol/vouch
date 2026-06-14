"""
Reference validator transport for the Heartbeat Protocol (Specification §11.3).

A single-region HTTP server that puts the existing continuous-trust runtime
(HeartbeatValidator, HeartbeatQuorum) on the wire so an agent can renew trust,
read its session status, fetch its published SessionVoucher, and so an authority
can revoke a DID. It is a clean reference, not production infrastructure: storage
is the existing pluggable in-memory store, and there is no Raft, no multi-region,
no multi-tenancy, and no hosting. Those belong to the commercial layer.

Endpoints:
  POST /heartbeat                     submit a signed heartbeat, get a signed voucher
  GET  /sessions/{did}/{session_id}   session status
  GET  /vouchers/{did}/{session_id}   the last issued voucher (cache-friendly)
  POST /revoke                        revoke a DID
  GET  /healthz                       liveness

The coordinator is either a HeartbeatValidator (single validator) or a
HeartbeatQuorum (M-of-N). Both expose validate(request); this server normalizes
their result shapes and signs the issued voucher with the server's own key.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any, Dict, Optional, Tuple, Union

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import data_integrity
from .heartbeat import HeartbeatValidator
from .quorum import HeartbeatQuorum
from .revocation import MemoryRevocationStore, RevocationRegistry

Coordinator = Union[HeartbeatValidator, HeartbeatQuorum]


class VoucherStore:
    """In-memory cache of the last issued voucher per (subject_did, session_id)."""

    def __init__(self) -> None:
        self._data: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def put(self, did: str, session_id: str, voucher: Dict[str, Any]) -> None:
        with self._lock:
            self._data[(did, session_id)] = voucher

    def get(self, did: str, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._data.get((did, session_id))


def _etag(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return '"' + hashlib.sha256(raw).hexdigest()[:32] + '"'


def _normalize(result: Any) -> Dict[str, Any]:
    """Flatten a HeartbeatValidationResult or QuorumResult into a dict."""
    out: Dict[str, Any] = {"ok": bool(result.ok), "session_voucher": result.session_voucher}
    # Single-validator result carries reasons; quorum result carries the tally.
    if hasattr(result, "reasons"):
        out["reasons"] = list(result.reasons)
    if hasattr(result, "rejections"):
        out["rejections"] = dict(result.rejections)
        out["threshold"] = result.threshold
        out["votes_for"] = result.votes_for
        out["approving_dids"] = list(result.approving_dids)
    return out


def create_validator_app(
    coordinator: Coordinator,
    signer: Any,
    revocation: Optional[RevocationRegistry] = None,
    voucher_store: Optional[VoucherStore] = None,
) -> FastAPI:
    """
    Build the validator FastAPI app.

    Args:
      coordinator: a HeartbeatValidator or HeartbeatQuorum.
      signer: a vouch.Signer used to sign issued vouchers.
      revocation: a RevocationRegistry. Defaults to a local-only memory registry
        (no remote .well-known lookups) so the reference server is self-contained.
      voucher_store: where issued vouchers are cached for GET /vouchers.
    """
    if revocation is None:
        revocation = RevocationRegistry(local_store=MemoryRevocationStore(), check_remote=False)
    if voucher_store is None:
        voucher_store = VoucherStore()

    if signer is None or getattr(signer, "_raw_priv", None) is None:
        raise ValueError("validator server requires a Signer with an Ed25519 key")

    app = FastAPI(title="Vouch Validator", version="1")

    def _sign_voucher(voucher: Dict[str, Any]) -> Dict[str, Any]:
        signed = dict(voucher)
        signed["proof"] = data_integrity.build_proof(
            signed, signer._raw_priv, signer.verification_method_id()
        )
        return signed

    @app.get("/healthz")
    async def healthz() -> Dict[str, Any]:
        return {"ok": True, "validator": signer.get_did()}

    @app.post("/heartbeat")
    async def heartbeat(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "reasons": ["body_not_json"]}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"ok": False, "reasons": ["body_not_object"]}, status_code=400)

        did = body.get("subject_did")
        session_id = body.get("session_id")
        if not did or not session_id:
            return JSONResponse(
                {"ok": False, "reasons": ["missing_subject_did_or_session_id"]},
                status_code=400,
            )

        if await revocation.is_revoked(did):
            return JSONResponse({"ok": False, "revoked": True}, status_code=403)

        result = _normalize(coordinator.validate(body))
        if not result["ok"]:
            # A rejected heartbeat is a valid, expected outcome, not a server error.
            return JSONResponse(result, status_code=200)

        voucher = _sign_voucher(result["session_voucher"])
        voucher_store.put(did, session_id, voucher)
        result["session_voucher"] = voucher
        return JSONResponse(result, status_code=200)

    @app.get("/sessions/{did}/{session_id}")
    async def session_status(did: str, session_id: str) -> Dict[str, Any]:
        voucher = voucher_store.get(did, session_id)
        return {
            "subject_did": did,
            "session_id": session_id,
            "has_active_voucher": voucher is not None,
            "revoked": await revocation.is_revoked(did),
        }

    @app.get("/vouchers/{did}/{session_id}")
    async def get_voucher(did: str, session_id: str, request: Request) -> Response:
        voucher = voucher_store.get(did, session_id)
        if voucher is None:
            return JSONResponse({"error": "no_voucher_for_session"}, status_code=404)
        etag = _etag(voucher)
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"ETag": etag})
        return JSONResponse(
            voucher,
            headers={
                "ETag": etag,
                # The voucher is short-lived; let caches hold it briefly but
                # revalidate against the ETag.
                "Cache-Control": "public, max-age=30, must-revalidate",
            },
        )

    @app.post("/revoke")
    async def revoke(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "body_not_json"}, status_code=400)
        did = (body or {}).get("did")
        if not did:
            return JSONResponse({"error": "missing_did"}, status_code=400)
        record = await revocation.revoke(
            did=did,
            reason=(body.get("reason") or "unspecified"),
            revoked_by=body.get("revoked_by"),
        )
        return JSONResponse(
            {"revoked": True, "did": did, "revoked_at": record.revoked_at}, status_code=200
        )

    # Expose the wiring for tests and embedding.
    app.state.coordinator = coordinator
    app.state.revocation = revocation
    app.state.voucher_store = voucher_store
    return app
