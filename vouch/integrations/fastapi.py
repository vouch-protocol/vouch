"""
Vouch Protocol FastAPI Integration — one-line credential gate.

Protect an endpoint by adding a single dependency. The gate reads the inbound
credential (from the ``Vouch-Credential`` header, falling back to the request
body), verifies it, optionally checks the intent matches the route, and rejects
unsigned/untrusted callers with 401/403 — before your handler runs.

    from fastapi import Depends, FastAPI
    from vouch.integrations.fastapi import VouchGate

    app = FastAPI()
    gate = VouchGate()                      # auto-resolves issuers via did:web

    @app.post("/charge")
    async def charge(passport = Depends(gate)):
        return {"agent": passport.iss, "intent": passport.intent}

Configuration mirrors :class:`vouch.gate.CredentialGate` (``public_key=``,
``trusted_keys=``, ``allow_did_resolution=``, ``require_action=`` …).
"""

from typing import Any, Optional

from vouch.gate import CredentialGate, GateResult

try:
    from fastapi import HTTPException, Request
except ImportError:  # pragma: no cover - optional dep
    Request = Any  # type: ignore

    class HTTPException(Exception):  # type: ignore
        def __init__(self, status_code: int, detail: str = "") -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail


class VouchGate:
    """A FastAPI dependency that requires a valid Vouch credential.

    Use it as ``Depends(gate)``. On success the dependency value is the
    verified :class:`~vouch.verifier.CredentialPassport`; on failure it raises
    ``HTTPException`` (401 for missing/invalid, 403 for an intent-policy
    mismatch) so the handler never runs.
    """

    def __init__(
        self,
        *,
        header: str = "Vouch-Credential",
        gate: Optional[CredentialGate] = None,
        **gate_kwargs: Any,
    ) -> None:
        self.header = header
        self._gate = gate or CredentialGate(**gate_kwargs)

    async def __call__(self, request: Request):
        credential = request.headers.get(self.header)
        if not credential:
            # Fall back to the raw request body (the application/vc+vouch path).
            body = await request.body()
            credential = body.decode("utf-8") if body else None

        result: GateResult = self._gate.check(credential)
        if result.ok:
            return result.passport

        # Distinguish "no/invalid credential" (401) from "valid but not allowed
        # for this route" (403), so callers can tell auth from authz.
        status = 403 if result.passport is not None else 401
        raise HTTPException(status_code=status, detail=result.reason or "credential rejected")


__all__ = ["VouchGate"]
