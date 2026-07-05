"""The receiving service: verifies the credential and enforces the binding.

This is the other party. It never trusts the request fields on their own. It
verifies the attached Vouch Credential, then checks that the action it is about
to perform matches the exact intent that was authorized. A valid signature on
``account:123`` does not authorize a transfer to ``account:999``.

The bank does not need the sidecar or the private key. It only needs the
agent's public key, which it holds the way any service holds a trusted key: in
its own trust registry. Here we pass it in directly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from vouch import Verifier


@dataclass
class Bank:
    """A service that accepts an action only if the credential authorizes it."""

    trusted_did: str
    trusted_public_key_jwk: str

    def handle(self, request: Dict[str, Any]) -> Tuple[bool, str]:
        """Return (accepted, reason) for one incoming request."""
        credential_json = request.get("vouch_credential", "")
        try:
            credential = json.loads(credential_json)
        except (json.JSONDecodeError, TypeError):
            return False, "no valid Vouch Credential attached"

        # 1. Is the credential genuine, unexpired, and from a key we trust?
        is_valid, passport = Verifier.verify(
            credential, public_key=self.trusted_public_key_jwk
        )
        if not is_valid or passport is None:
            return False, "credential failed signature or validity check"

        issuer = getattr(passport, "iss", None) or getattr(passport, "sub", None)
        if issuer != self.trusted_did:
            return False, f"issuer {issuer} is not our trusted agent"

        # 2. Does the credential authorize *this exact* action? This is the
        #    step that catches a swapped or replayed request.
        intent = getattr(passport, "intent", {}) or {}
        authorized_resource = intent.get("resource")
        requested_resource = request.get("requested_resource")
        if authorized_resource != requested_resource:
            return (
                False,
                f"credential authorizes {authorized_resource}, "
                f"but the request targets {requested_resource}",
            )
        if intent.get("action") != request.get("action"):
            return (
                False,
                f"credential authorizes '{intent.get('action')}', "
                f"but the request is '{request.get('action')}'",
            )

        return True, f"authorized by {issuer} for {authorized_resource}"
