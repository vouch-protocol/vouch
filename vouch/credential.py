"""
A thin, read-friendly wrapper over a Vouch Credential dict.

The dict produced by :meth:`Signer.sign` (and :func:`vouch.sign`) is
the canonical, on-the-wire form. This wrapper does not replace it; it sits on
top so you can read back what a credential authorizes without digging through
``credentialSubject.intent`` by hand, and verify it in one call::

    c = vouch.Credential(signed)
    c.action, c.target, c.resource      # what it authorizes
    c.issuer                            # who signed it
    ok, passport = c.verify()           # resolve issuer key and verify
    c.to_json()                         # back to the wire form

``Credential`` is sugar only. ``c.to_dict()`` returns the exact same dict you
passed in (not a copy), so nothing about the wire format changes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from vouch.verifier import (
    CredentialDelegationLink,
    CredentialPassport,
    _parse_iso8601,
    verify,
)


class Credential:
    """Ergonomic accessor over a Vouch Credential dict.

    Accepts a credential dict or its JSON string. All accessors are read-only;
    the underlying dict is never mutated.
    """

    def __init__(self, credential: Union[Dict[str, Any], str]) -> None:
        if isinstance(credential, Credential):
            credential = credential._cred
        if isinstance(credential, str):
            credential = json.loads(credential)
        if not isinstance(credential, dict):
            raise TypeError("Credential expects a dict or JSON string")
        self._cred: Dict[str, Any] = credential

    # -- intent ---------------------------------------------------------------

    @property
    def intent(self) -> Dict[str, Any]:
        """The full intent payload (action, target, resource, and any extras)."""
        subject = self._cred.get("credentialSubject") or {}
        return subject.get("intent") or {}

    @property
    def action(self) -> Optional[str]:
        return self.intent.get("action")

    @property
    def target(self) -> Optional[str]:
        return self.intent.get("target")

    @property
    def resource(self) -> Optional[str]:
        return self.intent.get("resource")

    # -- issuer / identity ----------------------------------------------------

    @property
    def issuer(self) -> str:
        """The issuer DID (the ``issuer`` field, first entry if it is a list)."""
        issuer = self._cred.get("issuer")
        if isinstance(issuer, list):
            return issuer[0] if issuer else ""
        return issuer or ""

    @property
    def subject(self) -> str:
        """The credentialSubject id (the agent's DID)."""
        return (self._cred.get("credentialSubject") or {}).get("id", "")

    @property
    def credential_id(self) -> str:
        return self._cred.get("id", "")

    # -- validity -------------------------------------------------------------

    @property
    def valid_from(self) -> str:
        return self._cred.get("validFrom", "")

    @property
    def valid_until(self) -> str:
        return self._cred.get("validUntil", "")

    @property
    def is_expired(self) -> bool:
        """True if the credential's validity window has passed (no skew)."""
        expires = _parse_iso8601(self.valid_until)
        if expires is None:
            return False
        return datetime.now(timezone.utc) > expires

    # -- extras ---------------------------------------------------------------

    @property
    def reputation_score(self) -> Optional[int]:
        score = (self._cred.get("credentialSubject") or {}).get("reputationScore")
        if score is None:
            return None
        try:
            return int(score)
        except (TypeError, ValueError):
            return None

    @property
    def delegation_chain(self) -> List[CredentialDelegationLink]:
        chain: List[CredentialDelegationLink] = []
        raw = (self._cred.get("credentialSubject") or {}).get("delegationChain") or []
        for link in raw:
            chain.append(
                CredentialDelegationLink(
                    issuer=link.get("issuer", ""),
                    subject=link.get("subject", ""),
                    intent=link.get("intent", {}) or {},
                    valid_from=link.get("validFrom"),
                    valid_until=link.get("validUntil"),
                    parent_proof_value=link.get("parentProofValue"),
                )
            )
        return chain

    @property
    def proof(self) -> Dict[str, Any]:
        proof = self._cred.get("proof")
        return proof if isinstance(proof, dict) else {}

    # -- verification ---------------------------------------------------------

    def verify(
        self,
        public_key: Optional[Any] = None,
        *,
        allow_did_resolution: bool = True,
    ) -> Tuple[bool, Optional[CredentialPassport]]:
        """Verify this credential.

        With ``public_key`` it verifies offline against that key. Without it,
        the issuer key is resolved from trusted roots, ``did:web``, or
        ``did:key`` (set ``allow_did_resolution=False`` to forbid the network).
        Returns ``(is_valid, CredentialPassport | None)``.
        """
        return verify(
            self._cred,
            public_key=public_key,
            allow_did_resolution=allow_did_resolution,
        )

    # -- serialization --------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Return the underlying credential dict (the canonical wire form)."""
        return self._cred

    def to_json(self) -> str:
        """Return the credential as a compact JSON string for transport."""
        return json.dumps(self._cred, separators=(",", ":"))

    def __getitem__(self, key: str) -> Any:
        return self._cred[key]

    def __contains__(self, key: str) -> bool:
        return key in self._cred

    def __repr__(self) -> str:
        return f"Credential(issuer={self.issuer!r}, action={self.action!r}, resource={self.resource!r})"


__all__ = ["Credential"]
