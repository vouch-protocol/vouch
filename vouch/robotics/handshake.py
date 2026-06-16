"""
Robot-to-robot trust handshake protocol (Phase 5.4).

Two robots in different trust domains authenticate each other and establish a
bounded-trust session before cooperating. The protocol is three signed messages:

  1. HELLO    (initiator A -> responder B): A's DID, a fresh nonce, and the
     scope A proposes to operate under.
  2. ACCEPT   (B -> A): B verifies A's identity and that A's domain is allowed by
     B's trust policy, intersects the proposed scope with what B offers, and
     signs an acceptance binding the nonce and the bounded scope.
  3. CONFIRM  (A -> B): A verifies B's identity and acceptance (and that the
     nonce echoes), and signs a confirmation. Both now hold the same
     BoundedSession.

Each message is an eddsa-jcs-2022 signed object, so authentication reuses the
existing verifier. "Bounded trust" means the session scope is the intersection
of what each side is willing to grant, never the union.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set
from ._signing import attach_proof

HELLO = "handshake_hello"
ACCEPT = "handshake_accept"
CONFIRM = "handshake_confirm"


class HandshakeError(Exception):
    """Raised on handshake protocol failures."""


@dataclass
class TrustPolicy:
    """
    Cross-domain trust policy. A peer is trusted when its did:web domain is in
    `trusted_domains`, or when `accept_unknown` is set (open cooperation).
    """

    trusted_domains: Set[str] = field(default_factory=set)
    accept_unknown: bool = False

    def is_trusted(self, did: str) -> bool:
        if self.accept_unknown:
            return True
        return _did_web_domain(did) in self.trusted_domains


@dataclass
class BoundedSession:
    session_id: str
    initiator: str
    responder: str
    scope: List[str]
    nonce: str
    valid_until: Optional[str] = None


def _did_web_domain(did: str) -> Optional[str]:
    if did.startswith("did:web:"):
        return did[len("did:web:") :].split(":")[0]
    return None


def _sign(signer: Any, obj: Dict[str, Any]) -> Dict[str, Any]:
    return attach_proof(obj, signer)


def _verify(obj: Dict[str, Any], public_key: Any) -> bool:
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False
    try:
        return bool(data_integrity.verify_proof(obj, resolved))
    except ValueError:
        return False


def build_hello(
    signer: Any,
    *,
    proposed_scope: List[str],
    nonce: Optional[str] = None,
    peer_did: Optional[str] = None,
) -> Dict[str, Any]:
    """A: open the handshake with a proposed scope and a fresh nonce."""
    hello = {
        "type": HELLO,
        "from": signer.get_did(),
        "to": peer_did,
        "nonce": nonce or uuid.uuid4().hex,
        "proposedScope": list(proposed_scope),
        "issuedAt": _iso(datetime.now(timezone.utc)),
    }
    return _sign(signer, hello)


def build_accept(
    signer: Any,
    *,
    hello: Dict[str, Any],
    hello_public_key: Any,
    policy: TrustPolicy,
    offered_scope: List[str],
    valid_seconds: int = 300,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    B: verify A's HELLO and identity domain, intersect the scope, and sign an
    acceptance. Raises HandshakeError if A is untrusted or the HELLO is invalid.
    """
    if hello.get("type") != HELLO:
        raise HandshakeError("not a HELLO message")
    if not _verify(hello, hello_public_key):
        raise HandshakeError("HELLO signature invalid")
    initiator = hello.get("from")
    if not policy.is_trusted(initiator):
        raise HandshakeError(f"peer {initiator} is not in this trust domain's policy")

    bounded = sorted(set(hello.get("proposedScope", [])) & set(offered_scope))
    sid = session_id or f"urn:uuid:{uuid.uuid4()}"
    valid_until = _iso(datetime.now(timezone.utc) + timedelta(seconds=valid_seconds))
    accept = {
        "type": ACCEPT,
        "from": signer.get_did(),
        "to": initiator,
        "sessionId": sid,
        "nonce": hello.get("nonce"),
        "boundedScope": bounded,
        "validUntil": valid_until,
    }
    return _sign(signer, accept)


def verify_accept(
    accept: Dict[str, Any],
    accept_public_key: Any,
    *,
    expected_nonce: str,
    policy: Optional[TrustPolicy] = None,
) -> "tuple[bool, Optional[BoundedSession]]":
    """A: verify B's ACCEPT, that the nonce echoes, and (optionally) that B is trusted."""
    if accept.get("type") != ACCEPT:
        return False, None
    if not _verify(accept, accept_public_key):
        return False, None
    if accept.get("nonce") != expected_nonce:
        return False, None
    responder = accept.get("from")
    if policy is not None and not policy.is_trusted(responder):
        return False, None
    session = BoundedSession(
        session_id=accept.get("sessionId"),
        initiator=accept.get("to"),
        responder=responder,
        scope=list(accept.get("boundedScope", [])),
        nonce=accept.get("nonce"),
        valid_until=accept.get("validUntil"),
    )
    return True, session


def build_confirm(signer: Any, *, session: BoundedSession) -> Dict[str, Any]:
    """A: confirm the bounded session to B."""
    confirm = {
        "type": CONFIRM,
        "from": signer.get_did(),
        "to": session.responder,
        "sessionId": session.session_id,
        "nonce": session.nonce,
        "acceptedScope": list(session.scope),
    }
    return _sign(signer, confirm)


def verify_confirm(
    confirm: Dict[str, Any],
    confirm_public_key: Any,
    *,
    session_id: str,
    expected_nonce: str,
) -> bool:
    """B: verify A's CONFIRM closes the agreed session."""
    if confirm.get("type") != CONFIRM:
        return False
    if not _verify(confirm, confirm_public_key):
        return False
    return confirm.get("sessionId") == session_id and confirm.get("nonce") == expected_nonce


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "HELLO",
    "ACCEPT",
    "CONFIRM",
    "HandshakeError",
    "TrustPolicy",
    "BoundedSession",
    "build_hello",
    "build_accept",
    "verify_accept",
    "build_confirm",
    "verify_confirm",
]
