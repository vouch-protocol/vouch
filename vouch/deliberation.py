"""
Proof of Deliberation: gate irreversible agent actions behind a challenge window.

Identity, delegation, reasoning, and reputation all answer questions *after* an
action takes effect. For a reversible action that is enough: the effect can be
rolled back. For an *irreversible* one (wiring funds, deleting without backup,
publishing, actuating) it is not, and by the time an audit log is read the money
is already gone.

This module adds the one preventive control in the accountable-autonomy set. A
consequential action runs in two phases:

  1. commit_intent  -> the agent signs and broadcasts a VouchIntentCredential
     naming the action, its reversibility class, a challenge window, and the
     parties allowed to object. The exact action is fixed by a digest.
  2. execute        -> only after the window has provably elapsed, and only if no
     valid veto exists, the agent signs a VouchExecuteCredential that a verifier
     will accept.

During the window any named authority may veto_intent, producing a
VouchVetoCredential bound to the committed intent that any verifier treats as a
hard block. The verifier, not the agent, decides when the action may proceed: the
agent cannot shorten the window (elapse is checked) and cannot clear its own veto
(the veto authority is a separate DID). Reversible actions pay no delay.

Everything here is an ordinary ``eddsa-jcs-2022`` Verifiable Credential, so the
intent, veto, and execution verify across the language SDKs and compose with the
delegation, reasoning, and accountability primitives. This is the on-protocol
form of the method disclosed in PAD-085.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import data_integrity
from .jcs import canonicalize

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"

INTENT_TYPE = "VouchIntentCredential"
EXECUTE_TYPE = "VouchExecuteCredential"
VETO_TYPE = "VouchVetoCredential"

DIGEST_ALGORITHM = "sha-256-jcs"

# Reversibility classes. Those in REVERSIBLE_CLASSES need no deliberation window;
# the rest require one before they may execute.
CLASS_REVERSIBLE = "reversible"
CLASS_REVERSIBLE_COSTLY = "reversible-costly"
CLASS_IRREVERSIBLE_FINANCIAL = "irreversible-financial"
CLASS_IRREVERSIBLE_DESTRUCTIVE = "irreversible-destructive"
CLASS_IRREVERSIBLE_EXTERNAL = "irreversible-external"

REVERSIBLE_CLASSES = frozenset({CLASS_REVERSIBLE, CLASS_REVERSIBLE_COSTLY})
IRREVERSIBLE_CLASSES = frozenset(
    {
        CLASS_IRREVERSIBLE_FINANCIAL,
        CLASS_IRREVERSIBLE_DESTRUCTIVE,
        CLASS_IRREVERSIBLE_EXTERNAL,
    }
)
KNOWN_CLASSES = REVERSIBLE_CLASSES | IRREVERSIBLE_CLASSES

# Structured verification reasons (stable strings, mirrored by the SDKs).
REASON_INVALID_PROOF = "invalid_proof"
REASON_NOT_EXECUTE = "not_execute_credential"
REASON_INTENT_MISMATCH = "intent_mismatch"
REASON_UNAUTHORIZED_EXECUTOR = "unauthorized_executor"
REASON_WINDOW_NOT_ELAPSED = "challenge_window_not_elapsed"
REASON_VETOED = "vetoed"


class DeliberationError(Exception):
    """Raised on malformed deliberation input."""


# ---------------------------------------------------------------------------
# Low-level helpers (kept local so the module stands alone, matching
# vouch.accountability and vouch.reasoning)
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise DeliberationError(f"malformed timestamp: {s!r}") from exc


def _mb64(b: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise DeliberationError("signing requires a Signer with an Ed25519 key")
    return raw


def _attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    credential["proof"] = data_integrity.build_proof(
        credential, _raw_priv(signer), signer.verification_method_id()
    )
    return credential


def _type_list(credential: Dict[str, Any]) -> list:
    t = credential.get("type") or []
    return [t] if isinstance(t, str) else list(t)


def action_digest(intent: Dict[str, Any]) -> str:
    """Multibase SHA-256 over the JCS-canonical action, so the executed action
    must be byte-identical to the announced one."""
    if not isinstance(intent, dict):
        raise DeliberationError("intent must be a JSON object")
    return _mb64(hashlib.sha256(canonicalize(intent)).digest())


def requires_window(reversibility_class: str) -> bool:
    """True if the class must deliberate before executing."""
    return reversibility_class not in REVERSIBLE_CLASSES


# ---------------------------------------------------------------------------
# Phase one: the Intent Credential
# ---------------------------------------------------------------------------


def commit_intent(
    signer: Any,
    *,
    intent: Dict[str, Any],
    reversibility_class: str,
    min_seconds: int = 0,
    veto_authorities: Optional[Iterable[str]] = None,
    broadcast: Optional[Iterable[str]] = None,
    opens_at: Optional[datetime] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Issue a ``VouchIntentCredential`` announcing an action before it executes.

    The credential fixes the exact action by digest and declares a challenge
    window: how long a verifier must wait (``min_seconds``), when it opens, which
    DIDs may object (``veto_authorities``), and where the intent is broadcast.
    Broadcast the returned credential to those channels so objectors can see it.

    Args:
        signer: The acting agent's ``Signer``.
        intent: The action to be taken (``action``/``target``/``resource``).
        reversibility_class: One of the module's class constants. Irreversible
            classes require ``min_seconds > 0``.
        min_seconds: Minimum deliberation window, in seconds.
        veto_authorities: DIDs permitted to block execution during the window.
        broadcast: Opaque channel locators the intent is published to.
        opens_at: Window open time (defaults to now, UTC).
        credential_id: Optional credential id (defaults to a ``urn:uuid``).
    """
    if not isinstance(intent, dict) or not intent.get("action") or not intent.get("target"):
        raise DeliberationError("intent must be a dict with at least action and target")
    if reversibility_class not in KNOWN_CLASSES:
        raise DeliberationError(f"unknown reversibility class: {reversibility_class!r}")
    if requires_window(reversibility_class) and min_seconds <= 0:
        raise DeliberationError(
            f"class {reversibility_class!r} is irreversible and requires min_seconds > 0"
        )

    opened = (opens_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    window: Dict[str, Any] = {
        "minSeconds": int(min_seconds),
        "opensAt": _iso(opened),
        "vetoAuthorities": list(veto_authorities or []),
    }
    if broadcast:
        window["broadcast"] = list(broadcast)

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", INTENT_TYPE],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": signer.get_did(),
        "validFrom": _iso(opened),
        "credentialSubject": {
            "intent": dict(intent),
            "actionDigest": {"algorithm": DIGEST_ALGORITHM, "digest": action_digest(intent)},
            "reversibilityClass": reversibility_class,
            "challengeWindow": window,
        },
    }
    return _attach_proof(credential, signer)


def verify_intent(
    credential: Dict[str, Any], public_key: Any
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Verify an intent credential's proof and structure. Returns (ok, subject)."""
    from vouch.verifier import _coerce_ed25519_public_key

    if INTENT_TYPE not in _type_list(credential):
        return False, None
    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return False, None
    except ValueError:
        return False, None
    subject = credential.get("credentialSubject") or {}
    if not (subject.get("actionDigest") or {}).get("digest"):
        return False, None
    return True, subject


# ---------------------------------------------------------------------------
# The Veto Credential (issued during the window by an authorized objector)
# ---------------------------------------------------------------------------


def veto_intent(
    veto_signer: Any,
    *,
    intent_credential: Dict[str, Any],
    reason: str = "",
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Issue a ``VouchVetoCredential`` blocking a committed intent.

    Signed by an objector (whose DID should appear in the intent's
    ``vetoAuthorities``), it binds to the intent's action digest so a verifier can
    match it to exactly this intent.
    """
    subject = intent_credential.get("credentialSubject") or {}
    digest = (subject.get("actionDigest") or {}).get("digest")
    if not digest:
        raise DeliberationError("intent credential has no action digest to veto")

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", VETO_TYPE],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": veto_signer.get_did(),
        "validFrom": _iso(datetime.now(timezone.utc)),
        "credentialSubject": {
            "intentDigest": {"algorithm": DIGEST_ALGORITHM, "digest": digest},
            "decision": "block",
            "reason": reason,
        },
    }
    return _attach_proof(credential, veto_signer)


def _veto_blocks(
    veto: Dict[str, Any],
    intent_digest: str,
    veto_authorities: Iterable[str],
    veto_public_keys: Dict[str, Any],
) -> bool:
    """A veto blocks iff it verifies under a listed authority's key, decides
    'block', and binds to this intent's digest."""
    from vouch.verifier import _coerce_ed25519_public_key

    if VETO_TYPE not in _type_list(veto):
        return False
    issuer = veto.get("issuer")
    if issuer not in set(veto_authorities):
        return False
    key = veto_public_keys.get(issuer)
    resolved = _coerce_ed25519_public_key(key) if key is not None else None
    if resolved is None:
        return False
    try:
        if not data_integrity.verify_proof(veto, resolved):
            return False
    except ValueError:
        return False
    subject = veto.get("credentialSubject") or {}
    if subject.get("decision") != "block":
        return False
    return (subject.get("intentDigest") or {}).get("digest") == intent_digest


# ---------------------------------------------------------------------------
# Phase two: the Execute Credential
# ---------------------------------------------------------------------------


def execute(
    signer: Any,
    *,
    intent_credential: Dict[str, Any],
    closed_at: Optional[datetime] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Issue a ``VouchExecuteCredential`` for a committed intent after its window.

    ``closed_at`` records when the window is claimed to have closed; a verifier
    rejects it if that is earlier than ``opensAt + minSeconds``. The credential
    references the intent and repeats its digest, so the executed action is bound
    to exactly what was announced.
    """
    subject = intent_credential.get("credentialSubject") or {}
    digest = (subject.get("actionDigest") or {}).get("digest")
    if not digest:
        raise DeliberationError("intent credential has no action digest")

    closed = (closed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", EXECUTE_TYPE],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": signer.get_did(),
        "validFrom": _iso(closed),
        "credentialSubject": {
            "intentRef": intent_credential.get("id"),
            "intentDigest": {"algorithm": DIGEST_ALGORITHM, "digest": digest},
            "intent": dict(subject.get("intent") or {}),
            "windowEvidence": {"mode": "timestamp", "closedAt": _iso(closed)},
        },
    }
    return _attach_proof(credential, signer)


def check_execution(
    execute_credential: Dict[str, Any],
    intent_credential: Dict[str, Any],
    executor_public_key: Any,
    *,
    intent_public_key: Any = None,
    vetoes: Optional[List[Dict[str, Any]]] = None,
    veto_public_keys: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    Verify a two-phase execution; return None on success or a structured reason.

    Checks the executor's proof, that the executed action matches the committed
    intent digest, that the executor is the intent's issuer, that the challenge
    window has provably elapsed, and that no valid veto from a listed authority
    blocks it. Pass ``intent_public_key`` to also verify the intent's own proof,
    and ``vetoes`` plus ``veto_public_keys`` (issuer DID -> key) to enforce vetoes.
    """
    from vouch.verifier import _coerce_ed25519_public_key

    if EXECUTE_TYPE not in _type_list(execute_credential):
        return REASON_NOT_EXECUTE

    resolved = (
        _coerce_ed25519_public_key(executor_public_key) if executor_public_key is not None else None
    )
    if resolved is None:
        return REASON_INVALID_PROOF
    try:
        if not data_integrity.verify_proof(execute_credential, resolved):
            return REASON_INVALID_PROOF
    except ValueError:
        return REASON_INVALID_PROOF

    if intent_public_key is not None:
        ok, _ = verify_intent(intent_credential, intent_public_key)
        if not ok:
            return REASON_INVALID_PROOF

    esub = execute_credential.get("credentialSubject") or {}
    isub = intent_credential.get("credentialSubject") or {}
    intent_digest = (isub.get("actionDigest") or {}).get("digest")
    exec_digest = (esub.get("intentDigest") or {}).get("digest")

    # The executed action must be byte-identical to the committed one.
    if not intent_digest or exec_digest != intent_digest:
        return REASON_INTENT_MISMATCH
    if "intent" in esub and action_digest(esub["intent"]) != intent_digest:
        return REASON_INTENT_MISMATCH

    # Only the intent's issuer may execute it.
    if execute_credential.get("issuer") != intent_credential.get("issuer"):
        return REASON_UNAUTHORIZED_EXECUTOR

    # The window must provably have elapsed.
    window = isub.get("challengeWindow") or {}
    min_seconds = int(window.get("minSeconds", 0))
    opened = _parse_iso(window.get("opensAt", ""))
    closed = _parse_iso((esub.get("windowEvidence") or {}).get("closedAt", ""))
    if (closed - opened).total_seconds() < min_seconds:
        return REASON_WINDOW_NOT_ELAPSED

    # No valid veto from a listed authority may bind to this intent.
    authorities = window.get("vetoAuthorities") or []
    if vetoes and authorities:
        keys = veto_public_keys or {}
        for v in vetoes:
            if _veto_blocks(v, intent_digest, authorities, keys):
                return REASON_VETOED

    return None


def verify_execution(
    execute_credential: Dict[str, Any],
    intent_credential: Dict[str, Any],
    executor_public_key: Any,
    *,
    intent_public_key: Any = None,
    vetoes: Optional[List[Dict[str, Any]]] = None,
    veto_public_keys: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Convenience wrapper over :func:`check_execution` returning
    ``(ok, credentialSubject)`` in the style of the rest of the SDK.
    """
    reason = check_execution(
        execute_credential,
        intent_credential,
        executor_public_key,
        intent_public_key=intent_public_key,
        vetoes=vetoes,
        veto_public_keys=veto_public_keys,
    )
    if reason is not None:
        return False, None
    return True, execute_credential.get("credentialSubject") or {}


__all__ = [
    "DeliberationError",
    "INTENT_TYPE",
    "EXECUTE_TYPE",
    "VETO_TYPE",
    "CLASS_REVERSIBLE",
    "CLASS_REVERSIBLE_COSTLY",
    "CLASS_IRREVERSIBLE_FINANCIAL",
    "CLASS_IRREVERSIBLE_DESTRUCTIVE",
    "CLASS_IRREVERSIBLE_EXTERNAL",
    "REVERSIBLE_CLASSES",
    "IRREVERSIBLE_CLASSES",
    "action_digest",
    "requires_window",
    "commit_intent",
    "verify_intent",
    "veto_intent",
    "execute",
    "check_execution",
    "verify_execution",
]
