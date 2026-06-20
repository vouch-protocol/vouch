"""
Reputation receipts and normalization (reputation Phase 1).

Reputation is computed from signed receipts about an agent DID. This module
defines the two new receipt types that the agent cannot self-issue, the
relying-party `StateReceipt` and the authority `PenaltyReceipt`, and a
`normalize_receipt` that turns any of the four receipt types (these two plus the
existing OutcomeAttestation and ReviewCredential) into dimensioned `Signal`s for
the aggregation function in Phase 2.

A receipt is an eddsa-jcs-2022 Verifiable Credential whose subject is the agent
being rated and which is tied to an `interactionId`. Normalization is read-only:
it inspects the credential `type` and shape, so it does not import the modules
that mint the other two types.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import data_integrity

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"

STATE_RECEIPT_TYPE = "StateReceipt"
PENALTY_RECEIPT_TYPE = "PenaltyReceipt"
OUTCOME_ATTESTATION_TYPE = "OutcomeAttestationCredential"
REVIEW_CREDENTIAL_TYPE = "ReviewCredential"

RELIABILITY = "reliability"
PERFORMANCE = "performance"
COMPLIANCE = "compliance"
SATISFACTION = "satisfaction"
KNOWN_DIMENSIONS = {RELIABILITY, PERFORMANCE, COMPLIANCE, SATISFACTION}


class ReceiptError(Exception):
    """Raised on malformed receipt input."""


@dataclass
class Signal:
    """A single normalized reputation contribution. `value` is in [-1, 1]."""

    dimension: str
    value: float
    source_type: str
    issuer: str
    interaction_id: str
    timestamp: datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _clamp(x: float, lo: float = -1.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise ReceiptError("signing requires a Signer with an Ed25519 key")
    return raw


def _attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    credential["proof"] = data_integrity.build_proof(
        credential, _raw_priv(signer), signer.verification_method_id()
    )
    return credential


def _type_list(credential: Dict[str, Any]) -> list:
    t = credential.get("type") or []
    return [t] if isinstance(t, str) else list(t)


def _verify(credential: Dict[str, Any], public_key: Any) -> bool:
    from vouch.verifier import _coerce_ed25519_public_key

    pub = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if pub is None:
        return False
    try:
        return data_integrity.verify_proof(credential, pub)
    except ValueError:
        return False


def _base(issuer: str, type_name: str, valid_from: Optional[datetime]) -> Dict[str, Any]:
    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", type_name],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuer": issuer,
        "validFrom": _iso(issued),
    }


# ---------------------------------------------------------------------------
# StateReceipt: the relying party attests the result of an agent's action
# ---------------------------------------------------------------------------


def build_state_receipt(
    relying_party_signer: Any,
    *,
    agent: str,
    interaction_id: str,
    action: str,
    result: str,
    sla_met: Optional[bool] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Issue a StateReceipt signed by the relying party the agent acted on. `result`
    is "success" or "failure". The agent cannot mint this, so it is an admissible
    objective signal.
    """
    if result not in ("success", "failure"):
        raise ReceiptError("result must be 'success' or 'failure'")
    cred = _base(relying_party_signer.get_did(), STATE_RECEIPT_TYPE, valid_from)
    subject: Dict[str, Any] = {
        "id": agent,
        "interactionId": interaction_id,
        "action": action,
        "result": result,
    }
    if sla_met is not None:
        subject["slaMet"] = sla_met
    cred["credentialSubject"] = subject
    return _attach_proof(cred, relying_party_signer)


def verify_state_receipt(receipt: Dict[str, Any], public_key: Any):
    if STATE_RECEIPT_TYPE not in _type_list(receipt):
        return False, None
    if not _verify(receipt, public_key):
        return False, None
    return True, receipt.get("credentialSubject") or {}


# ---------------------------------------------------------------------------
# PenaltyReceipt: an authority records a violation
# ---------------------------------------------------------------------------


def build_penalty_receipt(
    authority_signer: Any,
    *,
    agent: str,
    interaction_id: str,
    kind: str,
    severity: float = 1.0,
    dimension: str = COMPLIANCE,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Issue a PenaltyReceipt signed by a validator or authority. `kind` is a label
    (revocation, slash, heartbeat-lapse, kill-switch, policy-violation);
    `severity` in [0, 1] sets the magnitude of the negative signal.
    """
    cred = _base(authority_signer.get_did(), PENALTY_RECEIPT_TYPE, valid_from)
    cred["credentialSubject"] = {
        "id": agent,
        "interactionId": interaction_id,
        "kind": kind,
        "severity": float(severity),
        "dimension": dimension,
    }
    return _attach_proof(cred, authority_signer)


def verify_penalty_receipt(receipt: Dict[str, Any], public_key: Any):
    if PENALTY_RECEIPT_TYPE not in _type_list(receipt):
        return False, None
    if not _verify(receipt, public_key):
        return False, None
    return True, receipt.get("credentialSubject") or {}


# ---------------------------------------------------------------------------
# Subject and normalization
# ---------------------------------------------------------------------------


def receipt_subject(credential: Dict[str, Any]) -> Optional[str]:
    """The agent DID a receipt is about. Callers group receipts by this."""
    return (credential.get("credentialSubject") or {}).get("id")


def normalize_receipt(credential: Dict[str, Any]) -> List[Signal]:
    """Turn one receipt into zero or more dimensioned Signals."""
    types = _type_list(credential)
    issuer = credential.get("issuer") or ""
    subject = credential.get("credentialSubject") or {}
    try:
        ts = _parse_iso(credential.get("validFrom"))
    except (TypeError, ValueError):
        ts = datetime.now(timezone.utc)
    iid = subject.get("interactionId") or credential.get("id") or ""

    def sig(dim: str, value: float, source: str) -> Signal:
        return Signal(dim, _clamp(value), source, issuer, iid, ts)

    if STATE_RECEIPT_TYPE in types:
        out: List[Signal] = []
        result = subject.get("result")
        if result == "success":
            out.append(sig(RELIABILITY, 1.0, STATE_RECEIPT_TYPE))
        elif result == "failure":
            out.append(sig(RELIABILITY, -1.0, STATE_RECEIPT_TYPE))
        sla = subject.get("slaMet")
        if sla is True:
            out.append(sig(PERFORMANCE, 1.0, STATE_RECEIPT_TYPE))
        elif sla is False:
            out.append(sig(PERFORMANCE, -1.0, STATE_RECEIPT_TYPE))
        return out

    if OUTCOME_ATTESTATION_TYPE in types:
        matches = (subject.get("outcome") or {}).get("matchesCommitment")
        if matches is True:
            return [sig(RELIABILITY, 1.0, OUTCOME_ATTESTATION_TYPE)]
        if matches is False:
            return [sig(RELIABILITY, -1.0, OUTCOME_ATTESTATION_TYPE)]
        return []

    if PENALTY_RECEIPT_TYPE in types:
        dim = subject.get("dimension") or COMPLIANCE
        sev = _clamp(float(subject.get("severity", 1.0)), 0.0, 1.0)
        return [sig(dim, -sev, PENALTY_RECEIPT_TYPE)]

    if REVIEW_CREDENTIAL_TYPE in types:
        out = []
        for k, r in (subject.get("ratings") or {}).items():
            dim = k if k in KNOWN_DIMENSIONS else SATISFACTION
            out.append(sig(dim, (float(r) - 3.0) / 2.0, REVIEW_CREDENTIAL_TYPE))
        return out

    return []


__all__ = [
    "STATE_RECEIPT_TYPE",
    "PENALTY_RECEIPT_TYPE",
    "OUTCOME_ATTESTATION_TYPE",
    "REVIEW_CREDENTIAL_TYPE",
    "RELIABILITY",
    "PERFORMANCE",
    "COMPLIANCE",
    "SATISFACTION",
    "KNOWN_DIMENSIONS",
    "ReceiptError",
    "Signal",
    "build_state_receipt",
    "verify_state_receipt",
    "build_penalty_receipt",
    "verify_penalty_receipt",
    "receipt_subject",
    "normalize_receipt",
]
