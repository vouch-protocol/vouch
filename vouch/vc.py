"""
Verifiable Credential envelope for Vouch Protocol.

Builds a `VouchCredential` per Specification §5: a VC Data Model 2.0
credential carrying an agent's intent, optional reputation, and optional
delegation chain, secured by a Data Integrity proof (eddsa-jcs-2022).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"

VC_TYPE = "VerifiableCredential"
VOUCH_CREDENTIAL_TYPE = "VouchCredential"
SESSION_VOUCHER_TYPE = "SessionVoucher"

PROTOCOL_VERSION = "1.0"


def build_vouch_credential(
    issuer_did: str,
    intent: Dict[str, Any],
    *,
    valid_seconds: int = 300,
    reputation_score: Optional[int] = None,
    delegation_chain: Optional[List[Dict[str, Any]]] = None,
    credential_id: Optional[str] = None,
    valid_from: Optional[datetime] = None,
    credential_status: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Construct an unsigned Vouch Credential. Caller is responsible for attaching
    a Data Integrity proof via `data_integrity.build_proof`.

    Args:
      issuer_did: DID of the issuing agent (e.g., "did:web:agent.example.com").
      intent: Intent payload. MUST contain `action`, `target`, `resource`.
      valid_seconds: Validity window in seconds. Default 300 (5 minutes).
      reputation_score: Optional self-reported score in [0, 100].
      delegation_chain: Optional ordered list of delegation links.
      credential_id: Optional credential ID. Defaults to a fresh UUID URN.
      valid_from: Optional override for `validFrom`. Defaults to current UTC.
      credential_status: Optional W3C `credentialStatus` entry, typically built
        via `status_list.build_status_list_entry` to reference a
        BitstringStatusListCredential (Specification §11.2).

    Returns:
      A dict suitable for proof attachment.
    """
    _validate_intent(intent)

    issued_at = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = issued_at + timedelta(seconds=valid_seconds)

    subject: Dict[str, Any] = {
        "id": issuer_did,
        "vouchVersion": PROTOCOL_VERSION,
        "intent": intent,
    }

    if reputation_score is not None:
        subject["reputationScore"] = max(0, min(100, int(reputation_score)))

    if delegation_chain:
        subject["delegationChain"] = delegation_chain

    vc: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "id": credential_id or _new_uuid_urn(),
        "type": [VC_TYPE, VOUCH_CREDENTIAL_TYPE],
        "issuer": issuer_did,
        "validFrom": _iso(issued_at),
        "validUntil": _iso(expires_at),
        "credentialSubject": subject,
    }

    if credential_status is not None:
        vc["credentialStatus"] = credential_status

    return vc


def build_session_voucher(
    subject_did: str,
    validator_dids: List[str],
    *,
    decay_lambda: float,
    initial_trust: float,
    max_ttl_seconds: int,
    scope: List[str],
    valid_seconds: int = 60,
) -> Dict[str, Any]:
    """
    Construct an unsigned SessionVoucher credential (Specification §11.4).
    Each validator in `validator_dids` will attach a separate proof.
    """
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(seconds=valid_seconds)
    return {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "id": _new_uuid_urn(),
        "type": [VC_TYPE, SESSION_VOUCHER_TYPE],
        "issuer": validator_dids,
        "validFrom": _iso(issued_at),
        "validUntil": _iso(expires_at),
        "credentialSubject": {
            "id": subject_did,
            "decayLambda": decay_lambda,
            "initialTrust": initial_trust,
            "maxTtl": max_ttl_seconds,
            "scope": scope,
        },
    }


def _validate_intent(intent: Dict[str, Any]) -> None:
    if not isinstance(intent, dict):
        raise TypeError("intent must be a dict")
    for required in ("action", "target", "resource"):
        if required not in intent or intent[required] in (None, ""):
            raise ValueError(
                f"intent.{required} is REQUIRED (Specification §5.4.1) — "
                "Vouch credentials MUST bind to a concrete resource"
            )


def _new_uuid_urn() -> str:
    return f"urn:uuid:{uuid.uuid4()}"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
