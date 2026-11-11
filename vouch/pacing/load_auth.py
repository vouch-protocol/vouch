"""
Weight-Bound Load Authorization (PAD-133).

A set of trained parameters, once produced, is a file, and whatever governance
attached to its creation stops at the moment the file exists. This module
extends governance past that moment.

An identifier is derived deterministically from the canonical digest of the
parameter tensors, so the parameters name themselves and no assertion is
involved. A quorum of holders from distinct domains authorizes that identifier
to be loaded, within an envelope, from an anchor time, at a decay rate. A
conforming runtime computes the digest of what it is about to load, derives the
identifier, and admits the load only against a current authorization. It
re-checks while the parameters stay resident, so the envelope narrows as the
authorization ages.

Modifying any parameter yields a different identifier, so an authorization does
not transfer to a modified checkpoint. Continued operation therefore expresses
continuing consent rather than a permission granted once and inherited forever.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ._common import (
    PacingError,
    base_credential,
    digest_of,
    iso,
    mb64,
    now_utc,
    parse_iso,
    subject_of,
    verify_credential,
)
from .pace import (
    CONSEQUENCE_ORDER,
    DEFAULT_THRESHOLDS,
    QuorumPolicy,
    effective_standing,
    permitted_classes,
)

AUTHORIZATION_ENDORSEMENT_TYPE = "VouchLoadAuthorizationEndorsement"
RUNTIME_ATTESTATION_TYPE = "VouchRuntimeAttestation"

REASON_NO_AUTHORIZATION = "no_authorization_for_identifier"
REASON_INVALID_ENDORSEMENT = "invalid_endorsement"
REASON_QUORUM_NOT_MET = "quorum_not_met"
REASON_IDENTIFIER_MISMATCH = "weight_identifier_mismatch"
REASON_STANDING_TOO_LOW = "standing_below_class_threshold"
REASON_CLASS_NOT_IN_ENVELOPE = "deployment_class_not_in_envelope"
REASON_RUNTIME_NOT_ATTESTED = "runtime_class_not_permitted"
REASON_NOT_ATTENUATION = "derived_envelope_expands_authority"


def canonical_tensor_digest(tensors: Sequence[Tuple[str, bytes]]) -> str:
    """
    Digest a parameter set in a declared canonical order and layout.

    Tensors are sorted by name and each contributes its name, its length, and its
    bytes, so the digest is stable across serializations and sensitive to every
    parameter.
    """
    if not tensors:
        raise PacingError("a parameter set must contain at least one tensor")
    hasher = hashlib.sha256()
    hasher.update(b"vouch-pacing-tensors/v1\x00")
    for name, payload in sorted(tensors, key=lambda item: item[0]):
        if not isinstance(name, str) or not isinstance(payload, (bytes, bytearray)):
            raise PacingError("each tensor must be a (name, bytes) pair")
        encoded = name.encode("utf-8")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
        hasher.update(len(payload).to_bytes(8, "big"))
        hasher.update(bytes(payload))
    return mb64(hasher.digest())


def derive_weight_identifier(tensor_digest: str) -> str:
    """
    Derive the identifier the parameters name themselves by.

    The identifier is a function of the tensors alone, so it is recomputable by
    anyone holding them and cannot be claimed for a different parameter set.
    """
    if not tensor_digest or not isinstance(tensor_digest, str):
        raise PacingError("tensor_digest is required")
    payload = b"vouch-pacing-weight-id/v1\x00" + tensor_digest.encode("utf-8")
    return "urn:vouch:weights:" + mb64(hashlib.sha256(payload).digest())


def identifier_for(tensors: Sequence[Tuple[str, bytes]]) -> str:
    """Convenience: digest a parameter set and derive its identifier."""
    return derive_weight_identifier(canonical_tensor_digest(tensors))


def load_authorization(
    *,
    weight_identifier: str,
    envelope: Dict[str, Any],
    decay_lambda: float,
    anchored_at: Optional[datetime] = None,
    initial_standing: float = 1.0,
    conditions: Optional[Dict[str, str]] = None,
    parent_identifier: Optional[str] = None,
    runtime_classes: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """
    Build the unsigned load authorization record for a derived identifier.

    Args:
        weight_identifier: The identifier derived from the parameter tensors.
        envelope: The permitted deployment envelope.
        decay_lambda: The rate at which the authorization's standing decays.
        anchored_at: When standing is measured from. Defaults to now.
        initial_standing: Standing at the anchor time.
        conditions: Conditions referenced by digest, such as a committed policy.
        parent_identifier: The parent parameter set this one was derived from.
        runtime_classes: Runtime classes permitted to perform the load.
    """
    if not weight_identifier.startswith("urn:vouch:weights:"):
        raise PacingError("weight_identifier must be a derived weights identifier")
    if decay_lambda < 0:
        raise PacingError("decay_lambda must be non-negative")
    if not isinstance(envelope, dict) or not envelope:
        raise PacingError("envelope must be a non-empty object")
    anchor = anchored_at or now_utc()
    record: Dict[str, Any] = {
        "type": "VouchLoadAuthorization",
        "weightIdentifier": weight_identifier,
        "envelope": dict(envelope),
        "decayLambda": float(decay_lambda),
        "anchoredAt": iso(anchor),
        "initialStanding": float(initial_standing),
    }
    if conditions:
        record["conditions"] = {str(k): str(v) for k, v in conditions.items()}
    if parent_identifier:
        record["parentIdentifier"] = parent_identifier
    if runtime_classes:
        record["runtimeClasses"] = list(runtime_classes)
    return record


def authorization_digest(record: Dict[str, Any]) -> str:
    """Canonical digest of a load authorization record."""
    return digest_of(record)


def endorse_authorization(holder_signer: Any, record: Dict[str, Any]) -> Dict[str, Any]:
    """One quorum holder's endorsement of a load authorization."""
    return base_credential(
        holder_signer,
        AUTHORIZATION_ENDORSEMENT_TYPE,
        {
            "id": authorization_digest(record),
            "holder": holder_signer.get_did(),
            "weightIdentifier": record.get("weightIdentifier"),
        },
    )


def runtime_attestation(
    runtime_signer: Any, *, runtime_class: str, configuration: Dict[str, Any]
) -> Dict[str, Any]:
    """A runtime attests its own class and configuration before performing a load."""
    return base_credential(
        runtime_signer,
        RUNTIME_ATTESTATION_TYPE,
        {
            "id": runtime_signer.get_did(),
            "runtimeClass": runtime_class,
            "configurationDigest": digest_of(configuration),
        },
    )


def attenuate_envelope(
    envelope: Dict[str, Any],
    standing: float,
    thresholds: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Derive the envelope in force at a given standing.

    Numeric caps scale down with standing, list dimensions are carried through
    unchanged, and the maximum consequence class narrows to the highest class the
    standing still permits. The result is never broader than the authorized
    envelope on any dimension.
    """
    if standing < 0:
        raise PacingError("standing must be non-negative")
    factor = min(1.0, float(standing))
    derived: Dict[str, Any] = {}
    allowed = permitted_classes(standing, thresholds)
    for key, value in envelope.items():
        if key == "maxConsequenceClass":
            if not allowed:
                derived[key] = None
                continue
            authorized_rank = CONSEQUENCE_ORDER.index(value) if value in CONSEQUENCE_ORDER else -1
            permitted_rank = CONSEQUENCE_ORDER.index(allowed[-1])
            rank = min(authorized_rank, permitted_rank) if authorized_rank >= 0 else -1
            derived[key] = CONSEQUENCE_ORDER[rank] if rank >= 0 else None
        elif isinstance(value, bool):
            derived[key] = value
        elif isinstance(value, int):
            derived[key] = int(value * factor)
        elif isinstance(value, float):
            derived[key] = float(value) * factor
        else:
            derived[key] = value
    return derived


def is_attenuation(derived: Dict[str, Any], authorized: Dict[str, Any]) -> bool:
    """
    Check the non-expansion rule over an envelope.

    Default-deny: an unknown shape, a new key, or a widened list is treated as an
    expansion, because a false negative here is an authority-escalation bug.
    """
    if not isinstance(derived, dict) or not isinstance(authorized, dict):
        return False
    if set(derived) - set(authorized):
        return False
    for key, value in derived.items():
        original = authorized[key]
        if key == "maxConsequenceClass":
            if value is None:
                continue
            if value not in CONSEQUENCE_ORDER or original not in CONSEQUENCE_ORDER:
                return False
            if CONSEQUENCE_ORDER.index(value) > CONSEQUENCE_ORDER.index(original):
                return False
        elif isinstance(value, bool) or isinstance(original, bool):
            if value != original:
                return False
        elif isinstance(value, (int, float)) and isinstance(original, (int, float)):
            if value > original + 1e-9:
                return False
        elif isinstance(value, list) and isinstance(original, list):
            if not set(map(str, value)) <= set(map(str, original)):
                return False
        elif value != original:
            return False
    return True


@dataclass
class LoadDecision:
    """The runtime's decision for one load or one resident re-check."""

    admitted: bool
    standing: float
    envelope: Dict[str, Any] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)


def check_load(
    *,
    record: Dict[str, Any],
    endorsements: Sequence[Dict[str, Any]],
    policy: QuorumPolicy,
    holder_public_keys: Dict[str, Any],
    tensors: Sequence[Tuple[str, bytes]],
    deployment_class: str,
    at_time: Optional[datetime] = None,
    pace_lambda: Optional[float] = None,
    thresholds: Optional[Dict[str, float]] = None,
    runtime_class: Optional[str] = None,
) -> LoadDecision:
    """
    Decide whether these exact parameters may be loaded, and under what envelope.

    The identifier is recomputed from the tensors, so an authorization issued for
    different parameters does not apply. The same call serves the resident
    re-check: pass a later ``at_time`` and the standing, and therefore the
    envelope, will have narrowed.
    """
    reasons: List[str] = []
    recomputed = identifier_for(tensors)
    if record.get("weightIdentifier") != recomputed:
        return LoadDecision(False, 0.0, {}, [REASON_IDENTIFIER_MISMATCH])

    digest = authorization_digest(record)
    seen = set()
    for endorsement in endorsements:
        subject = endorsement.get("credentialSubject") or {}
        holder = subject.get("holder")
        if holder not in policy.holders:
            continue
        if not verify_credential(
            endorsement, holder_public_keys.get(holder), AUTHORIZATION_ENDORSEMENT_TYPE
        ):
            reasons.append(REASON_INVALID_ENDORSEMENT)
            continue
        if endorsement.get("issuer") != holder or subject.get("id") != digest:
            reasons.append(REASON_INVALID_ENDORSEMENT)
            continue
        seen.add(holder)
    if len(seen) < policy.minimum:
        reasons.append(REASON_QUORUM_NOT_MET)

    permitted_runtimes = record.get("runtimeClasses")
    if permitted_runtimes and runtime_class not in permitted_runtimes:
        reasons.append(REASON_RUNTIME_NOT_ATTESTED)

    rate = float(pace_lambda if pace_lambda is not None else record.get("decayLambda", 0.0))
    standing = effective_standing(
        anchored_at=parse_iso(str(record.get("anchoredAt"))),
        initial_standing=float(record.get("initialStanding", 1.0)),
        pace_lambda=rate,
        at_time=at_time,
    )
    envelope = dict(record.get("envelope") or {})
    derived = attenuate_envelope(envelope, standing, thresholds)
    if not is_attenuation(derived, envelope):
        reasons.append(REASON_NOT_ATTENUATION)

    table = thresholds or DEFAULT_THRESHOLDS
    if deployment_class not in table:
        reasons.append(REASON_CLASS_NOT_IN_ENVELOPE)
    elif standing < table[deployment_class]:
        reasons.append(REASON_STANDING_TOO_LOW)

    return LoadDecision(not reasons, standing, derived, reasons)
