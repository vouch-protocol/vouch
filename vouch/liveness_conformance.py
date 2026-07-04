"""
Liveness-conformance-decaying recognition trust (PAD-073).

A point-in-time recognition or reputation credential stays cryptographically
valid after the recognized deployment goes offline or stops conforming, so the
trust it displays becomes stale. This module binds the trust a verifier consumes
to a continuously updated liveness-conformance signal.

An automated prober periodically re-checks the holder's live surface against
published conformance criteria and emits a signed ``ConformanceReceipt`` per
observation. Because every observation is a signed receipt, the decay is
recomputable from evidence rather than asserted: any verifier can replay the
receipt history and reconstruct the same trust value.

Three properties make the recognition self-correcting:

  - Trust decays as a function of elapsed time since the last independently
    verified passing observation, reusing the trust-entropy half-life model
    (see :mod:`vouch.trust_entropy`). A credential no longer backed by a live
    conforming deployment loses trust on its own.
  - A fresh passing receipt raises the consumable trust back up, since the decay
    is measured from the most recent ``pass``.
  - When conformance fails, or no passing receipt arrives for longer than a
    configured threshold, the credential is revoked through the existing
    BitstringStatusList path (see :mod:`vouch.status_list`), so it reads as
    revoked and not merely low-trust.

Each receipt is an ordinary ``eddsa-jcs-2022`` Verifiable Credential, so it
composes with the rest of the protocol, verifies across the language SDKs, and
can be consumed by aggregated reputation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import data_integrity, status_list
from .signer import Signer
from .verifier import _coerce_ed25519_public_key

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"

CONFORMANCE_RECEIPT_TYPE = "ConformanceReceipt"

RESULT_PASS = "pass"
RESULT_FAIL = "fail"
_VALID_RESULTS = (RESULT_PASS, RESULT_FAIL)


class LivenessError(Exception):
    """Raised on malformed conformance-receipt input."""


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    if not value or not isinstance(value, str):
        raise LivenessError(f"malformed timestamp: {value!r}")
    try:
        if value.endswith("Z"):
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except (TypeError, ValueError) as exc:
        raise LivenessError(f"malformed timestamp: {value!r}") from exc


def _type_list(credential: Dict[str, Any]) -> list:
    t = credential.get("type") or []
    return [t] if isinstance(t, str) else list(t)


def _at_utc(at_time: datetime) -> datetime:
    if not isinstance(at_time, datetime):
        raise LivenessError("at_time must be a datetime")
    if at_time.tzinfo is None:
        return at_time.replace(tzinfo=timezone.utc)
    return at_time.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Receipt build + verify
# ---------------------------------------------------------------------------


def build_conformance_receipt(
    *,
    subject: str,
    surface: str,
    criteria: str,
    result: str,
    private_key: str,
    did: str,
    observed_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Issue a signed ``ConformanceReceipt`` for one liveness-conformance observation.

    A prober authority (identified by ``did``, signing with ``private_key``)
    re-checks the holder's live ``surface`` against published ``criteria`` and
    records the observed ``result``. The receipt binds the holder DID (``subject``),
    the surface, the criteria, the result, and the observation time, then carries
    an ``eddsa-jcs-2022`` Data Integrity proof so any verifier can confirm the
    prober signed it and replay the observation history.

    Args:
        subject: The holder DID whose deployment was observed.
        surface: The live surface (endpoint or locator) that was probed.
        criteria: Identifier or description of the conformance criteria applied.
        result: The observed result, ``"pass"`` or ``"fail"``.
        private_key: The prober's Ed25519 key as a JWK JSON string.
        did: The prober authority's DID (the receipt issuer).
        observed_at: Observation time (defaults to now, UTC).

    Returns:
        The signed ConformanceReceipt as a credential dict.

    Raises:
        LivenessError: if a required field is missing or ``result`` is not
            ``"pass"`` or ``"fail"``.
    """
    if not subject:
        raise LivenessError("subject (holder DID) is required")
    if not surface:
        raise LivenessError("surface is required")
    if not criteria:
        raise LivenessError("criteria is required")
    if result not in _VALID_RESULTS:
        raise LivenessError(f"result must be one of {_VALID_RESULTS}, got {result!r}")

    observed = _at_utc(observed_at) if observed_at is not None else datetime.now(timezone.utc)
    signer = Signer(private_key=private_key, did=did)

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", CONFORMANCE_RECEIPT_TYPE],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuer": did,
        "validFrom": _iso(observed),
        "credentialSubject": {
            "id": subject,
            "surface": surface,
            "criteria": criteria,
            "result": result,
            "observedAt": _iso(observed),
        },
    }
    credential["proof"] = data_integrity.build_proof(
        credential,
        private_key=signer._raw_priv,
        verification_method=signer.verification_method_id(),
    )
    return credential


def verify_conformance_receipt(
    receipt: Dict[str, Any],
    *,
    public_key: str,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify a ConformanceReceipt's Data Integrity proof and structure.

    Checks that ``receipt`` carries the ConformanceReceipt type, that its proof
    validates against ``public_key`` (the prober's key), and that the subject
    carries a valid ``result``. Returns ``(ok, credentialSubject)``; the subject
    is an empty dict when verification fails.

    Args:
        receipt: A ConformanceReceipt credential dict.
        public_key: The prober's public key as a Multikey, JWK string, JWK dict,
            or ``Ed25519PublicKey``.

    Returns:
        ``(ok, credentialSubject)``.
    """
    if not isinstance(receipt, dict):
        return False, {}
    if CONFORMANCE_RECEIPT_TYPE not in _type_list(receipt):
        return False, {}

    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, {}
    try:
        if not data_integrity.verify_proof(receipt, resolved):
            return False, {}
    except ValueError:
        return False, {}

    subject = receipt.get("credentialSubject") or {}
    if not isinstance(subject, dict):
        return False, {}
    if subject.get("result") not in _VALID_RESULTS:
        return False, {}

    return True, subject


# ---------------------------------------------------------------------------
# Decay + revocation from the receipt history
# ---------------------------------------------------------------------------


def _observed_at(receipt: Dict[str, Any]) -> Optional[datetime]:
    """Read the observation time of a receipt, tolerating malformed entries."""
    subject = receipt.get("credentialSubject") if isinstance(receipt, dict) else None
    if not isinstance(subject, dict):
        return None
    stamp = subject.get("observedAt") or receipt.get("validFrom")
    if not stamp:
        return None
    try:
        return _parse_iso(stamp)
    except LivenessError:
        return None


def _result(receipt: Dict[str, Any]) -> Optional[str]:
    subject = receipt.get("credentialSubject") if isinstance(receipt, dict) else None
    if not isinstance(subject, dict):
        return None
    return subject.get("result")


def last_conformant(receipts: List[Dict[str, Any]]) -> Optional[datetime]:
    """
    Return the latest ``observedAt`` among receipts whose ``result`` is ``"pass"``.

    Returns None when no passing receipt is present. Receipts with a missing or
    malformed observation time are ignored.
    """
    latest: Optional[datetime] = None
    for receipt in receipts or []:
        if _result(receipt) != RESULT_PASS:
            continue
        observed = _observed_at(receipt)
        if observed is None:
            continue
        if latest is None or observed > latest:
            latest = observed
    return latest


def _latest_receipt(receipts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return the receipt with the newest observation time, or None."""
    latest: Optional[Dict[str, Any]] = None
    latest_at: Optional[datetime] = None
    for receipt in receipts or []:
        observed = _observed_at(receipt)
        if observed is None:
            continue
        if latest_at is None or observed > latest_at:
            latest_at = observed
            latest = receipt
    return latest


def consumable_trust(
    receipts: List[Dict[str, Any]],
    *,
    at_time: datetime,
    half_life_days: float = 30.0,
    baseline: float = 100.0,
) -> float:
    """
    Compute the consumable trust of a recognition credential at ``at_time``.

    Trust decays from ``baseline`` by the trust-entropy half-life model over the
    time elapsed since the last passing conformance observation: it halves every
    ``half_life_days`` days. A credential last observed to conform ``half_life_days``
    ago reads at ``baseline / 2``; two half-lives ago, ``baseline / 4``; and so on.

    The value is recomputable: any verifier holding the same signed receipts and
    the same ``at_time`` derives the same number, so the trust is evidence rather
    than an asserted score.

    Args:
        receipts: The holder's ConformanceReceipt history.
        at_time: The moment to evaluate trust at.
        half_life_days: The decay half-life in days (default 30).
        baseline: The trust value at zero elapsed time (default 100).

    Returns:
        A float in ``[0.0, baseline]``. Returns ``0.0`` when no passing receipt
        is present. When ``at_time`` precedes the last passing observation, the
        elapsed time is clamped to zero and the value is ``baseline``.

    Raises:
        LivenessError: if ``half_life_days`` is not positive or ``baseline`` is
            negative.
    """
    if half_life_days <= 0:
        raise LivenessError(f"half_life_days must be positive, got {half_life_days}")
    if baseline < 0:
        raise LivenessError(f"baseline must be non-negative, got {baseline}")

    last = last_conformant(receipts)
    if last is None:
        return 0.0

    now = _at_utc(at_time)
    elapsed_seconds = (now - last).total_seconds()
    if elapsed_seconds <= 0:
        return baseline

    # Trust-entropy half-life decay (see vouch.trust_entropy.half_life_seconds):
    # trust(t) = baseline * 0.5 ** (elapsed / half_life). Reusing the same model
    # keeps this consistent with SessionVoucher decay across the SDK.
    half_life_seconds = half_life_days * 86400.0
    return baseline * (0.5 ** (elapsed_seconds / half_life_seconds))


def should_revoke(
    receipts: List[Dict[str, Any]],
    *,
    at_time: datetime,
    lapse_threshold_days: float,
) -> bool:
    """
    Decide whether a lapsed recognition credential should be auto-revoked.

    Returns True when either the most recent observation is a ``fail``, or no
    passing observation has arrived within ``lapse_threshold_days`` of ``at_time``
    (including the case of no passing receipt at all). Revocation is the automatic
    consequence of failed or absent continuous conformance, not of a manual event.

    Args:
        receipts: The holder's ConformanceReceipt history.
        at_time: The moment to evaluate at.
        lapse_threshold_days: The maximum tolerated gap, in days, since the last
            passing observation before the credential is considered lapsed.

    Returns:
        True if the credential should be revoked, else False.

    Raises:
        LivenessError: if ``lapse_threshold_days`` is negative.
    """
    if lapse_threshold_days < 0:
        raise LivenessError(
            f"lapse_threshold_days must be non-negative, got {lapse_threshold_days}"
        )

    latest = _latest_receipt(receipts)
    if latest is not None and _result(latest) == RESULT_FAIL:
        return True

    last = last_conformant(receipts)
    if last is None:
        return True

    now = _at_utc(at_time)
    elapsed_days = (now - last).total_seconds() / 86400.0
    return elapsed_days > lapse_threshold_days


def revocation_entry(
    *,
    status_list_credential: str,
    status_list_index: int,
    entry_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build the ``credentialStatus`` entry used to revoke a lapsed credential.

    A thin, purpose-named wrapper over
    :func:`vouch.status_list.build_status_list_entry` that fixes the status
    purpose to revocation, so a caller that detects a lapse (via
    :func:`should_revoke`) can flip the credential's bit in the existing
    BitstringStatusList without reaching for a second module.

    Args:
        status_list_credential: URL of the published status list credential.
        status_list_index: Bit index for this credential within the list.
        entry_id: Optional id for the entry.

    Returns:
        A ``credentialStatus`` dict suitable for inclusion on a Vouch Credential.
    """
    return status_list.build_status_list_entry(
        status_list_credential=status_list_credential,
        status_list_index=status_list_index,
        status_purpose=status_list.STATUS_PURPOSE_REVOCATION,
        entry_id=entry_id,
    )


__all__ = [
    "CONFORMANCE_RECEIPT_TYPE",
    "RESULT_PASS",
    "RESULT_FAIL",
    "LivenessError",
    "build_conformance_receipt",
    "verify_conformance_receipt",
    "last_conformant",
    "consumable_trust",
    "should_revoke",
    "revocation_entry",
]
