"""
Attested device census for period compute accounting (PAD-125).

The unit of accounting is the enrolled device population, not the list of
workloads an operator chooses to disclose. Each accelerator is enrolled by a
signed credential binding its own device key to a hardware attestation, the set
of enrollments is accumulated into a Merkle tree, and the root together with the
cardinality forms the census commitment for a period.

The census is a chained quantity. The population for a period is derived from
the previous census plus signed enrollment and decommission records, so a device
cannot appear or disappear without a dated, attributable credential saying so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ._common import (
    PacingError,
    base_credential,
    digest_bytes,
    mb64,
    merkle_root,
    subject_of,
    verify_credential,
)

ENROLLMENT_TYPE = "VouchDeviceEnrollmentCredential"
DECOMMISSION_TYPE = "VouchDeviceDecommissionCredential"

REASON_INVALID_PROOF = "invalid_proof"
REASON_DUPLICATE_DEVICE = "duplicate_device"
REASON_UNKNOWN_DEVICE = "unknown_device"
REASON_OPERATOR_MISMATCH = "operator_mismatch"
REASON_CENSUS_MISMATCH = "census_mismatch"


def enroll_device(
    operator_signer: Any,
    *,
    device_did: str,
    device_id: str,
    hardware_attestation: Dict[str, Any],
    device_class: str = "accelerator",
) -> Dict[str, Any]:
    """
    Issue an enrollment credential binding a device key to the operator.

    Args:
        operator_signer: The operator's ``Signer``.
        device_did: The device's own decentralized identifier.
        device_id: A stable device identifier such as a serial number.
        hardware_attestation: The device's hardware attestation evidence, carried
            opaquely and bound by the credential's canonical digest.
        device_class: The class of device being enrolled.
    """
    if not device_did or not isinstance(device_did, str):
        raise PacingError("device_did is required")
    if not device_id or not isinstance(device_id, str):
        raise PacingError("device_id is required")
    if not isinstance(hardware_attestation, dict):
        raise PacingError("hardware_attestation must be a JSON object")
    return base_credential(
        operator_signer,
        ENROLLMENT_TYPE,
        {
            "id": device_did,
            "deviceId": device_id,
            "deviceClass": device_class,
            "operator": operator_signer.get_did(),
            "hardwareAttestation": dict(hardware_attestation),
        },
    )


def decommission_device(
    operator_signer: Any,
    *,
    device_did: str,
    period: str,
    reason: str,
    census_commitment: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Issue a decommission or maintenance record explaining a device's absence.

    A device that contributes no work record for a period must be covered by one
    of these, otherwise the period accounting is incomplete and the restraint
    attestation over it does not verify.
    """
    if not device_did or not isinstance(device_did, str):
        raise PacingError("device_did is required")
    if not period or not isinstance(period, str):
        raise PacingError("period is required")
    if not reason or not isinstance(reason, str):
        raise PacingError("reason is required")
    subject: Dict[str, Any] = {
        "id": device_did,
        "operator": operator_signer.get_did(),
        "period": period,
        "reason": reason,
    }
    if census_commitment:
        subject["censusCommitment"] = census_commitment
    return base_credential(operator_signer, DECOMMISSION_TYPE, subject)


def _enrollment_leaf(credential: Dict[str, Any]) -> bytes:
    """The census leaf value for an enrollment credential."""
    return digest_bytes(credential)


@dataclass(frozen=True)
class Census:
    """An operator's enrolled device population for a period."""

    operator: str
    root: str
    cardinality: int
    device_dids: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def commitment(self) -> Dict[str, Any]:
        """The published census commitment: root plus cardinality."""
        return {"operator": self.operator, "root": self.root, "cardinality": self.cardinality}

    @property
    def commitment_digest(self) -> str:
        """A single string identifying this census, used to bind records to it."""
        return mb64(digest_bytes(self.commitment))

    def contains(self, device_did: str) -> bool:
        """True if the device is in this census."""
        return device_did in self.device_dids


def build_census(
    operator_did: str,
    enrollments: Sequence[Dict[str, Any]],
    device_public_keys: Dict[str, Any],
) -> Tuple[Optional[Census], List[str]]:
    """
    Build a census from verified enrollment credentials.

    Every enrollment must carry a valid proof from the operator, name the same
    operator, and name a device exactly once. Returns ``(census, reasons)``; the
    census is None when any reason is present.

    Args:
        operator_did: The operator whose census this is.
        enrollments: Enrollment credentials.
        device_public_keys: Map of operator DID to public key, used to verify the
            issuer proof on each enrollment.
    """
    reasons: List[str] = []
    seen: Dict[str, Dict[str, Any]] = {}
    operator_key = device_public_keys.get(operator_did)
    for credential in enrollments:
        if not verify_credential(credential, operator_key, ENROLLMENT_TYPE):
            reasons.append(REASON_INVALID_PROOF)
            continue
        subject = subject_of(credential)
        if subject.get("operator") != operator_did or credential.get("issuer") != operator_did:
            reasons.append(REASON_OPERATOR_MISMATCH)
            continue
        device_did = subject.get("id")
        if not isinstance(device_did, str) or not device_did:
            reasons.append(REASON_UNKNOWN_DEVICE)
            continue
        if device_did in seen:
            reasons.append(REASON_DUPLICATE_DEVICE)
            continue
        seen[device_did] = credential
    if reasons:
        return None, reasons

    ordered = sorted(seen.items(), key=lambda item: item[0])
    leaves = [_enrollment_leaf(credential) for _, credential in ordered]
    census = Census(
        operator=operator_did,
        root=mb64(merkle_root(leaves)),
        cardinality=len(leaves),
        device_dids=tuple(did for did, _ in ordered),
    )
    return census, []


def chain_census(
    prior: Census,
    *,
    enrollments: Sequence[Dict[str, Any]],
    decommissions: Sequence[Dict[str, Any]],
    prior_enrollments: Sequence[Dict[str, Any]],
    public_keys: Dict[str, Any],
) -> Tuple[Optional[Census], List[str]]:
    """
    Derive the next period's census from the prior one plus signed changes.

    An enrollment for a device already present, or a decommission for a device
    not present, is a reason rather than a silent no-op, so the population is an
    accumulated quantity that cannot be restated freely from period to period.
    """
    reasons: List[str] = []
    operator_key = public_keys.get(prior.operator)
    surviving: Dict[str, Dict[str, Any]] = {}

    for credential in prior_enrollments:
        if not verify_credential(credential, operator_key, ENROLLMENT_TYPE):
            reasons.append(REASON_INVALID_PROOF)
            continue
        device_did = subject_of(credential).get("id")
        if isinstance(device_did, str) and prior.contains(device_did):
            surviving[device_did] = credential
    if set(surviving) != set(prior.device_dids):
        reasons.append(REASON_CENSUS_MISMATCH)

    for credential in decommissions:
        if not verify_credential(credential, operator_key, DECOMMISSION_TYPE):
            reasons.append(REASON_INVALID_PROOF)
            continue
        device_did = subject_of(credential).get("id")
        if not isinstance(device_did, str) or device_did not in surviving:
            reasons.append(REASON_UNKNOWN_DEVICE)
            continue
        del surviving[device_did]

    for credential in enrollments:
        if not verify_credential(credential, operator_key, ENROLLMENT_TYPE):
            reasons.append(REASON_INVALID_PROOF)
            continue
        subject = subject_of(credential)
        device_did = subject.get("id")
        if not isinstance(device_did, str) or not device_did:
            reasons.append(REASON_UNKNOWN_DEVICE)
            continue
        if device_did in surviving:
            reasons.append(REASON_DUPLICATE_DEVICE)
            continue
        surviving[device_did] = credential

    if reasons:
        return None, reasons

    ordered = sorted(surviving.items(), key=lambda item: item[0])
    leaves = [_enrollment_leaf(credential) for _, credential in ordered]
    census = Census(
        operator=prior.operator,
        root=mb64(merkle_root(leaves)),
        cardinality=len(leaves),
        device_dids=tuple(did for did, _ in ordered),
    )
    return census, []


def census_device_dids(enrollments: Iterable[Dict[str, Any]]) -> List[str]:
    """Device identifiers named by a set of enrollment credentials, in order."""
    dids: List[str] = []
    for credential in enrollments:
        subject = credential.get("credentialSubject") or {}
        device_did = subject.get("id")
        if isinstance(device_did, str) and device_did:
            dids.append(device_did)
    return dids
