"""
Hardware-rooted robot identity and lifecycle credential profile (Phase 5.1).

A documented profile for a robot's verifiable identity, bound to a hardware root
of trust (a TPM or a secure element), plus a reference implementation. It is the
open, vendor-neutral alternative to closed or state-run robot-ID schemes.

A RobotIdentityCredential is an eddsa-jcs-2022 VC whose subject carries the
robot's make, model, and serial, a lifecycle history, and a `hardwareRoot` block.
The hardware root signs a binding over (robot DID, robot key), so the robot's
software identity key is provably bound to a specific piece of hardware. A
verifier checks both the credential proof (the robot key) and the hardware
attestation (the root key).

The hardware root is pluggable. `SoftwareRootOfTrust` is the reference; a real
deployment substitutes a TPM- or secure-element-backed implementation that signs
with a hardware-resident attestation key. The interface is the contract such a
backend satisfies.
"""

from __future__ import annotations

import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vouch import multikey
from vouch.jcs import canonicalize
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
ROBOT_IDENTITY_TYPE = "RobotIdentityCredential"


class RoboticsError(Exception):
    """Raised on malformed robot-identity input."""


# ---------------------------------------------------------------------------
# Hardware root of trust
# ---------------------------------------------------------------------------


class HardwareRootOfTrust(ABC):
    """
    A hardware-resident key that attests the robot's software identity key.

    A TPM backend signs with an Attestation Key (AK) derived from the
    Endorsement Key; a secure-element backend signs with a device key fused at
    manufacture. Both satisfy this interface.
    """

    @abstractmethod
    def public_key_raw(self) -> bytes:
        """The 32-byte Ed25519 public key of the hardware root."""

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign `data` with the hardware-resident key."""

    @property
    def kind(self) -> str:
        return "Software"

    def public_key_multibase(self) -> str:
        return multikey.encode_ed25519_public(self.public_key_raw())


class SoftwareRootOfTrust(HardwareRootOfTrust):
    """
    Reference root of trust backed by a local Ed25519 key. Stands in for a TPM
    or secure element in development and tests. NOT a hardware root: a real
    deployment MUST use a hardware-backed implementation.
    """

    def __init__(self, seed: Optional[bytes] = None, kind: str = "Software") -> None:
        self._sk = (
            Ed25519PrivateKey.from_private_bytes(seed) if seed else Ed25519PrivateKey.generate()
        )
        self._kind = kind

    def public_key_raw(self) -> bytes:
        return self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)

    @property
    def kind(self) -> str:
        return self._kind


# ---------------------------------------------------------------------------
# Binding and minting
# ---------------------------------------------------------------------------


def _binding_bytes(robot_did: str, robot_key_multibase: str) -> bytes:
    """Canonical bytes the hardware root signs to bind the identity key."""
    return canonicalize({"key": robot_key_multibase, "robotDid": robot_did})


def _mb64(b: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unmb64(s: str) -> bytes:
    if not s.startswith("u"):
        raise RoboticsError("expected multibase 'u' prefix")
    payload = s[1:]
    return base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))


def mint_robot_identity(
    robot_signer: Any,
    root: HardwareRootOfTrust,
    *,
    make: str,
    model: str,
    serial: str,
    owner: Optional[str] = None,
    lifecycle: Optional[List[Dict[str, Any]]] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Mint a hardware-attested RobotIdentityCredential. The robot self-issues the
    credential with its Vouch key (`robot_signer`); the hardware root signs a
    binding over the robot DID and key, embedded as `hardwareRoot.attestation`.
    """
    robot_did = robot_signer.get_did()
    robot_key_mb = robot_signer.get_public_key_multikey()
    attestation = root.sign(_binding_bytes(robot_did, robot_key_mb))

    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "make": make,
        "model": model,
        "serial": serial,
        "hardwareRoot": {
            "kind": root.kind,
            "publicKeyMultibase": root.public_key_multibase(),
            "attestation": _mb64(attestation),
        },
        "lifecycle": lifecycle
        or [
            {"event": "commissioned", "timestamp": _iso(issued)},
        ],
    }
    if owner is not None:
        subject["owner"] = owner

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", ROBOT_IDENTITY_TYPE],
        "issuer": robot_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, robot_signer)


def verify_robot_identity(
    credential: Dict[str, Any],
    robot_public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a RobotIdentityCredential: the credential proof (robot key) AND the
    hardware-root attestation binding the robot key to the hardware. Returns
    (ok, credentialSubject).
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = credential.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if ROBOT_IDENTITY_TYPE not in type_field:
        return False, None

    resolved = (
        _coerce_ed25519_public_key(robot_public_key) if robot_public_key is not None else None
    )
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return False, None
    except ValueError:
        return False, None

    subject = credential.get("credentialSubject") or {}
    hw = subject.get("hardwareRoot") or {}
    hw_mb = hw.get("publicKeyMultibase")
    attestation = hw.get("attestation")
    if not hw_mb or not attestation:
        return False, None

    try:
        alg, hw_raw = multikey.decode(hw_mb)
        if alg != "Ed25519":
            return False, None
        hw_pub = Ed25519PublicKey.from_public_bytes(hw_raw)
        robot_raw = resolved.public_bytes(Encoding.Raw, PublicFormat.Raw)
        robot_key_mb = multikey.encode_ed25519_public(robot_raw)
        binding = _binding_bytes(subject.get("id", ""), robot_key_mb)
        hw_pub.verify(_unmb64(attestation), binding)
    except (InvalidSignature, RoboticsError, ValueError):
        return False, None

    return True, subject


def lifecycle_event(
    event: str,
    *,
    actor: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build a lifecycle history entry (manufactured, commissioned, transferred, decommissioned, ...)."""
    entry: Dict[str, Any] = {
        "event": event,
        "timestamp": _iso(timestamp or datetime.now(timezone.utc)),
    }
    if actor is not None:
        entry["actor"] = actor
    if details is not None:
        entry["details"] = details
    return entry


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "ROBOT_IDENTITY_TYPE",
    "RoboticsError",
    "HardwareRootOfTrust",
    "SoftwareRootOfTrust",
    "mint_robot_identity",
    "verify_robot_identity",
    "lifecycle_event",
]
