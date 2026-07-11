"""
Root of Trust for robot identity: bind a hardware-rooted robot to a recognized
manufacturer, anchored to one pinned Vouch Protocol root.

The Root of Trust for Machine Identity lets a pinned Vouch root recognize issuers,
and a recognized issuer bind a subject DID to attributes, verified offline against
the one pinned root. This extends that to robots. A recognized manufacturer (an
issuer the root granted the ``issueRobotIdentity`` action) issues an identity that
binds a robot's DID and its hardware-rooted key to attributes such as make, model,
serial, and owner. The robot separately holds a hardware-attested RobotIdentityCredential
(vouch.robotics.identity) proving its key is bound to a secure element.

`verify_robot_identity_chain` closes the loop: from one pinned root, a verifier
confirms both that the robot is a legitimate robot from a recognized manufacturer
(the authority chain) and that the key the manufacturer vouched for is genuinely
hardware-rooted (the secure-element attestation), and that the two name the same
robot and the same key. It follows the anchor-once model and the reason-code style
of the underlying root_of_trust.

This is the open layer: a single recognized manufacturer issues the identity and a
single pinned root anchors it. Quorum issuance across multiple recognized
manufacturers and continuous behavioral binding of the robot to its identity are
out of scope for the open layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Optional

from vouch import multikey, root_of_trust
from vouch.verifier import _coerce_ed25519_public_key

from .identity import verify_robot_identity

ACTION_ISSUE_ROBOT_IDENTITY = root_of_trust.ACTION_ISSUE_ROBOT_IDENTITY


@dataclass
class RobotIdentityChainResult:
    """
    Outcome of :func:`verify_robot_identity_chain`.

      ok: True only if the authority chain verified against the pinned root AND the
        vouched key is hardware-rooted for the same robot.
      reason: Structured failure reason when ok is False, else None.
      robot_did: The robot the identity describes.
      issuer_did: The recognized manufacturer that issued the identity.
      root_did: The pinned Vouch root the chain anchored to.
      attributes: The identity attributes the manufacturer bound.
      hardware_rooted: True when the vouched key is secure-element-rooted.
    """

    ok: bool
    reason: Optional[str] = None
    robot_did: Optional[str] = None
    issuer_did: Optional[str] = None
    root_did: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = field(default=None)
    hardware_rooted: bool = False


def build_robot_identity(
    issuer_signer: Any,
    *,
    robot_did: str,
    hardware_key_multibase: str,
    attributes: Dict[str, Any],
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
    created: Optional[datetime] = None,
    credential_status: Optional[Dict[str, Any]] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Issue an authority robot identity: a recognized manufacturer binds `robot_did`,
    its hardware-rooted key (`hardware_key_multibase`, the robot's Ed25519 key as a
    multikey), and identity `attributes` (make, model, serial, owner). The manufacturer
    must be a recognized issuer for the ``issueRobotIdentity`` action. The credential is
    an AgentIdentityCredential so the shared identity-chain verification applies, with the
    hardware key and a robot marker carried in the bound identity attributes.
    """
    if not robot_did:
        raise ValueError("robot_did is required")
    if not hardware_key_multibase:
        raise ValueError("hardware_key_multibase is required")
    if not isinstance(attributes, dict) or not attributes:
        raise ValueError("attributes must be a non-empty dict")

    bound = dict(attributes)
    bound["kind"] = "robot"
    bound["hardwareKey"] = hardware_key_multibase

    kwargs: Dict[str, Any] = {
        "subject_did": robot_did,
        "attributes": bound,
        "valid_from": valid_from,
        "created": created,
        "credential_status": credential_status,
        "credential_id": credential_id,
    }
    if valid_seconds is not None:
        kwargs["valid_seconds"] = valid_seconds
    return root_of_trust.build_agent_identity(issuer_signer, **kwargs)


def verify_robot_identity_chain(
    authority_identity: Dict[str, Any],
    recognized_issuer_credential: Dict[str, Any],
    robot_hardware_credential: Dict[str, Any],
    *,
    trusted_root: str,
    robot_public_key: Any,
    root_credential: Optional[Dict[str, Any]] = None,
    allow_did_resolution: bool = False,
    trusted_roots: Optional[Dict[str, str]] = None,
    clock_skew_seconds: int = 30,
    is_revoked: Optional[Callable[[Dict[str, Any]], bool]] = None,
) -> RobotIdentityChainResult:
    """
    Verify a robot's identity against a single pinned Vouch root, confirming both
    provenance and hardware-rooting.

    From `trusted_root`, the pinned root DID:

    1. The authority chain: the recognized manufacturer must be recognized by the
       pinned root for the ``issueRobotIdentity`` action, and the authority identity
       must be signed by that manufacturer (via the shared identity-chain verify).
    2. The vouched key: the authority identity must carry a hardware key.
    3. The hardware root: the robot's own RobotIdentityCredential must verify under
       `robot_public_key` and its secure-element attestation, name the same robot,
       and its key must equal the key the manufacturer vouched for.

    Returns a :class:`RobotIdentityChainResult` with a reason code on any failure,
    matching the anchor-once, reason-code style of the underlying root_of_trust.
    """
    chain = root_of_trust.verify_identity_chain(
        authority_identity,
        recognized_issuer_credential,
        trusted_root=trusted_root,
        required_action=ACTION_ISSUE_ROBOT_IDENTITY,
        root_credential=root_credential,
        allow_did_resolution=allow_did_resolution,
        trusted_roots=trusted_roots,
        clock_skew_seconds=clock_skew_seconds,
        is_revoked=is_revoked,
    )
    if not chain.ok:
        return RobotIdentityChainResult(ok=False, reason=chain.reason, root_did=trusted_root)

    attributes = chain.attributes if isinstance(chain.attributes, dict) else {}
    hardware_key = attributes.get("hardwareKey")
    if not hardware_key:
        return RobotIdentityChainResult(
            ok=False, reason="identity_no_hardware_key", root_did=trusted_root
        )

    hw_ok, hw_subject = verify_robot_identity(robot_hardware_credential, robot_public_key)
    if not hw_ok or hw_subject is None:
        return RobotIdentityChainResult(
            ok=False, reason="hardware_root_invalid", root_did=trusted_root
        )
    if hw_subject.get("id") != chain.agent_did:
        return RobotIdentityChainResult(
            ok=False, reason="hardware_subject_mismatch", root_did=trusted_root
        )

    resolved = (
        _coerce_ed25519_public_key(robot_public_key) if robot_public_key is not None else None
    )
    if resolved is None:
        return RobotIdentityChainResult(
            ok=False, reason="hardware_key_unresolvable", root_did=trusted_root
        )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    robot_key_mb = multikey.encode_ed25519_public(
        resolved.public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    if robot_key_mb != hardware_key:
        return RobotIdentityChainResult(
            ok=False, reason="hardware_key_mismatch", root_did=trusted_root
        )

    return RobotIdentityChainResult(
        ok=True,
        robot_did=chain.agent_did,
        issuer_did=chain.issuer_did,
        root_did=trusted_root,
        attributes=attributes,
        hardware_rooted=True,
    )


__all__ = [
    "ACTION_ISSUE_ROBOT_IDENTITY",
    "RobotIdentityChainResult",
    "build_robot_identity",
    "verify_robot_identity_chain",
]
