"""
Offline multi-node trust primitives:

  - PAD-110: swarm-consensus revocation. Attested peers sign evidence-bound
    distress against a misbehaving node; a threshold of distinct signers
    quarantines it locally, bounded and reversible.
  - PAD-111: quorum-of-orbits trust anchoring. A trust-state update is accepted
    only on corroboration by a threshold of anchors from distinct independent
    failure domains, with monotonic-epoch rollback resistance.
  - PAD-116: offline threshold key continuity. A pre-delegated threshold of
    attested members re-issues a mission credential offline, with a continuity link
    a verifier uses to confirm the same identity persisted.

This module verifies the signed artifacts and computes the threshold/diversity
predicates. Attestation of membership and detection of misbehavior are the
caller's concern.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from .identity import RoboticsError
from ._signing import attach_proof
from ._verify import verify_typed_credential

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
DISTRESS_TYPE = "DistressAttestation"
TRUST_STATE_UPDATE_TYPE = "TrustStateUpdate"
KEY_CONTINUITY_PREDELEGATION_TYPE = "KeyContinuityPredelegation"
CONTINUITY_APPROVAL_TYPE = "ContinuityApproval"


# --------------------------------------------------------------------------- #
# PAD-110: swarm-consensus revocation (quarantine)
# --------------------------------------------------------------------------- #


def build_distress_attestation(
    observer_signer: Any,
    *,
    target_did: str,
    reason: str,
    evidence_ref: str,
    epoch: int,
) -> Dict[str, Any]:
    """An attested observer signs evidence-bound distress against a misbehaving target."""
    if not (target_did and reason and evidence_ref):
        raise RoboticsError("target_did, reason, and evidence_ref are required")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", DISTRESS_TYPE],
        "issuer": observer_signer.get_did(),
        "credentialSubject": {
            "id": target_did,
            "observer": observer_signer.get_did(),
            "reason": reason,
            "evidenceRef": evidence_ref,
            "epoch": int(epoch),
        },
    }
    return attach_proof(credential, observer_signer)


def verify_distress_attestation(
    attestation: Dict[str, Any], observer_public_key: Any
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    subject = verify_typed_credential(attestation, observer_public_key, DISTRESS_TYPE)
    return (subject is not None), subject


def is_quarantined(
    distress_subjects: List[Dict[str, Any]],
    *,
    target_did: str,
    threshold: int,
    member_dids: Set[str],
    window: "Optional[Tuple[int, int]]" = None,
) -> bool:
    """
    True if at least `threshold` distinct attested members (in `member_dids`) signed
    distress against `target_did`, optionally within an inclusive epoch `window`.
    The caller passes only signature-verified subjects. Honest-majority assumption:
    sound while fewer than `threshold` present members are malicious.
    """
    if threshold <= 0:
        raise RoboticsError("threshold must be positive")
    signers: Set[str] = set()
    for s in distress_subjects:
        if s.get("id") != target_did:
            continue
        observer = s.get("observer")
        if observer not in member_dids:
            continue
        if window is not None:
            e = s.get("epoch")
            if not isinstance(e, int) or not (window[0] <= e <= window[1]):
                continue
        signers.add(observer)
    return len(signers) >= threshold


# --------------------------------------------------------------------------- #
# PAD-111: quorum-of-orbits trust-state acceptance
# --------------------------------------------------------------------------- #


def build_trust_state_update(
    anchor_signer: Any,
    *,
    scope: str,
    change: Dict[str, Any],
    epoch: int,
    failure_domain: str,
) -> Dict[str, Any]:
    """
    An anchor asserts a trust-state change (an anchor add/remove, a revocation
    delta, a freshness-epoch advance), declaring its own independent failure domain.
    """
    if not (scope and failure_domain):
        raise RoboticsError("scope and failure_domain are required")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", TRUST_STATE_UPDATE_TYPE],
        "issuer": anchor_signer.get_did(),
        "credentialSubject": {
            "id": anchor_signer.get_did(),
            "scope": scope,
            "change": change,
            "epoch": int(epoch),
            "failureDomain": failure_domain,
        },
    }
    return attach_proof(credential, anchor_signer)


def verify_trust_state_update(
    update: Dict[str, Any], anchor_public_key: Any
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    subject = verify_typed_credential(update, anchor_public_key, TRUST_STATE_UPDATE_TYPE)
    return (subject is not None), subject


def accept_trust_state_update(
    corroborating_subjects: List[Dict[str, Any]],
    *,
    current_epoch: int,
    threshold: int,
) -> bool:
    """
    Accept a trust-state change only when at least `threshold` signature-verified
    corroborations agree on the SAME (scope, change, epoch) from DISTINCT failure
    domains, and the epoch is not a rollback (>= current_epoch for the scope).

    The caller passes corroborations already grouped to one change; this enforces
    distinct-domain count and monotonicity.
    """
    if threshold <= 0:
        raise RoboticsError("threshold must be positive")
    if not corroborating_subjects:
        return False
    ref = corroborating_subjects[0]
    scope, change, epoch = ref.get("scope"), ref.get("change"), ref.get("epoch")
    if not isinstance(epoch, int) or epoch < current_epoch:
        return False  # rollback or malformed
    domains: Set[str] = set()
    for s in corroborating_subjects:
        if s.get("scope") != scope or s.get("change") != change or s.get("epoch") != epoch:
            continue
        fd = s.get("failureDomain")
        if fd:
            domains.add(fd)
    return len(domains) >= threshold


# --------------------------------------------------------------------------- #
# PAD-116: offline threshold key continuity
# --------------------------------------------------------------------------- #


def build_key_continuity_predelegation(
    authority_signer: Any,
    *,
    mission_credential_id: str,
    member_dids: List[str],
    threshold: int,
) -> Dict[str, Any]:
    """The authority pre-delegates, while in contact, a threshold of members to re-issue this credential."""
    if threshold <= 0 or threshold > len(set(member_dids)):
        raise RoboticsError("threshold must be in 1..len(member_dids)")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", KEY_CONTINUITY_PREDELEGATION_TYPE],
        "issuer": authority_signer.get_did(),
        "credentialSubject": {
            "id": mission_credential_id,
            "members": sorted(set(member_dids)),
            "threshold": int(threshold),
            "bound": "preserve_or_narrow",
        },
    }
    return attach_proof(credential, authority_signer)


def build_continuity_approval(
    member_signer: Any,
    *,
    reissuance_id: str,
    supersedes: str,
    epoch: int,
) -> Dict[str, Any]:
    """A member signs approval of a re-issuance carrying a continuity link to the retired credential."""
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", CONTINUITY_APPROVAL_TYPE],
        "issuer": member_signer.get_did(),
        "credentialSubject": {
            "id": reissuance_id,
            "member": member_signer.get_did(),
            "supersedes": supersedes,
            "epoch": int(epoch),
        },
    }
    return attach_proof(credential, member_signer)


def verify_key_continuity(
    *,
    predelegation_subject: Dict[str, Any],
    reissuance_id: str,
    supersedes: str,
    approval_subjects: List[Dict[str, Any]],
) -> bool:
    """
    Confirm an offline re-issuance: the pre-delegation authorized the group, at
    least `threshold` distinct authorized members approved THIS re-issuance, and the
    continuity link (supersedes) is present and consistent. Approvals must be
    signature-verified by the caller.
    """
    members = set(predelegation_subject.get("members") or [])
    threshold = predelegation_subject.get("threshold")
    if not isinstance(threshold, int) or threshold <= 0:
        return False
    approvers: Set[str] = set()
    for s in approval_subjects:
        if s.get("id") != reissuance_id or s.get("supersedes") != supersedes:
            continue
        m = s.get("member")
        if m in members:
            approvers.add(m)
    return len(approvers) >= threshold


__all__ = [
    "DISTRESS_TYPE",
    "TRUST_STATE_UPDATE_TYPE",
    "KEY_CONTINUITY_PREDELEGATION_TYPE",
    "CONTINUITY_APPROVAL_TYPE",
    "build_distress_attestation",
    "verify_distress_attestation",
    "is_quarantined",
    "build_trust_state_update",
    "verify_trust_state_update",
    "accept_trust_state_update",
    "build_key_continuity_predelegation",
    "build_continuity_approval",
    "verify_key_continuity",
]
