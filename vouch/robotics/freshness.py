"""
DTN freshness: presenter-side proof of freshness and graded trust decay.

Implements the open layer of:

  - PAD-107: a relay-issued FreshnessToken bound to a monotonic network epoch,
    which a disconnected verifier requires to be within a consequence-scaled
    epoch gap of its own last-known epoch. Recency is measured in epochs, not
    wall-clock, so it survives clock drift on a long-disconnected node.
  - PAD-119: a continuously-decaying trust weight as a function of elapsed epochs
    since last trusted contact, admitted against a consequence-scaled threshold.

Epochs are plain non-negative integers advanced by relays; this module does not
advance them (that is a relay/deployment concern), it only builds and checks the
signed artifacts and computes the deterministic predicates.
"""

from __future__ import annotations

import math
import uuid
from typing import Any, Dict, Optional, Tuple

from ..status_list import (
    CONSEQUENCE_CRITICAL,
    CONSEQUENCE_ROUTINE,
    CONSEQUENCE_SENSITIVE,
    VALID_CONSEQUENCE_TIERS,
)
from .identity import RoboticsError
from ._signing import attach_proof
from ._verify import verify_typed_credential

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
FRESHNESS_TOKEN_TYPE = "FreshnessToken"

# Default acceptable epoch gap per consequence tier (PAD-107). Deployment policy;
# the tightest tier tolerates no drift.
DEFAULT_MAX_EPOCH_GAP: Dict[str, int] = {
    CONSEQUENCE_ROUTINE: 100,
    CONSEQUENCE_SENSITIVE: 10,
    CONSEQUENCE_CRITICAL: 1,
}


def build_freshness_token(
    relay_signer: Any,
    *,
    subject_did: str,
    epoch: int,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """
    A relay (freshness anchor) issues `subject_did` a token proving recent contact,
    bound to the current monotonic network `epoch` and an anti-replay nonce.
    """
    if not isinstance(epoch, int) or epoch < 0:
        raise RoboticsError("epoch must be a non-negative integer")
    if not subject_did:
        raise RoboticsError("subject_did is required")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", FRESHNESS_TOKEN_TYPE],
        "issuer": relay_signer.get_did(),
        "credentialSubject": {
            "id": subject_did,
            "epoch": epoch,
            "nonce": nonce or uuid.uuid4().hex,
        },
    }
    return attach_proof(credential, relay_signer)


def verify_freshness_token(
    token: Dict[str, Any],
    relay_public_key: Any,
    *,
    verifier_epoch: int,
    tier: str = CONSEQUENCE_CRITICAL,
    max_epoch_gap: Optional[Dict[str, int]] = None,
    expected_subject: Optional[str] = None,
    seen_epoch: Optional[int] = None,
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a FreshnessToken offline: the relay's proof, and that the token's epoch
    is within the consequence-scaled gap of `verifier_epoch`. An unknown tier is
    treated as critical. `seen_epoch`, when supplied, enforces rollback resistance:
    a token whose epoch precedes the newest already seen for this subject is
    rejected. Returns (ok, credentialSubject).
    """
    subject = verify_typed_credential(token, relay_public_key, FRESHNESS_TOKEN_TYPE)
    if subject is None:
        return False, None
    if expected_subject is not None and subject.get("id") != expected_subject:
        return False, None

    token_epoch = subject.get("epoch")
    if not isinstance(token_epoch, int):
        return False, None
    if seen_epoch is not None and token_epoch < seen_epoch:
        return False, None  # rollback

    if tier not in VALID_CONSEQUENCE_TIERS:
        tier = CONSEQUENCE_CRITICAL
    budget = (max_epoch_gap or DEFAULT_MAX_EPOCH_GAP).get(
        tier, DEFAULT_MAX_EPOCH_GAP[CONSEQUENCE_CRITICAL]
    )
    gap = verifier_epoch - token_epoch
    if gap < 0 or gap > budget:
        return False, None
    return True, subject


def decay_weight(
    *,
    elapsed_epochs: int,
    half_life_epochs: float,
    form: str = "exponential",
) -> float:
    """
    Continuously-decaying trust weight in [0, 1] (PAD-119). `exponential` uses a
    half-life; `linear` ramps to zero at `2 * half_life_epochs`. Deterministic, so
    every disconnected verifier computes the same weight.
    """
    if elapsed_epochs < 0:
        raise RoboticsError("elapsed_epochs must be non-negative")
    if half_life_epochs <= 0:
        raise RoboticsError("half_life_epochs must be positive")
    if form == "exponential":
        return 0.5 ** (elapsed_epochs / half_life_epochs)
    if form == "linear":
        return max(0.0, 1.0 - elapsed_epochs / (2.0 * half_life_epochs))
    raise RoboticsError(f"unknown decay form: {form!r}")


# Default minimum remaining trust weight required per consequence tier (PAD-119).
DEFAULT_WEIGHT_THRESHOLD: Dict[str, float] = {
    CONSEQUENCE_ROUTINE: 0.1,
    CONSEQUENCE_SENSITIVE: 0.5,
    CONSEQUENCE_CRITICAL: 0.9,
}


def decay_permits(
    *,
    elapsed_epochs: int,
    half_life_epochs: float,
    tier: str = CONSEQUENCE_CRITICAL,
    form: str = "exponential",
    thresholds: Optional[Dict[str, float]] = None,
) -> bool:
    """Admit an action only if the decayed weight meets the consequence-scaled threshold."""
    if tier not in VALID_CONSEQUENCE_TIERS:
        tier = CONSEQUENCE_CRITICAL
    weight = decay_weight(
        elapsed_epochs=elapsed_epochs, half_life_epochs=half_life_epochs, form=form
    )
    need = (thresholds or DEFAULT_WEIGHT_THRESHOLD).get(
        tier, DEFAULT_WEIGHT_THRESHOLD[CONSEQUENCE_CRITICAL]
    )
    return weight >= need


__all__ = [
    "FRESHNESS_TOKEN_TYPE",
    "DEFAULT_MAX_EPOCH_GAP",
    "DEFAULT_WEIGHT_THRESHOLD",
    "build_freshness_token",
    "verify_freshness_token",
    "decay_weight",
    "decay_permits",
]
