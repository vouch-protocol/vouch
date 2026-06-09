"""
Ephemeral agent identities for the Vouch Protocol.

When a parent agent spawns a short-lived sub-agent (the kind Claude Code spins
up per task), that sub-agent needs its own verifiable identity so its actions
are attributable, but it does not need a permanent, hosted identity. This module
mints exactly that: a fresh did:key for the child plus a time-bound delegated
credential issued by the parent, scoped to a single intent.

Why did:key for the child:
  A did:key is self-contained. The public key is encoded directly in the DID,
  so nothing has to be published or hosted for a verifier to resolve it. That
  fits a sub-agent that exists for seconds and then disappears.

Why nothing needs cleaning up:
  Auto-expiry is enforced by the credential's `validUntil`. Once `ttl_seconds`
  elapses, every verifier rejects the credential on its temporal check. There is
  no registry entry, no hosted document, and no revocation step: when the child
  is done, its authority simply expires. "Self-cleaning" here means the identity
  has a built-in deadline, not that any background process deletes state.

How the delegation works (see vouch/signer.py and vouch/attenuation.py):
  The parent first issues itself a credential for the broad intent and a longer
  validity window. The child then issues its own credential with
  `parent_credential=<parent credential>` and a shorter TTL. The signer's
  builder appends a delegation link from the parent to the child and enforces
  the capability-attenuation rule: the child must be a proper subset of the
  parent on at least one dimension (here, the shorter time window) and broader
  on none. The verifier re-checks the same rule.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from jwcrypto.common import base64url_decode

from . import multikey
from .keys import generate_identity
from .signer import Signer

# The parent's self-issued credential needs a validity window at least as wide as
# the child's, otherwise the child cannot narrow the time dimension. We give the
# parent a generous head start over the child's TTL so the child's window always
# sits strictly inside the parent's.
_PARENT_VALIDITY_HEADROOM_SECONDS = 3600


@dataclass
class EphemeralIdentity:
    """
    A freshly minted, short-lived identity for a spawned sub-agent.

    Attributes:
      did: The child's did:key. Self-contained; needs no hosting.
      private_key_jwk: The child's Ed25519 private key (JWK JSON string).
        Hand this to the sub-agent process; never log or persist it.
      public_key_jwk: The child's Ed25519 public key (JWK JSON string).
      public_key_multikey: The child's public key in Multikey form (the same
        z-prefixed string embedded in the did:key). Pass this to
        `Verifier.verify_credential(..., public_key=...)`.
      credential: The time-bound delegated Vouch Credential the parent issued
        to the child, scoped to `intent` and expiring after the TTL.
      valid_until: ISO-8601 expiry of the credential (mirrors
        credential["validUntil"]). After this instant the credential is
        rejected by any verifier.
    """

    did: str
    private_key_jwk: str
    public_key_jwk: str
    public_key_multikey: str
    credential: Dict[str, Any]
    valid_until: str


def _did_key_from_public_jwk(public_key_jwk: str) -> str:
    """Derive a did:key (and its Multikey) from an Ed25519 public JWK, offline."""
    jwk = json.loads(public_key_jwk)
    raw = base64url_decode(jwk["x"])
    return "did:key:" + multikey.encode_ed25519_public(raw)


def spawn_ephemeral_identity(
    parent_signer: Signer,
    intent: Dict[str, Any],
    ttl_seconds: int,
    *,
    reputation_score: Optional[int] = None,
) -> EphemeralIdentity:
    """
    Mint a short-lived, self-cleaning identity for a spawned sub-agent.

    The parent delegates scoped, time-bound authority to a brand-new child
    identity. The child gets a did:key (self-contained, nothing to host) and a
    Vouch Credential issued by the parent that is scoped to `intent` and expires
    after `ttl_seconds`. Auto-expiry via the credential's `validUntil` is the
    only cleanup needed.

    Args:
      parent_signer: The parent agent's Signer. Acts as the delegator.
      intent: The scoped intent for the child. MUST contain `action`, `target`,
        and `resource` (the concrete resource URL the action touches). This is
        the authority the child is allowed to exercise.
      ttl_seconds: How long the child's credential stays valid, in seconds.
        After this window the credential is rejected on its temporal check.
      reputation_score: Optional self-reported score in [0, 100] to carry on the
        child's credential.

    Returns:
      An `EphemeralIdentity` with the child's did:key, its private and public
      keys, the delegated credential, and the credential's expiry.

    Raises:
      ValueError: If `intent` is missing required fields or `ttl_seconds` is not
        a positive integer.
    """
    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer")
    for required in ("action", "target", "resource"):
        if not intent.get(required):
            raise ValueError(
                f"intent.{required} is required (action, target, resource must all be set)"
            )

    # 1. Generate a fresh keypair for the child and derive its did:key.
    child_keypair = generate_identity()
    child_did = _did_key_from_public_jwk(child_keypair.public_key_jwk)
    child_multikey = child_did[len("did:key:"):]

    # 2. The parent self-issues a credential for the same intent with a wider
    #    validity window. This is the authority the parent holds and is about to
    #    delegate. Its window must be at least as wide as the child's so the
    #    child can narrow the time dimension (the attenuation rule).
    parent_credential = parent_signer.sign_credential(
        intent=intent,
        valid_seconds=ttl_seconds + _PARENT_VALIDITY_HEADROOM_SECONDS,
        reputation_score=reputation_score,
    )

    # 3. The child issues its own credential, delegating from the parent. The
    #    signer appends a parent -> child delegation link and enforces
    #    capability attenuation. The shorter TTL narrows the time dimension, so
    #    the child capability is a proper subset of the parent's.
    child_signer = Signer(
        private_key=child_keypair.private_key_jwk,
        did=child_did,
    )
    credential = child_signer.sign_credential(
        intent=intent,
        valid_seconds=ttl_seconds,
        reputation_score=reputation_score,
        parent_credential=parent_credential,
    )

    return EphemeralIdentity(
        did=child_did,
        private_key_jwk=child_keypair.private_key_jwk,
        public_key_jwk=child_keypair.public_key_jwk,
        public_key_multikey=child_multikey,
        credential=credential,
        valid_until=credential["validUntil"],
    )
