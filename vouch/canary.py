"""
Canary Commitments for the Heartbeat Protocol.

Implements the commit/reveal chain referenced in Specification §11.3 and
described in detail in §11.7. The mechanism gives the Heartbeat Protocol
a dead-man's-switch property: an agent that stops heartbeating cannot
have its absence covered up, because every heartbeat reveals the secret
committed in the previous one.

Protocol:

  Interval 0:  agent generates secret S_0, sends commitment H(S_0).
  Interval 1:  agent reveals S_0 (plaintext) and commits H(S_1).
         Verifier checks H(revealed S_0) == prior commitment.
  Interval 2:  agent reveals S_1 and commits H(S_2). And so on.

If the agent is offline for an interval, the next heartbeat carrying a
fresh commitment without the matching reveal will be rejected as a
broken chain. Verifiers SHOULD treat a broken canary chain as immediate
revocation of the SessionVoucher: the agent has either failed or been
compromised.

Wire format (embedded in heartbeat_request per §11.3):

  {
   ...,
   "canaryCommitment": "<multibase-encoded SHA-256 of fresh secret>",
   "canaryReveal": "<multibase-encoded prior secret plaintext>"
  }

Both fields use the multibase base64url prefix `u` for byte values.
The first heartbeat in a session has `canaryCommitment` but no `canaryReveal`.
"""

from __future__ import annotations

import base64
import hashlib
import os
import threading
from dataclasses import dataclass, field
from typing import Optional


# Length of canary secrets in bytes. 32 bytes (256 bits) is enough to make
# guessing infeasible while staying small in the heartbeat payload.
CANARY_SECRET_BYTES = 32

# Multibase prefix for base64url-no-pad per the multibase spec.
MULTIBASE_BASE64URL_PREFIX = "u"


class CanaryChainError(Exception):
    """Raised when a canary commit/reveal cycle fails."""


def _encode(b: bytes) -> str:
    return MULTIBASE_BASE64URL_PREFIX + base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _decode(s: str) -> bytes:
    if not s.startswith(MULTIBASE_BASE64URL_PREFIX):
        raise CanaryChainError(
            f"canary values must use multibase prefix {MULTIBASE_BASE64URL_PREFIX!r}, "
            f"got prefix {s[:1]!r}"
        )
    payload = s[1:]
    padding = (-len(payload)) % 4
    try:
        return base64.urlsafe_b64decode(payload + ("=" * padding))
    except Exception as exc:
        raise CanaryChainError(f"failed to decode canary value: {exc}") from exc


def compute_commitment(secret: bytes) -> str:
    """
    Return the multibase-encoded SHA-256 commitment of `secret`.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise CanaryChainError("secret must be bytes")
    if not secret:
        raise CanaryChainError("secret must be non-empty")
    return _encode(hashlib.sha256(bytes(secret)).digest())


def verify_reveal(revealed: str, prior_commitment: str) -> bool:
    """
    Verify that hash(revealed) matches the previously sent commitment.

    Args:
      revealed: Multibase-encoded plaintext secret from the current heartbeat.
      prior_commitment: Multibase-encoded commitment carried in the
        *previous* heartbeat.

    Returns:
      True if the reveal matches the commitment.
    """
    if not revealed:
        raise CanaryChainError("revealed value is required")
    if not prior_commitment:
        raise CanaryChainError("prior_commitment is required")

    revealed_bytes = _decode(revealed)
    expected = compute_commitment(revealed_bytes)
    return _constant_time_eq(expected, prior_commitment)


def _constant_time_eq(a: str, b: str) -> bool:
    """Constant-time string comparison to avoid timing side channels."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


@dataclass
class CanaryHeartbeat:
    """One side of the wire format: what the agent emits each interval."""

    commitment: str
    reveal: Optional[str]

    def to_dict(self) -> dict:
        d: dict = {"canaryCommitment": self.commitment}
        if self.reveal is not None:
            d["canaryReveal"] = self.reveal
        return d


@dataclass
class CanaryChain:
    """
    Stateful canary commit/reveal chain on the agent side.

    Typical lifecycle:

      chain = CanaryChain()
      # First heartbeat: commitment only, no reveal.
      msg = chain.next_heartbeat()
      send_heartbeat(commitment=msg.commitment, reveal=msg.reveal)
      # Subsequent heartbeats: reveal of prior + fresh commitment.
      msg = chain.next_heartbeat()
      send_heartbeat(commitment=msg.commitment, reveal=msg.reveal)

    The chain holds two pieces of state: the current secret (to be
    revealed on the next heartbeat) and a flag for whether this is the
    first interval (which has no prior secret to reveal).

    Thread-safe; safe to invoke from a heartbeat scheduler running in
    a background asyncio task.

    Attributes:
      secret_bytes: Length of each random secret (default 32).
    """

    secret_bytes: int = CANARY_SECRET_BYTES
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _pending_secret: Optional[bytes] = field(default=None, init=False, repr=False)
    _started: bool = field(default=False, init=False)

    def next_heartbeat(self) -> CanaryHeartbeat:
        """
        Advance the chain by one interval and return the heartbeat fields.

        The returned object's `commitment` is the hash of a fresh secret
        the agent must remember; `reveal` is the plaintext of the secret
        committed in the previous interval (None for the very first
        heartbeat).
        """
        with self._lock:
            fresh_secret = os.urandom(self.secret_bytes)
            commitment = compute_commitment(fresh_secret)

            reveal: Optional[str] = None
            if self._pending_secret is not None:
                reveal = _encode(self._pending_secret)

            self._pending_secret = fresh_secret
            self._started = True
            return CanaryHeartbeat(commitment=commitment, reveal=reveal)

    @property
    def has_pending_reveal(self) -> bool:
        """True if the next heartbeat will carry a reveal."""
        return self._pending_secret is not None


@dataclass
class CanaryVerifier:
    """
    Stateful verifier for a canary chain.

    Tracks the last commitment received from a specific agent so that
    each new heartbeat's `canaryReveal` can be checked against it.

    Typical lifecycle:

      verifier = CanaryVerifier()
      # First heartbeat carries commitment only.
      verifier.observe(commitment_0, reveal=None)
      # Second heartbeat must reveal the prior secret.
      ok = verifier.observe(commitment_1, reveal_of_0)
      if not ok:
        reject_session_voucher()

    `observe` returns False if the reveal does not match the prior
    commitment, indicating a broken chain (the agent skipped an
    interval, or was compromised).

    Verifiers SHOULD persist `last_commitment` if they need to survive
    restarts; the state is small (one string per agent).
    """

    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _last_commitment: Optional[str] = field(default=None, init=False)
    _expecting_reveal: bool = field(default=False, init=False)

    def observe(
        self,
        commitment: str,
        reveal: Optional[str] = None,
    ) -> bool:
        """
        Process one observed heartbeat. Returns True if the chain remains
        intact, False if the reveal does not match the prior commitment.

        The very first heartbeat MAY omit `reveal`; subsequent heartbeats
        MUST include it.

        Raises:
          CanaryChainError: on malformed input (e.g., empty commitment).
        """
        if not commitment:
            raise CanaryChainError("commitment is required")

        with self._lock:
            if not self._expecting_reveal:
                # First heartbeat for this session; reveal is optional.
                self._last_commitment = commitment
                self._expecting_reveal = True
                return True

            # Subsequent heartbeats MUST carry a reveal.
            if reveal is None:
                return False

            if self._last_commitment is None:
                raise CanaryChainError(
                    "verifier state corrupted: expecting reveal but no prior commitment"
                )

            try:
                ok = verify_reveal(reveal, self._last_commitment)
            except CanaryChainError:
                return False
            if not ok:
                return False

            self._last_commitment = commitment
            return True

    @property
    def last_commitment(self) -> Optional[str]:
        """The most recent commitment observed, for persistence across restarts."""
        return self._last_commitment

    def reset(self) -> None:
        """Reset chain state, e.g., when starting a fresh session."""
        with self._lock:
            self._last_commitment = None
            self._expecting_reveal = False


__all__ = [
    "CANARY_SECRET_BYTES",
    "MULTIBASE_BASE64URL_PREFIX",
    "CanaryChainError",
    "CanaryChain",
    "CanaryHeartbeat",
    "CanaryVerifier",
    "compute_commitment",
    "verify_reveal",
]
