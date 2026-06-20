"""
Robot liveness heartbeat with safety-envelope conformance attestation.

A robot's identity and capability credentials, once minted, are otherwise valid
until something revokes them. This module makes robot trust living: the robot
periodically re-attests that it is alive and that its actual motion over the last
interval stayed inside the physical envelope its capability credential permits. A
verifier then treats the robot as trusted only while a fresh, conformant
heartbeat exists, inverting the model from "trusted until revoked" to "untrusted
until renewed", the same inversion the agent Heartbeat Protocol applies, adapted
to physical telemetry.

The per-interval "motion digest" is the physical analogue of the agent
behavioral digest. It carries aggregates of what the robot actually did over the
interval (peak force, peak speed, peak speed while a human was near, count of
zone breaches) and asserts whether those stayed inside the declared envelope:

  {
    "samples": <int>,                  # telemetry samples observed this interval
    "maxForceN": <number>,             # peak force observed, newtons
    "maxSpeedMps": <number>,           # peak speed observed, m/s
    "maxSpeedNearHumansMps": <number>, # peak speed observed while a human was near
    "zoneBreaches": <int>,             # samples observed outside an allowed zone
    "breachCount": <int>,              # total samples that violated the envelope
    "withinEnvelope": <bool>           # breachCount == 0
  }

A RobotHeartbeatCredential is an eddsa-jcs-2022 VC carrying the robot DID, a
session id, the interval index, the declared interval length, and the motion
digest, signed by the robot's own key. Trust freshness is evaluated by
`is_live`, which requires both a recent heartbeat and an in-envelope digest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any, Dict, List, Optional

from .capability import PhysicalAction, check_physical_action
from .identity import RoboticsError
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
ROBOT_HEARTBEAT_TYPE = "RobotHeartbeatCredential"

# Default number of missed intervals tolerated before trust is considered stale.
DEFAULT_GRACE_INTERVALS = 2


@dataclass
class MotionSample:
    """One observed motion sample, used for testing and audit."""

    force_n: Optional[float]
    speed_mps: Optional[float]
    near_humans: bool
    zone: Optional[str]
    timestamp_ns: int


@dataclass
class MotionCollector:
    """
    Thread-safe collector for per-interval motion telemetry.

    The collector accumulates aggregates of what the robot physically did over a
    heartbeat interval and, when given the robot's physical scope, counts how
    many samples fell outside the declared envelope.

    Typical lifecycle:

      collector = MotionCollector(scope=physical_scope_subject["physicalScope"])
      # ... during the interval, the controller records each commanded motion ...
      collector.record(force_n=12.0, speed_mps=0.4, near_humans=True, zone="cell-3")
      # ... heartbeat time ...
      digest = collector.digest()
      collector.reset()

    Attributes:
      scope: Optional physicalScope object (the credentialSubject.physicalScope
        from a PhysicalCapabilityScope credential). When supplied, each recorded
        sample is checked against it and breaches are counted. When omitted, the
        digest still reports observed maxima but cannot judge conformance, so it
        reports withinEnvelope true with a zero breach count.
    """

    scope: Optional[Dict[str, Any]] = None
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _samples: int = field(default=0, init=False)
    _max_force: float = field(default=0.0, init=False)
    _max_speed: float = field(default=0.0, init=False)
    _max_speed_near: float = field(default=0.0, init=False)
    _zone_breaches: int = field(default=0, init=False)
    _breaches: int = field(default=0, init=False)
    _audit: List[MotionSample] = field(default_factory=list, init=False, repr=False)

    def record(
        self,
        *,
        force_n: Optional[float] = None,
        speed_mps: Optional[float] = None,
        near_humans: bool = False,
        zone: Optional[str] = None,
        time_hm: Optional[str] = None,
    ) -> None:
        """
        Record a single observed motion sample.

        Args:
          force_n: Force exerted in this sample, newtons.
          speed_mps: Speed in this sample, m/s.
          near_humans: Whether a human was within the safety distance.
          zone: Zone id the robot was operating in.
          time_hm: Local "HH:MM" the sample occurred, for shift-window checks.
        """
        if force_n is not None and force_n < 0:
            raise RoboticsError(f"force_n must be non-negative, got {force_n}")
        if speed_mps is not None and speed_mps < 0:
            raise RoboticsError(f"speed_mps must be non-negative, got {speed_mps}")

        with self._lock:
            self._samples += 1
            if force_n is not None:
                self._max_force = max(self._max_force, float(force_n))
            if speed_mps is not None:
                self._max_speed = max(self._max_speed, float(speed_mps))
                if near_humans:
                    self._max_speed_near = max(self._max_speed_near, float(speed_mps))

            if self.scope is not None:
                action = PhysicalAction(
                    force_n=force_n,
                    speed_mps=speed_mps,
                    near_humans=near_humans,
                    zone=zone,
                    time_hm=time_hm,
                )
                result = check_physical_action(self.scope, action)
                if not result.ok:
                    self._breaches += 1
                    if any(r.startswith("zone_not_allowed") for r in result.reasons):
                        self._zone_breaches += 1

            if len(self._audit) < 4096:
                self._audit.append(
                    MotionSample(
                        force_n=float(force_n) if force_n is not None else None,
                        speed_mps=float(speed_mps) if speed_mps is not None else None,
                        near_humans=near_humans,
                        zone=zone,
                        timestamp_ns=_now_ns(),
                    )
                )

    def snapshot_samples(self) -> List[MotionSample]:
        """Return a copy of the per-sample audit trail (not part of the digest)."""
        with self._lock:
            return list(self._audit)

    def digest(self) -> Dict[str, Any]:
        """Return the motionDigest object for embedding in a heartbeat credential."""
        with self._lock:
            return {
                "samples": self._samples,
                "maxForceN": self._max_force,
                "maxSpeedMps": self._max_speed,
                "maxSpeedNearHumansMps": self._max_speed_near,
                "zoneBreaches": self._zone_breaches,
                "breachCount": self._breaches,
                "withinEnvelope": self._breaches == 0,
            }

    def reset(self) -> None:
        """Clear all state. Call after submitting a heartbeat to start fresh."""
        with self._lock:
            self._samples = 0
            self._max_force = 0.0
            self._max_speed = 0.0
            self._max_speed_near = 0.0
            self._zone_breaches = 0
            self._breaches = 0
            self._audit.clear()


def validate_motion_digest(digest: Dict[str, Any]) -> None:
    """
    Structural validation of a motionDigest object. Raises RoboticsError on
    malformed input. Does not judge whether the values are acceptable; that is
    policy, expressed through `is_live` and the verifier's thresholds.
    """
    if not isinstance(digest, dict):
        raise RoboticsError("motionDigest must be a dict")

    for name in ("samples", "zoneBreaches", "breachCount"):
        if name not in digest:
            raise RoboticsError(f"motionDigest.{name} is required")
        if not isinstance(digest[name], int) or isinstance(digest[name], bool) or digest[name] < 0:
            raise RoboticsError(f"motionDigest.{name} must be a non-negative integer")

    for name in ("maxForceN", "maxSpeedMps", "maxSpeedNearHumansMps"):
        if name not in digest:
            raise RoboticsError(f"motionDigest.{name} is required")
        if isinstance(digest[name], bool) or not isinstance(digest[name], (int, float)):
            raise RoboticsError(f"motionDigest.{name} must be a number")
        if digest[name] < 0:
            raise RoboticsError(f"motionDigest.{name} must be non-negative")

    if "withinEnvelope" not in digest:
        raise RoboticsError("motionDigest.withinEnvelope is required")
    if not isinstance(digest["withinEnvelope"], bool):
        raise RoboticsError("motionDigest.withinEnvelope must be a boolean")


def build_robot_heartbeat(
    signer: Any,
    *,
    session_id: str,
    interval_index: int,
    motion_digest: Dict[str, Any],
    interval_seconds: int,
    issued_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed RobotHeartbeatCredential.

    The robot self-issues the credential with its own Vouch key. `motion_digest`
    is produced by a MotionCollector over the interval; `interval_seconds` is the
    declared heartbeat cadence, which a verifier uses to judge freshness.
    """
    if interval_index < 0:
        raise RoboticsError("interval_index must be non-negative")
    if interval_seconds <= 0:
        raise RoboticsError("interval_seconds must be positive")
    validate_motion_digest(motion_digest)

    issued = (issued_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    robot_did = signer.get_did()
    subject: Dict[str, Any] = {
        "id": robot_did,
        "sessionId": session_id,
        "intervalIndex": interval_index,
        "intervalSeconds": interval_seconds,
        "motionDigest": motion_digest,
    }
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", ROBOT_HEARTBEAT_TYPE],
        "issuer": robot_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    return attach_proof(credential, signer)


def verify_robot_heartbeat(
    credential: Dict[str, Any],
    robot_public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a RobotHeartbeatCredential: the credential proof (robot key) and the
    structural validity of the embedded motion digest. Returns (ok, subject).

    This checks authenticity and shape only. Whether the robot is currently
    trusted is a separate, time-dependent question answered by `is_live`.
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = credential.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if ROBOT_HEARTBEAT_TYPE not in type_field:
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
    digest = subject.get("motionDigest")
    try:
        validate_motion_digest(digest)
    except RoboticsError:
        return False, None

    return True, subject


def is_live(
    credential: Dict[str, Any],
    *,
    now: Optional[datetime] = None,
    interval_seconds: Optional[int] = None,
    grace_intervals: int = DEFAULT_GRACE_INTERVALS,
) -> bool:
    """
    Decide whether a robot is currently trusted, given its most recent heartbeat.

    A robot is live only if BOTH hold:
      1. Freshness: the heartbeat was issued within `grace_intervals` cadence
         periods of `now`. A robot that stopped sending heartbeats loses trust.
      2. Conformance: the heartbeat's motion digest reports withinEnvelope true.
         A robot that exceeded its physical envelope loses trust even if recent.

    `interval_seconds` defaults to the value the heartbeat itself declares. The
    caller should still pass the cadence it expects when it does not trust the
    robot's self-declared interval.
    """
    subject = credential.get("credentialSubject") or {}
    digest = subject.get("motionDigest") or {}
    if not digest.get("withinEnvelope", False):
        return False

    cadence = interval_seconds if interval_seconds is not None else subject.get("intervalSeconds")
    if not isinstance(cadence, int) or cadence <= 0:
        return False
    if grace_intervals < 1:
        raise RoboticsError("grace_intervals must be at least 1")

    raw = credential.get("validFrom")
    if not raw:
        return False
    try:
        issued = _parse_iso(raw)
    except (ValueError, TypeError):
        return False

    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    deadline = issued + timedelta(seconds=cadence * grace_intervals)
    # A heartbeat from the future (clock skew beyond one cadence) is not trusted.
    if moment + timedelta(seconds=cadence) < issued:
        return False
    return moment <= deadline


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _now_ns() -> int:
    import time as _time

    return _time.time_ns()


__all__ = [
    "ROBOT_HEARTBEAT_TYPE",
    "DEFAULT_GRACE_INTERVALS",
    "MotionSample",
    "MotionCollector",
    "validate_motion_digest",
    "build_robot_heartbeat",
    "verify_robot_heartbeat",
    "is_live",
]
