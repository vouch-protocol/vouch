"""
Hardware-facing seam for the disconnected-edge primitives.

The disconnected-edge modules (presence, localization, edge_trust, freshness, …)
are deterministic verifier predicates over signed measurements. The measurements
themselves come from platform hardware: a radio or laser ranging its peer, an
attitude solution, a navigation fix, a clock, a radiation monitor, a relay's epoch
counter. This module defines that seam as a small set of typed Protocols a platform
implements, ships reference *simulated* implementations for tests and demos, and
provides capture/verify-live adapters that read a sensor and feed the existing
build/verify functions — so integrating real hardware is implementing an interface,
not rewriting the trust logic.

Nothing here talks to real devices. A flight or field integrator subclasses or
duck-types the Protocols with drivers for its own radio, IMU, GNSS, TPM, etc.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, Sequence, runtime_checkable

Vec3 = Sequence[float]


# --------------------------------------------------------------------------- #
# Sensor Protocols (the seam a platform implements)
# --------------------------------------------------------------------------- #


@runtime_checkable
class NavigationSource(Protocol):
    """Onboard position/velocity solution (GNSS, inertial, star tracker, odometry)."""

    def position(self) -> Vec3: ...
    def velocity(self) -> Vec3: ...


@runtime_checkable
class RangeSensor(Protocol):
    """Measures range in meters to a physical peer identified by `target`."""

    def measure_range_m(self, target: str) -> float: ...


@runtime_checkable
class DopplerSensor(Protocol):
    """Measures Doppler shift (Hz) of a peer's carrier at `carrier_hz`."""

    def measure_doppler_hz(self, target: str, carrier_hz: float) -> float: ...


@runtime_checkable
class PointingSource(Protocol):
    """Narrow-beam terminal attitude: pointing unit vector and beamwidth (radians)."""

    def pointing(self) -> Vec3: ...
    def beamwidth_rad(self) -> float: ...


@dataclass
class TimeQuality:
    source_class: str  # e.g. "gnss", "csac", "rc-oscillator"
    since_discipline_s: float  # seconds since last trusted discipline
    uncertainty_s: float  # bounded time uncertainty


@runtime_checkable
class ClockSource(Protocol):
    """Reports the node's time quality (PAD-115)."""

    def time_quality(self) -> TimeQuality: ...


@runtime_checkable
class EpochSource(Protocol):
    """Monotonic network-epoch counter, advanced by relays (PAD-107)."""

    def current_epoch(self) -> int: ...


@runtime_checkable
class IntegrityMonitor(Protocol):
    """Cumulative key-store integrity risk and optional metrics (PAD-118)."""

    def cumulative_risk(self) -> float: ...
    def metrics(self) -> Dict[str, Any]: ...


# --------------------------------------------------------------------------- #
# Reference simulated implementations (tests, demos, dry runs)
# --------------------------------------------------------------------------- #


@dataclass
class SimulatedNavigation:
    pos: List[float]
    vel: List[float]

    def position(self) -> Vec3:
        return list(self.pos)

    def velocity(self) -> Vec3:
        return list(self.vel)


class SimulatedRangeSensor:
    """Returns preset ranges per target; optional additive bias to model error."""

    def __init__(self, ranges_m: Dict[str, float], bias_m: float = 0.0) -> None:
        self._ranges = dict(ranges_m)
        self._bias = bias_m

    def measure_range_m(self, target: str) -> float:
        if target not in self._ranges:
            raise KeyError(f"no simulated range for target {target!r}")
        return self._ranges[target] + self._bias


class SimulatedDopplerSensor:
    def __init__(self, doppler_hz: Dict[str, float]) -> None:
        self._d = dict(doppler_hz)

    def measure_doppler_hz(self, target: str, carrier_hz: float) -> float:
        return self._d.get(target, 0.0)


@dataclass
class SimulatedPointing:
    point: List[float]
    beam_rad: float

    def pointing(self) -> Vec3:
        return list(self.point)

    def beamwidth_rad(self) -> float:
        return self.beam_rad


@dataclass
class SimulatedClock:
    source_class: str
    since_discipline_s: float
    uncertainty_s: float

    def time_quality(self) -> TimeQuality:
        return TimeQuality(self.source_class, self.since_discipline_s, self.uncertainty_s)


class SimulatedEpochSource:
    """A settable monotonic epoch; `advance` steps it forward as a relay would."""

    def __init__(self, epoch: int = 0) -> None:
        self._epoch = int(epoch)

    def current_epoch(self) -> int:
        return self._epoch

    def advance(self, by: int = 1) -> int:
        if by < 0:
            raise ValueError("epoch only advances forward")
        self._epoch += by
        return self._epoch


@dataclass
class SimulatedIntegrityMonitor:
    risk: float
    _metrics: Optional[Dict[str, Any]] = None

    def cumulative_risk(self) -> float:
        return self.risk

    def metrics(self) -> Dict[str, Any]:
        return dict(self._metrics or {})


# --------------------------------------------------------------------------- #
# Capture adapters: read a sensor, feed the existing build/verify predicates.
# The trust logic is unchanged; these only source the measurements.
# --------------------------------------------------------------------------- #


def capture_presence_attestation(
    signer: Any,
    *,
    peer_did: str,
    nonce: str,
    claimed_position: Vec3,
    range_sensor: RangeSensor,
    tolerance_m: float,
    claimed_velocity: Optional[Vec3] = None,
) -> Dict[str, Any]:
    """Read a live range to `peer_did` and build a PAD-108 presence attestation."""
    from .presence import build_presence_attestation

    measured = range_sensor.measure_range_m(peer_did)
    return build_presence_attestation(
        signer,
        peer_did=peer_did,
        nonce=nonce,
        claimed_position=claimed_position,
        measured_range_m=measured,
        tolerance_m=tolerance_m,
        claimed_velocity=claimed_velocity,
    )


def verify_presence_live(
    attestation: Dict[str, Any],
    public_key: Any,
    *,
    nav: NavigationSource,
    expected_nonce: Optional[str] = None,
):
    """Verify a presence attestation using this verifier's own live position."""
    from .presence import verify_presence_attestation

    return verify_presence_attestation(
        attestation, public_key, verifier_position=nav.position(), expected_nonce=expected_nonce
    )


def capture_range_observation(
    observer_signer: Any,
    *,
    target_did: str,
    nav: NavigationSource,
    range_sensor: RangeSensor,
    nonce: str,
    epoch_source: EpochSource,
) -> Dict[str, Any]:
    """Read own position, a live range to the target, and the current epoch; build a PAD-113 observation."""
    from .localization import build_range_observation

    return build_range_observation(
        observer_signer,
        target_did=target_did,
        observer_position=nav.position(),
        measured_range_m=range_sensor.measure_range_m(target_did),
        nonce=nonce,
        epoch=epoch_source.current_epoch(),
    )


def capture_beam_presence(
    signer: Any,
    *,
    peer_did: str,
    nonce: str,
    pointing_source: PointingSource,
) -> Dict[str, Any]:
    """Read the terminal's live pointing/beamwidth and build a PAD-121 beam-presence factor."""
    from .localization import build_beam_presence

    return build_beam_presence(
        signer,
        peer_did=peer_did,
        nonce=nonce,
        pointing=pointing_source.pointing(),
        beamwidth_rad=pointing_source.beamwidth_rad(),
    )


def capture_time_quality(signer: Any, *, clock: ClockSource) -> Dict[str, Any]:
    """Read the clock's live time quality and build a PAD-115 attestation."""
    from .edge_trust import build_time_quality_attestation

    tq = clock.time_quality()
    return build_time_quality_attestation(
        signer,
        source_class=tq.source_class,
        since_discipline_s=tq.since_discipline_s,
        uncertainty_s=tq.uncertainty_s,
    )


def capture_integrity_risk(
    signer: Any, *, monitor: IntegrityMonitor, prev_hash: Optional[str] = None
) -> Dict[str, Any]:
    """Read the integrity monitor and build a PAD-118 integrity-risk attestation."""
    from .edge_trust import build_integrity_risk_attestation

    return build_integrity_risk_attestation(
        signer,
        cumulative_risk=monitor.cumulative_risk(),
        metrics=monitor.metrics(),
        prev_hash=prev_hash,
    )


def issue_freshness_token(
    relay_signer: Any, *, subject_did: str, epoch_source: EpochSource, nonce: Optional[str] = None
) -> Dict[str, Any]:
    """A relay reads its current epoch and issues a PAD-107 freshness token."""
    from .freshness import build_freshness_token

    return build_freshness_token(
        relay_signer, subject_did=subject_did, epoch=epoch_source.current_epoch(), nonce=nonce
    )


def check_kinematics_live(
    *,
    prior_position: Vec3,
    nav: NavigationSource,
    elapsed_seconds: float,
    envelope: Dict[str, Any],
    prior_velocity: Optional[Vec3] = None,
    tolerance_m: float = 0.0,
) -> bool:
    """Check that this node's live position is kinematically reachable from a prior state (PAD-114)."""
    from .localization import kinematically_reachable

    return kinematically_reachable(
        prior_position=prior_position,
        claimed_position=nav.position(),
        elapsed_seconds=elapsed_seconds,
        envelope=envelope,
        prior_velocity=prior_velocity,
        tolerance_m=tolerance_m,
    )


__all__ = [
    # Protocols
    "NavigationSource",
    "RangeSensor",
    "DopplerSensor",
    "PointingSource",
    "ClockSource",
    "EpochSource",
    "IntegrityMonitor",
    "TimeQuality",
    # Simulated reference implementations
    "SimulatedNavigation",
    "SimulatedRangeSensor",
    "SimulatedDopplerSensor",
    "SimulatedPointing",
    "SimulatedClock",
    "SimulatedEpochSource",
    "SimulatedIntegrityMonitor",
    # Capture / verify-live adapters
    "capture_presence_attestation",
    "verify_presence_live",
    "capture_range_observation",
    "capture_beam_presence",
    "capture_time_quality",
    "capture_integrity_risk",
    "issue_freshness_token",
    "check_kinematics_live",
]
