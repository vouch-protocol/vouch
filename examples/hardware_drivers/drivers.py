"""
Reference driver skeleton for the Vouch disconnected-edge hardware seam.

Copy this file into your platform, rename it, and fill in each `raise
NotImplementedError` with a real device read. Each class implements one Protocol
from `vouch.robotics.hardware`; the Protocols are `runtime_checkable`, so you do
NOT need to inherit anything — matching the method signatures is enough — but
inheriting the ABCs below gives you editor help and a clear checklist.

Once implemented, hand your driver objects to the capture/verify-live adapters
(`capture_presence_attestation`, `verify_presence_live`, `capture_range_observation`,
`capture_time_quality`, `capture_integrity_risk`, `issue_freshness_token`,
`check_kinematics_live`) exactly as the reference `Simulated*` classes are used in
`examples/hardware_seam_demo.py`. The trust logic never changes.

Run `python examples/hardware_drivers/drivers.py` for a self-check that reports
which drivers you have implemented.
"""

from __future__ import annotations

from typing import Any, Dict, List

from vouch.robotics import (
    TimeQuality,
)  # dataclass: (source_class, since_discipline_s, uncertainty_s)

Vec3 = List[float]


class MyNavigation:
    """Position/velocity in your chosen metric frame (meters, m/s). Source: GNSS, INS, star tracker, odometry."""

    def position(self) -> Vec3:
        # TODO: return [x, y, z] from your navigation solution.
        raise NotImplementedError("wire up your GNSS/INS position solution")

    def velocity(self) -> Vec3:
        # TODO: return [vx, vy, vz] from your navigation solution.
        raise NotImplementedError("wire up your GNSS/INS velocity solution")


class MyRangeSensor:
    """One-way/round-trip range in meters to a peer. Source: RF ToF, UWB, laser ranging, acoustic modem."""

    def measure_range_m(self, target: str) -> float:
        # TODO: point/interrogate the link to `target` and return the measured range.
        raise NotImplementedError("wire up your ranging radio / laser terminal")


class MyDopplerSensor:
    """Doppler shift (Hz) of a peer's carrier. Source: receiver frequency estimator."""

    def measure_doppler_hz(self, target: str, carrier_hz: float) -> float:
        # TODO: return the measured carrier shift for `target`.
        raise NotImplementedError("wire up your carrier Doppler estimator")


class MyPointing:
    """Narrow-beam terminal attitude: pointing unit vector and beamwidth (radians). Source: gimbal/ADCS."""

    def pointing(self) -> Vec3:
        # TODO: return the commanded/attested boresight unit vector.
        raise NotImplementedError("wire up your terminal attitude solution")

    def beamwidth_rad(self) -> float:
        # TODO: return the beamwidth in radians (a fixed value is fine).
        raise NotImplementedError("return your terminal's beamwidth")


class MyClock:
    """Time quality. Source: GNSS-disciplined clock, chip-scale atomic clock, or a free-running oscillator model."""

    def time_quality(self) -> TimeQuality:
        # TODO: return TimeQuality(source_class, since_discipline_s, uncertainty_s).
        # Derive uncertainty from the source class and elapsed holdover.
        raise NotImplementedError("report your clock source class and bounded uncertainty")


class MyEpochSource:
    """Monotonic network epoch, advanced by relays. Source: your DTN control plane / relay beacon."""

    def current_epoch(self) -> int:
        # TODO: return the latest network epoch you have observed from a relay.
        raise NotImplementedError("return the latest relay-advanced network epoch")


class MyIntegrityMonitor:
    """Cumulative key-store integrity risk in [0, 1] and optional metrics. Source: dosimeter, ECC/SEU counters."""

    def cumulative_risk(self) -> float:
        # TODO: return a normalized cumulative risk (0 as-new .. 1 fully suspect).
        raise NotImplementedError("map your radiation dose / SEU counts to a normalized risk")

    def metrics(self) -> Dict[str, Any]:
        # TODO: return raw metrics (doseRad, seu, eccFaults, ...); may be {}.
        raise NotImplementedError("return your raw integrity metrics (or {})")


# --------------------------------------------------------------------------- #
# Self-check: which drivers are implemented?
# --------------------------------------------------------------------------- #

_PROBES = {
    "MyNavigation": (MyNavigation, lambda d: (d.position(), d.velocity())),
    "MyRangeSensor": (MyRangeSensor, lambda d: d.measure_range_m("did:web:probe")),
    "MyDopplerSensor": (MyDopplerSensor, lambda d: d.measure_doppler_hz("did:web:probe", 1e9)),
    "MyPointing": (MyPointing, lambda d: (d.pointing(), d.beamwidth_rad())),
    "MyClock": (MyClock, lambda d: d.time_quality()),
    "MyEpochSource": (MyEpochSource, lambda d: d.current_epoch()),
    "MyIntegrityMonitor": (MyIntegrityMonitor, lambda d: (d.cumulative_risk(), d.metrics())),
}


def self_check() -> Dict[str, bool]:
    """Return {driver_name: implemented?}. A driver is 'implemented' if its probe does not raise NotImplementedError."""
    results: Dict[str, bool] = {}
    for name, (cls, probe) in _PROBES.items():
        try:
            probe(cls())
            results[name] = True
        except NotImplementedError:
            results[name] = False
        except Exception:
            # Any other exception means the method ran (and hit real-device code) — count as implemented.
            results[name] = True
    return results


if __name__ == "__main__":
    print("Vouch hardware-seam driver self-check\n" + "-" * 38)
    status = self_check()
    for name, done in status.items():
        print(f"  [{'x' if done else ' '}] {name}")
    remaining = [n for n, d in status.items() if not d]
    if remaining:
        print(f"\n{len(remaining)} driver(s) still to implement: {', '.join(remaining)}")
    else:
        print("\nAll drivers implemented. Hand them to the capture/verify-live adapters.")
