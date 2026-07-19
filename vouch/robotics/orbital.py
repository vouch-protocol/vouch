"""
Two-body orbital propagation for the kinematic-plausibility filter (PAD-114).

The reference `kinematically_reachable` used a crude speed/delta-v ball. For a
spacecraft that is a poor bound: the vehicle coasts on an orbit, so its unforced
future position is highly constrained and computable. This module propagates the
prior state vector under two-body (Keplerian) gravity using the universal-variable
formulation (robust for elliptic, parabolic, and hyperbolic orbits), then the
reachable set is a ball around the propagated position whose radius is the maximum
maneuver (delta-v) budget times the elapsed time — a first-order bound on how far a
burn can displace the vehicle.

This is standard astrodynamics (Kepler's problem via universal anomaly and Stumpff
functions; Vallado / Curtis). Units are SI: meters, m/s, seconds; mu in m^3/s^2.
"""

from __future__ import annotations

import math
from typing import List, Sequence, Tuple

from .identity import RoboticsError

Vec3 = Sequence[float]

# Earth gravitational parameter (m^3/s^2); callers pass their own for other bodies.
MU_EARTH = 3.986004418e14


def _stumpff_c(z: float) -> float:
    if z > 1e-12:
        sz = math.sqrt(z)
        return (1.0 - math.cos(sz)) / z
    if z < -1e-12:
        sz = math.sqrt(-z)
        return (math.cosh(sz) - 1.0) / (-z)
    return 0.5


def _stumpff_s(z: float) -> float:
    if z > 1e-12:
        sz = math.sqrt(z)
        return (sz - math.sin(sz)) / (sz ** 3)
    if z < -1e-12:
        sz = math.sqrt(-z)
        return (math.sinh(sz) - sz) / (sz ** 3)
    return 1.0 / 6.0


def _dot(a: Vec3, b: Vec3) -> float:
    return sum(float(a[i]) * float(b[i]) for i in range(3))


def _norm(a: Vec3) -> float:
    return math.sqrt(_dot(a, a))


def propagate_two_body(
    r0: Vec3,
    v0: Vec3,
    dt: float,
    mu: float = MU_EARTH,
    *,
    max_iter: int = 100,
    tol: float = 1e-8,
) -> "Tuple[List[float], List[float]]":
    """
    Propagate a state vector (position `r0`, velocity `v0`) forward by `dt` seconds
    under two-body gravity `mu`, using universal variables. Returns (r, v).

    `dt` may be negative (propagate backward). Raises RoboticsError on a degenerate
    state or non-convergence.
    """
    if len(r0) != 3 or len(v0) != 3:
        raise RoboticsError("r0 and v0 must be 3-vectors")
    if mu <= 0:
        raise RoboticsError("mu must be positive")
    r0 = [float(x) for x in r0]
    v0 = [float(x) for x in v0]
    if dt == 0:
        return r0, v0

    r0mag = _norm(r0)
    v0mag = _norm(v0)
    if r0mag == 0:
        raise RoboticsError("degenerate state: |r0| = 0")

    sqrt_mu = math.sqrt(mu)
    vr0 = _dot(r0, v0) / r0mag
    alpha = 2.0 / r0mag - v0mag * v0mag / mu  # 1 / semi-major axis

    # Initial guess for the universal anomaly chi.
    chi = sqrt_mu * abs(alpha) * dt

    for _ in range(max_iter):
        z = alpha * chi * chi
        c = _stumpff_c(z)
        s = _stumpff_s(z)
        f = (
            (r0mag * vr0 / sqrt_mu) * chi * chi * c
            + (1.0 - alpha * r0mag) * chi ** 3 * s
            + r0mag * chi
            - sqrt_mu * dt
        )
        df = (
            (r0mag * vr0 / sqrt_mu) * chi * (1.0 - alpha * chi * chi * s)
            + (1.0 - alpha * r0mag) * chi * chi * c
            + r0mag
        )
        if df == 0:
            raise RoboticsError("two-body propagation stalled (zero derivative)")
        dchi = f / df
        chi -= dchi
        if abs(dchi) < tol:
            break
    else:
        raise RoboticsError("two-body propagation did not converge")

    z = alpha * chi * chi
    c = _stumpff_c(z)
    s = _stumpff_s(z)

    # Lagrange coefficients.
    fl = 1.0 - (chi * chi / r0mag) * c
    gl = dt - (chi ** 3 / sqrt_mu) * s
    r = [fl * r0[i] + gl * v0[i] for i in range(3)]
    rmag = _norm(r)
    if rmag == 0:
        raise RoboticsError("degenerate propagated state: |r| = 0")
    fdot = (sqrt_mu / (rmag * r0mag)) * (alpha * chi ** 3 * s - chi)
    gdot = 1.0 - (chi * chi / rmag) * c
    v = [fdot * r0[i] + gdot * v0[i] for i in range(3)]
    return r, v


def reachable_two_body(
    *,
    prior_position: Vec3,
    prior_velocity: Vec3,
    claimed_position: Vec3,
    elapsed_seconds: float,
    mu: float = MU_EARTH,
    max_delta_v_mps: float = 0.0,
    tolerance_m: float = 0.0,
) -> bool:
    """
    True if `claimed_position` is reachable from the prior orbital state within
    `elapsed_seconds`: propagate the coasting orbit, then allow a ball of radius
    `max_delta_v_mps * elapsed_seconds` (a first-order maneuver displacement bound),
    plus `tolerance_m` for measurement error.
    """
    if elapsed_seconds < 0:
        raise RoboticsError("elapsed_seconds must be non-negative")
    r_pred, _ = propagate_two_body(prior_position, prior_velocity, elapsed_seconds, mu)
    d = math.sqrt(sum((float(claimed_position[i]) - r_pred[i]) ** 2 for i in range(3)))
    reach = max_delta_v_mps * elapsed_seconds + tolerance_m
    return d <= reach


__all__ = [
    "MU_EARTH",
    "propagate_two_body",
    "reachable_two_body",
]
