"""
Tests for the two production deepenings:
  - vouch.robotics.orbital: two-body propagation + reachability (PAD-114)
  - vouch.robotics.accumulator: dynamic revocation SMT + non-revocation (PAD-120)
"""

import math

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    MU_EARTH,
    SparseMerkleTree,
    build_non_revocation_proof,
    build_revocation_accumulator_root,
    kinematically_reachable,
    propagate_two_body,
    reachable_two_body,
    verify_non_revocation,
    verify_non_revocation_proof,
)


def signer(domain):
    kp = generate_identity(domain=domain)
    return Signer(private_key=kp.private_key_jwk, did=kp.did), kp


# --------------------------------------------------------------------------- #
# PAD-114 two-body propagation
# --------------------------------------------------------------------------- #


def _circular_state(radius, mu=MU_EARTH):
    """A circular orbit in the x-y plane: r on +x, v tangential on +y."""
    v = math.sqrt(mu / radius)
    return [radius, 0.0, 0.0], [0.0, v, 0.0]


def test_propagation_preserves_radius_and_speed_on_circular_orbit():
    r0, v0 = _circular_state(7.0e6)
    period = 2 * math.pi * math.sqrt(7.0e6**3 / MU_EARTH)
    r, v = propagate_two_body(r0, v0, period / 4.0)
    # after a quarter period, radius and speed are conserved (two-body, circular)
    assert math.sqrt(sum(c * c for c in r)) == pytest.approx(7.0e6, rel=1e-6)
    assert math.sqrt(sum(c * c for c in v)) == pytest.approx(math.sqrt(MU_EARTH / 7.0e6), rel=1e-6)
    # a quarter orbit rotates +x toward +y: position should be ~ (0, +r, 0)
    assert r[0] == pytest.approx(0.0, abs=1.0)
    assert r[1] == pytest.approx(7.0e6, rel=1e-6)


def test_propagation_full_period_returns_to_start():
    r0, v0 = _circular_state(7.0e6)
    period = 2 * math.pi * math.sqrt(7.0e6**3 / MU_EARTH)
    r, v = propagate_two_body(r0, v0, period)
    for i in range(3):
        assert r[i] == pytest.approx(r0[i], abs=5.0)  # back to start within meters
        assert v[i] == pytest.approx(v0[i], abs=1e-3)


def test_reachable_two_body_coasting_and_maneuver():
    r0, v0 = _circular_state(7.0e6)
    dt = 60.0
    r_pred, _ = propagate_two_body(r0, v0, dt)
    # the exact coasting position is reachable with zero delta-v
    assert reachable_two_body(
        prior_position=r0,
        prior_velocity=v0,
        claimed_position=r_pred,
        elapsed_seconds=dt,
        max_delta_v_mps=0.0,
        tolerance_m=1.0,
    )
    # a position 100 km from the coasting point is NOT reachable with a 1 m/s budget over 60 s
    far = [r_pred[0] + 100_000.0, r_pred[1], r_pred[2]]
    assert not reachable_two_body(
        prior_position=r0,
        prior_velocity=v0,
        claimed_position=far,
        elapsed_seconds=dt,
        max_delta_v_mps=1.0,
    )
    # but a point within dv*dt (1 m/s * 60 s = 60 m) is reachable
    near = [r_pred[0] + 50.0, r_pred[1], r_pred[2]]
    assert reachable_two_body(
        prior_position=r0,
        prior_velocity=v0,
        claimed_position=near,
        elapsed_seconds=dt,
        max_delta_v_mps=1.0,
    )


def test_kinematically_reachable_dispatches_to_two_body():
    r0, v0 = _circular_state(7.0e6)
    dt = 120.0
    r_pred, _ = propagate_two_body(r0, v0, dt)
    env = {"model": "two-body", "maxDeltaVMps": 0.5}
    assert kinematically_reachable(
        prior_position=r0,
        claimed_position=r_pred,
        elapsed_seconds=dt,
        envelope=env,
        prior_velocity=v0,
        tolerance_m=1.0,
    )
    off = [r_pred[0], r_pred[1] + 10_000.0, r_pred[2]]
    assert not kinematically_reachable(
        prior_position=r0, claimed_position=off, elapsed_seconds=dt, envelope=env, prior_velocity=v0
    )


def test_two_body_requires_velocity():
    from vouch.robotics.identity import RoboticsError

    with pytest.raises(RoboticsError):
        kinematically_reachable(
            prior_position=[7e6, 0, 0],
            claimed_position=[7e6, 0, 0],
            elapsed_seconds=1.0,
            envelope={"model": "two-body"},
        )


# --------------------------------------------------------------------------- #
# PAD-120 dynamic revocation accumulator
# --------------------------------------------------------------------------- #


def test_smt_non_revocation_proof_before_and_after_revoke():
    smt = SparseMerkleTree()
    smt.revoke("cred-x")
    smt.revoke("cred-y")
    # cred-z is not revoked -> proof verifies against the current root
    root = smt.root()
    proof = smt.non_revocation_proof("cred-z")
    assert verify_non_revocation_proof(credential_id="cred-z", proof=proof, root=root)
    # a revoked credential's non-revocation proof must NOT verify
    proof_x = smt.non_revocation_proof("cred-x")
    assert not verify_non_revocation_proof(credential_id="cred-x", proof=proof_x, root=root)


def test_smt_incremental_update_changes_root_and_invalidates_stale_proof():
    smt = SparseMerkleTree()
    smt.revoke("a")
    root1 = smt.root()
    proof_z = smt.non_revocation_proof("z")
    assert verify_non_revocation_proof(credential_id="z", proof=proof_z, root=root1)
    # now revoke z; the root changes and the old (pre-revocation) proof no longer holds
    smt.revoke("z")
    root2 = smt.root()
    assert root2 != root1
    assert not verify_non_revocation_proof(
        credential_id="z", proof=smt.non_revocation_proof("z"), root=root2
    )
    # un-revoke restores it
    smt.unrevoke("z")
    assert verify_non_revocation_proof(
        credential_id="z", proof=smt.non_revocation_proof("z"), root=smt.root()
    )


def test_smt_proof_is_compact():
    smt = SparseMerkleTree()
    for i in range(5):
        smt.revoke(f"revoked-{i}")
    proof = smt.non_revocation_proof("still-valid")
    # a sparse tree yields far fewer than DEPTH (256) sibling hashes
    assert len(proof["siblings"]) < 40


def test_signed_accumulator_root_end_to_end():
    auth, kp = signer("authority.example")
    smt = SparseMerkleTree()
    smt.revoke("compromised-agent")
    signed_root = build_revocation_accumulator_root(auth, tree=smt, epoch=42)
    proof = build_non_revocation_proof(tree=smt, credential_id="good-agent")
    assert verify_non_revocation(
        credential_id="good-agent",
        proof=proof,
        signed_root_credential=signed_root,
        authority_public_key=kp.public_key_jwk,
    )
    # the compromised agent cannot produce a passing non-revocation proof against this root
    bad_proof = build_non_revocation_proof(tree=smt, credential_id="compromised-agent")
    assert not verify_non_revocation(
        credential_id="compromised-agent",
        proof=bad_proof,
        signed_root_credential=signed_root,
        authority_public_key=kp.public_key_jwk,
    )
