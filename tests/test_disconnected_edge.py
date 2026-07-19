"""
Tests for the disconnected-edge robotics primitives:

  - channel-geometry proof of presence (vouch.robotics.presence, PAD-108)
  - ephemeris-scoped delegation authority (vouch.robotics.geoscope, PAD-109)
"""

import math

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    build_geoscoped_grant,
    build_presence_attestation,
    check_presence,
    expected_doppler_hz,
    expected_range_m,
    geoscope_permits,
    radial_velocity_mps,
    region_attenuates,
    region_contains,
    verify_geoscoped_grant,
    verify_presence_attestation,
)
from vouch.robotics.identity import RoboticsError
from vouch.robotics.presence import SPEED_OF_LIGHT_MPS


@pytest.fixture
def verifier():
    kp = generate_identity(domain="verifier.example")
    return Signer(private_key=kp.private_key_jwk, did=kp.did), kp


# --------------------------------------------------------------------------- #
# PAD-108: channel-geometry proof of presence
# --------------------------------------------------------------------------- #


class TestPresenceGeometry:
    def test_expected_range_is_euclidean(self):
        assert expected_range_m([0, 0, 0], [3, 4, 0]) == pytest.approx(5.0)

    def test_expected_range_rejects_bad_vectors(self):
        with pytest.raises(RoboticsError):
            expected_range_m([0, 0], [1, 1, 1])

    def test_check_presence_within_tolerance(self):
        ok, residual = check_presence(
            verifier_position=[0, 0, 0],
            claimed_peer_position=[100, 0, 0],
            measured_range_m=101.0,
            tolerance_m=2.0,
        )
        assert ok and residual == pytest.approx(1.0)

    def test_check_presence_outside_tolerance(self):
        ok, residual = check_presence(
            verifier_position=[0, 0, 0],
            claimed_peer_position=[100, 0, 0],
            measured_range_m=140.0,
            tolerance_m=2.0,
        )
        assert not ok and residual == pytest.approx(40.0)

    def test_radial_velocity_sign(self):
        # peer at +x moving further out (+x) recedes -> positive radial velocity
        assert radial_velocity_mps([0, 0, 0], [100, 0, 0], [10, 0, 0]) == pytest.approx(10.0)
        # moving toward the verifier -> negative
        assert radial_velocity_mps([0, 0, 0], [100, 0, 0], [-10, 0, 0]) == pytest.approx(-10.0)
        # perpendicular motion -> zero radial component
        assert radial_velocity_mps([0, 0, 0], [100, 0, 0], [0, 10, 0]) == pytest.approx(0.0)

    def test_expected_doppler_receding_shifts_down(self):
        shift = expected_doppler_hz([0, 0, 0], [100, 0, 0], [10, 0, 0], carrier_hz=1e9)
        # receding -> negative shift; magnitude = (v/c)*f
        assert shift < 0
        assert abs(shift) == pytest.approx((10.0 / SPEED_OF_LIGHT_MPS) * 1e9)


class TestPresenceAttestation:
    def test_verifies_when_measurement_matches_claim(self, verifier):
        signer, kp = verifier
        att = build_presence_attestation(
            signer,
            peer_did="did:web:peer.example",
            nonce="abc123",
            claimed_position=[100, 0, 0],
            measured_range_m=100.5,
            tolerance_m=1.0,
        )
        ok, subject = verify_presence_attestation(
            att, kp.public_key_jwk, verifier_position=[0, 0, 0], expected_nonce="abc123"
        )
        assert ok and subject["id"] == "did:web:peer.example"

    def test_rejects_replay_from_wrong_location(self, verifier):
        # Attestation was committed for a peer at range ~100 m. A replayer sitting
        # 500 m away produces a measurement the committed geometry cannot explain.
        signer, kp = verifier
        att = build_presence_attestation(
            signer,
            peer_did="did:web:peer.example",
            nonce="n",
            claimed_position=[100, 0, 0],
            measured_range_m=500.0,  # measured far from the claimed 100 m
            tolerance_m=1.0,
        )
        ok, _ = verify_presence_attestation(att, kp.public_key_jwk, verifier_position=[0, 0, 0])
        assert not ok

    def test_rejects_wrong_nonce(self, verifier):
        signer, kp = verifier
        att = build_presence_attestation(
            signer,
            peer_did="did:web:peer",
            nonce="real",
            claimed_position=[10, 0, 0],
            measured_range_m=10.0,
            tolerance_m=0.5,
        )
        ok, _ = verify_presence_attestation(
            att, kp.public_key_jwk, verifier_position=[0, 0, 0], expected_nonce="forged"
        )
        assert not ok

    def test_rejects_tampered_signature(self, verifier):
        signer, kp = verifier
        att = build_presence_attestation(
            signer,
            peer_did="did:web:peer",
            nonce="n",
            claimed_position=[10, 0, 0],
            measured_range_m=10.0,
            tolerance_m=0.5,
        )
        att["credentialSubject"]["geometry"]["measuredRangeM"] = 10.0000001  # tamper post-sign
        # A different verifier key must reject it regardless.
        other = generate_identity(domain="other.example")
        ok, _ = verify_presence_attestation(att, other.public_key_jwk, verifier_position=[0, 0, 0])
        assert not ok


# --------------------------------------------------------------------------- #
# PAD-109: ephemeris-scoped delegation authority
# --------------------------------------------------------------------------- #


class TestRegionPredicates:
    def test_sphere_contains(self):
        r = {"type": "sphere", "centerM": [0, 0, 0], "radiusM": 10.0}
        assert region_contains(r, [3, 4, 0])  # dist 5 <= 10
        assert not region_contains(r, [9, 9, 0])  # dist ~12.7 > 10

    def test_box_contains(self):
        r = {"type": "box", "minM": [0, 0, 0], "maxM": [10, 10, 10]}
        assert region_contains(r, [5, 5, 5])
        assert not region_contains(r, [5, 11, 5])

    def test_altitude_band_contains(self):
        r = {"type": "altitudeBand", "minM": 400_000.0, "maxM": 600_000.0}
        assert region_contains(r, [0, 0, 500_000])
        assert not region_contains(r, [0, 0, 700_000])

    def test_unknown_region_type_raises(self):
        with pytest.raises(RoboticsError):
            region_contains({"type": "torus"}, [0, 0, 0])

    def test_sphere_attenuation(self):
        parent = {"type": "sphere", "centerM": [0, 0, 0], "radiusM": 100.0}
        inside = {"type": "sphere", "centerM": [10, 0, 0], "radiusM": 20.0}  # 10+20 <= 100
        outside = {"type": "sphere", "centerM": [90, 0, 0], "radiusM": 20.0}  # 90+20 > 100
        assert region_attenuates(parent, inside)
        assert not region_attenuates(parent, outside)

    def test_box_attenuation(self):
        parent = {"type": "box", "minM": [0, 0, 0], "maxM": [10, 10, 10]}
        child = {"type": "box", "minM": [1, 1, 1], "maxM": [9, 9, 9]}
        wider = {"type": "box", "minM": [-1, 0, 0], "maxM": [10, 10, 10]}
        assert region_attenuates(parent, child)
        assert not region_attenuates(parent, wider)

    def test_type_mismatch_is_not_attenuation(self):
        parent = {"type": "sphere", "centerM": [0, 0, 0], "radiusM": 100.0}
        child = {"type": "box", "minM": [0, 0, 0], "maxM": [1, 1, 1]}
        assert not region_attenuates(parent, child)


class TestGeoscopedGrant:
    def test_verify_and_permit_inside_region(self, verifier):
        signer, kp = verifier
        grant = build_geoscoped_grant(
            signer,
            holder_did="did:web:rover.example",
            grant_id="grant-1",
            region={"type": "sphere", "centerM": [0, 0, 0], "radiusM": 50.0},
        )
        ok, subject = verify_geoscoped_grant(grant, kp.public_key_jwk)
        assert ok
        assert geoscope_permits(subject, [10, 10, 0])  # inside
        assert not geoscope_permits(subject, [40, 40, 0])  # outside

    def test_subgrant_must_attenuate_parent_region(self, verifier):
        signer, kp = verifier
        parent_region = {"type": "sphere", "centerM": [0, 0, 0], "radiusM": 100.0}
        # a valid sub-grant region fully inside the parent
        child = build_geoscoped_grant(
            signer,
            holder_did="did:web:rover",
            grant_id="g2",
            region={"type": "sphere", "centerM": [10, 0, 0], "radiusM": 20.0},
            parent_grant_id="g1",
        )
        ok, _ = verify_geoscoped_grant(child, kp.public_key_jwk, parent_region=parent_region)
        assert ok

        # a sub-grant that pokes outside the parent is rejected
        wide = build_geoscoped_grant(
            signer,
            holder_did="did:web:rover",
            grant_id="g3",
            region={"type": "sphere", "centerM": [90, 0, 0], "radiusM": 30.0},
            parent_grant_id="g1",
        )
        ok, _ = verify_geoscoped_grant(wide, kp.public_key_jwk, parent_region=parent_region)
        assert not ok

    def test_rejects_wrong_key(self, verifier):
        signer, _ = verifier
        grant = build_geoscoped_grant(
            signer,
            holder_did="did:web:rover",
            grant_id="g",
            region={"type": "altitudeBand", "minM": 0.0, "maxM": 100.0},
        )
        other = generate_identity(domain="other.example")
        ok, _ = verify_geoscoped_grant(grant, other.public_key_jwk)
        assert not ok
