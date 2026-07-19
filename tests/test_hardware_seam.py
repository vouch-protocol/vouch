"""
Tests for the hardware-facing seam (vouch.robotics.hardware): sensor Protocols,
simulated implementations, and capture/verify-live adapters.
"""

import math

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    ClockSource,
    NavigationSource,
    RangeSensor,
    SimulatedClock,
    SimulatedEpochSource,
    SimulatedIntegrityMonitor,
    SimulatedNavigation,
    SimulatedPointing,
    SimulatedRangeSensor,
    capture_beam_presence,
    capture_integrity_risk,
    capture_presence_attestation,
    capture_range_observation,
    capture_time_quality,
    check_kinematics_live,
    issue_freshness_token,
    time_quality_permits,
    verify_beam_presence,
    verify_freshness_token,
    verify_integrity_risk_attestation,
    verify_presence_live,
    verify_range_observation,
    verify_time_quality_attestation,
    integrity_authority_level,
)


def signer(domain):
    kp = generate_identity(domain=domain)
    return Signer(private_key=kp.private_key_jwk, did=kp.did), kp


# ---- Protocols are satisfied by simulated impls and by duck-typed drivers -- #


def test_simulated_impls_satisfy_protocols():
    assert isinstance(SimulatedNavigation([0, 0, 0], [0, 0, 0]), NavigationSource)
    assert isinstance(SimulatedRangeSensor({"x": 1.0}), RangeSensor)
    assert isinstance(SimulatedClock("gnss", 1.0, 0.1), ClockSource)


def test_custom_driver_duck_types():
    class MyRadio:
        def measure_range_m(self, target):
            return 42.0

    assert isinstance(MyRadio(), RangeSensor)  # runtime_checkable Protocol


# ---- PAD-108 presence via the seam ---------------------------------------- #


def test_capture_and_verify_presence_live():
    node, nkp = signer("node.example")
    peer_did = "did:web:peer"
    # The node (at origin) ranges its peer; sensor reports 100.4 m; peer claims (100,0,0).
    rs = SimulatedRangeSensor({peer_did: 100.4})
    att = capture_presence_attestation(
        node,
        peer_did=peer_did,
        nonce="n1",
        claimed_position=[100, 0, 0],
        range_sensor=rs,
        tolerance_m=1.0,
    )
    verifier_nav = SimulatedNavigation([0, 0, 0], [0, 0, 0])
    ok, sub = verify_presence_live(att, nkp.public_key_jwk, nav=verifier_nav, expected_nonce="n1")
    assert ok and sub["id"] == peer_did


def test_presence_live_rejects_impossible_range():
    node, nkp = signer("node.example")
    peer_did = "did:web:peer"
    rs = SimulatedRangeSensor({peer_did: 500.0})  # measured far from claimed 100 m
    att = capture_presence_attestation(
        node,
        peer_did=peer_did,
        nonce="n",
        claimed_position=[100, 0, 0],
        range_sensor=rs,
        tolerance_m=1.0,
    )
    ok, _ = verify_presence_live(
        att, nkp.public_key_jwk, nav=SimulatedNavigation([0, 0, 0], [0, 0, 0])
    )
    assert not ok


# ---- PAD-113 range observation via the seam ------------------------------- #


def test_capture_range_observation():
    obs, okp = signer("observer.example")
    nav = SimulatedNavigation([10, 0, 0], [0, 0, 0])
    rs = SimulatedRangeSensor({"did:web:t": 90.0})
    epoch = SimulatedEpochSource(5)
    o = capture_range_observation(
        obs, target_did="did:web:t", nav=nav, range_sensor=rs, nonce="n", epoch_source=epoch
    )
    ok, sub = verify_range_observation(o, okp.public_key_jwk)
    assert (
        ok
        and sub["observerPosition"] == [10, 0, 0]
        and sub["measuredRangeM"] == 90.0
        and sub["epoch"] == 5
    )


# ---- PAD-121 beam presence via the seam ----------------------------------- #


def test_capture_beam_presence():
    term, tkp = signer("term.example")
    pointing = SimulatedPointing([1, 0, 0], math.radians(10))
    att = capture_beam_presence(term, peer_did="did:web:peer", nonce="n", pointing_source=pointing)
    ok, _ = verify_beam_presence(
        att, tkp.public_key_jwk, peer_direction=[1, 0.02, 0], expected_nonce="n"
    )
    bad, _ = verify_beam_presence(att, tkp.public_key_jwk, peer_direction=[0, 1, 0])
    assert ok and not bad


# ---- PAD-115 time quality via the seam ------------------------------------ #


def test_capture_time_quality_gate():
    node, nkp = signer("node.example")
    good = capture_time_quality(node, clock=SimulatedClock("gnss", 5.0, 0.5))
    ok, sub = verify_time_quality_attestation(good, nkp.public_key_jwk)
    assert ok and time_quality_permits(sub, tier="critical")
    poor = capture_time_quality(node, clock=SimulatedClock("rc-oscillator", 1e6, 120.0))
    _, psub = verify_time_quality_attestation(poor, nkp.public_key_jwk)
    assert not time_quality_permits(psub, tier="critical")


# ---- PAD-118 integrity via the seam --------------------------------------- #


def test_capture_integrity_risk():
    node, nkp = signer("node.example")
    mon = SimulatedIntegrityMonitor(0.8, {"doseRad": 1200, "seu": 4})
    att = capture_integrity_risk(node, monitor=mon)
    ok, sub = verify_integrity_risk_attestation(att, nkp.public_key_jwk)
    assert ok and sub["cumulativeRisk"] == 0.8 and sub["metrics"]["seu"] == 4
    assert integrity_authority_level(sub["cumulativeRisk"]) == "suspect"


# ---- PAD-107 freshness token via the seam --------------------------------- #


def test_issue_freshness_token_and_advance():
    relay, rkp = signer("relay.example")
    epoch = SimulatedEpochSource(10)
    tok = issue_freshness_token(relay, subject_did="did:web:node", epoch_source=epoch)
    ok, sub = verify_freshness_token(tok, rkp.public_key_jwk, verifier_epoch=10, tier="critical")
    assert ok and sub["epoch"] == 10
    epoch.advance(5)
    assert epoch.current_epoch() == 15


# ---- PAD-114 kinematics via the seam -------------------------------------- #


def test_check_kinematics_live():
    nav = SimulatedNavigation([40, 0, 0], [0, 0, 0])
    assert check_kinematics_live(
        prior_position=[0, 0, 0], nav=nav, elapsed_seconds=10, envelope={"maxSpeedMps": 5}
    )
    nav_far = SimulatedNavigation([80, 0, 0], [0, 0, 0])
    assert not check_kinematics_live(
        prior_position=[0, 0, 0], nav=nav_far, elapsed_seconds=10, envelope={"maxSpeedMps": 5}
    )
