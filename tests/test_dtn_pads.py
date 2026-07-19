"""
Tests for the DTN / disconnected-edge PAD implementations (PAD-107, 110-124).
"""

import math

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    # freshness (107, 119)
    build_freshness_token,
    verify_freshness_token,
    decay_weight,
    decay_permits,
    # dtn_revocation (112, 120)
    build_conditional_revocation,
    verify_conditional_revocation,
    conditional_revocation_active,
    build_validity_root,
    build_validity_witness,
    verify_validity_witness,
    # localization (113, 114, 121)
    build_range_observation,
    verify_range_observation,
    count_consistent,
    location_confirmed,
    kinematically_reachable,
    within_beam,
    build_beam_presence,
    verify_beam_presence,
    # quorum_trust (110, 111, 116)
    build_distress_attestation,
    verify_distress_attestation,
    is_quarantined,
    build_trust_state_update,
    verify_trust_state_update,
    accept_trust_state_update,
    build_key_continuity_predelegation,
    build_continuity_approval,
    verify_key_continuity,
    # edge_trust (115, 117, 118)
    build_time_quality_attestation,
    time_quality_permits,
    build_autonomy_schedule,
    verify_autonomy_schedule,
    select_envelope,
    autonomy_permits,
    build_integrity_risk_attestation,
    integrity_authority_level,
    # perception_consensus (122, 123)
    build_perception_claim,
    verify_perception_claim,
    cross_check_perception,
    build_interaction_attestation,
    node_standing,
    # bundle (124)
    bind_credential_to_bundle,
    verify_bundle_trust,
    build_custody_transfer,
    custody_chain_ok,
)
from vouch.robotics import PhysicalAction
from vouch.robotics.identity import RoboticsError


def signer(domain):
    kp = generate_identity(domain=domain)
    return Signer(private_key=kp.private_key_jwk, did=kp.did), kp


# ---- PAD-107 freshness token ---------------------------------------------- #


def test_freshness_token_within_and_over_gap():
    relay, kp = signer("relay.example")
    tok = build_freshness_token(relay, subject_did="did:web:node", epoch=100)
    ok, sub = verify_freshness_token(tok, kp.public_key_jwk, verifier_epoch=100, tier="critical")
    assert ok and sub["epoch"] == 100
    # critical gap budget is 1; epoch 4 behind fails critical, passes routine (budget 100)
    ok_c, _ = verify_freshness_token(tok, kp.public_key_jwk, verifier_epoch=104, tier="critical")
    ok_r, _ = verify_freshness_token(tok, kp.public_key_jwk, verifier_epoch=104, tier="routine")
    assert not ok_c and ok_r


def test_freshness_token_rollback_rejected():
    relay, kp = signer("relay.example")
    tok = build_freshness_token(relay, subject_did="did:web:node", epoch=50)
    ok, _ = verify_freshness_token(tok, kp.public_key_jwk, verifier_epoch=50, seen_epoch=60)
    assert not ok


# ---- PAD-119 graded decay ------------------------------------------------- #


def test_decay_weight_and_permit():
    assert decay_weight(elapsed_epochs=0, half_life_epochs=10) == pytest.approx(1.0)
    assert decay_weight(elapsed_epochs=10, half_life_epochs=10) == pytest.approx(0.5)
    # critical needs 0.9; after one half-life weight 0.5 -> denied; routine (0.1) allowed
    assert not decay_permits(elapsed_epochs=10, half_life_epochs=10, tier="critical")
    assert decay_permits(elapsed_epochs=10, half_life_epochs=10, tier="routine")


# ---- PAD-112 dead-man revocation ------------------------------------------ #


def test_conditional_revocation_fires_without_renewal():
    auth, kp = signer("authority.example")
    cr = build_conditional_revocation(
        auth, target_credential_id="cred-1", subject_did="did:web:node", deadline_epoch=100
    )
    ok, sub = verify_conditional_revocation(cr, kp.public_key_jwk)
    assert ok
    assert not conditional_revocation_active(sub, current_epoch=100)  # deadline not passed
    assert conditional_revocation_active(sub, current_epoch=101)  # passed, no renewal
    assert not conditional_revocation_active(
        sub, current_epoch=101, last_renewal_epoch=100
    )  # renewed at deadline


# ---- PAD-120 carried validity witness ------------------------------------- #


def test_validity_witness_roundtrip_and_negative():
    auth, kp = signer("authority.example")
    valid = ["cred-a", "cred-b", "cred-c", "cred-d"]
    root = build_validity_root(auth, valid_ids=valid, epoch=7)
    w = build_validity_witness(valid_ids=valid, credential_id="cred-c")
    assert verify_validity_witness(
        witness=w, signed_root_credential=root, authority_public_key=kp.public_key_jwk
    )
    # a witness against a different (revoked) set/root must fail
    root2 = build_validity_root(auth, valid_ids=["cred-a", "cred-b"], epoch=8)
    assert not verify_validity_witness(
        witness=w, signed_root_credential=root2, authority_public_key=kp.public_key_jwk
    )


def test_validity_witness_rejects_non_member():
    with pytest.raises(RoboticsError):
        build_validity_witness(valid_ids=["a", "b"], credential_id="z")


# ---- PAD-113 proof-of-location -------------------------------------------- #


def test_location_confirmed_by_threshold():
    obs = [
        {"observerPosition": [0, 0, 0], "measuredRangeM": 100.0},
        {"observerPosition": [200, 0, 0], "measuredRangeM": 100.0},
        {"observerPosition": [0, 200, 0], "measuredRangeM": 100.0},
    ]
    # target at (100,0,0): dist to obs = 100, 100, ~141. Two consistent within tol 2.
    assert count_consistent(obs, [100, 0, 0], tolerance_m=2.0) == 2
    assert location_confirmed(obs, [100, 0, 0], tolerance_m=2.0, threshold=2)
    assert not location_confirmed(obs, [100, 0, 0], tolerance_m=2.0, threshold=3)


def test_range_observation_signs_and_verifies():
    obs, kp = signer("observer.example")
    o = build_range_observation(
        obs,
        target_did="did:web:t",
        observer_position=[1, 2, 3],
        measured_range_m=10.0,
        nonce="n",
        epoch=1,
    )
    ok, sub = verify_range_observation(o, kp.public_key_jwk)
    assert ok and sub["measuredRangeM"] == 10.0


# ---- PAD-114 kinematic plausibility --------------------------------------- #


def test_kinematic_reachable_surface_and_orbital():
    # surface: 5 m/s over 10 s reaches 50 m
    assert kinematically_reachable(
        prior_position=[0, 0, 0],
        claimed_position=[40, 0, 0],
        elapsed_seconds=10,
        envelope={"maxSpeedMps": 5},
    )
    assert not kinematically_reachable(
        prior_position=[0, 0, 0],
        claimed_position=[80, 0, 0],
        elapsed_seconds=10,
        envelope={"maxSpeedMps": 5},
    )
    # orbital: |v0|=100 + dv 10 over 1 s => reach 110
    assert kinematically_reachable(
        prior_position=[0, 0, 0],
        claimed_position=[105, 0, 0],
        elapsed_seconds=1,
        envelope={"maxDeltaVMps": 10},
        prior_velocity=[100, 0, 0],
    )
    assert not kinematically_reachable(
        prior_position=[0, 0, 0],
        claimed_position=[200, 0, 0],
        elapsed_seconds=1,
        envelope={"maxDeltaVMps": 10},
        prior_velocity=[100, 0, 0],
    )


# ---- PAD-121 optical beam presence ---------------------------------------- #


def test_within_beam_and_attestation():
    assert within_beam([1, 0, 0], [1, 0.01, 0], beamwidth_rad=math.radians(10))
    assert not within_beam([1, 0, 0], [0, 1, 0], beamwidth_rad=math.radians(10))
    s, kp = signer("term.example")
    att = build_beam_presence(
        s, peer_did="did:web:peer", nonce="n", pointing=[1, 0, 0], beamwidth_rad=math.radians(10)
    )
    ok, _ = verify_beam_presence(
        att, kp.public_key_jwk, peer_direction=[1, 0.02, 0], expected_nonce="n"
    )
    bad, _ = verify_beam_presence(att, kp.public_key_jwk, peer_direction=[0, 1, 0])
    assert ok and not bad


# ---- PAD-110 swarm quarantine --------------------------------------------- #


def test_quarantine_needs_threshold_distinct_members():
    members = {f"did:web:m{i}" for i in range(4)}
    subs = [
        {"id": "did:web:bad", "observer": "did:web:m0", "epoch": 5},
        {"id": "did:web:bad", "observer": "did:web:m1", "epoch": 5},
        {"id": "did:web:bad", "observer": "did:web:m1", "epoch": 6},  # duplicate signer
        {"id": "did:web:bad", "observer": "did:web:outsider", "epoch": 5},  # not a member
    ]
    assert not is_quarantined(subs, target_did="did:web:bad", threshold=3, member_dids=members)
    subs.append({"id": "did:web:bad", "observer": "did:web:m2", "epoch": 5})
    assert is_quarantined(subs, target_did="did:web:bad", threshold=3, member_dids=members)


def test_distress_signs_and_verifies():
    m, kp = signer("m.example")
    d = build_distress_attestation(
        m, target_did="did:web:bad", reason="out_of_envelope", evidence_ref="frame:abc", epoch=5
    )
    ok, sub = verify_distress_attestation(d, kp.public_key_jwk)
    assert ok and sub["reason"] == "out_of_envelope"


# ---- PAD-111 quorum-of-orbits --------------------------------------------- #


def test_accept_update_needs_distinct_domains_and_no_rollback():
    change = {"op": "revoke", "did": "did:web:x"}
    subs = [
        {"scope": "revocations", "change": change, "epoch": 10, "failureDomain": "orbit-A"},
        {
            "scope": "revocations",
            "change": change,
            "epoch": 10,
            "failureDomain": "orbit-A",
        },  # same domain
    ]
    assert not accept_trust_state_update(subs, current_epoch=9, threshold=2)
    subs.append({"scope": "revocations", "change": change, "epoch": 10, "failureDomain": "orbit-B"})
    assert accept_trust_state_update(subs, current_epoch=9, threshold=2)
    # rollback: epoch below current is rejected
    assert not accept_trust_state_update(subs, current_epoch=11, threshold=2)


# ---- PAD-116 key continuity ----------------------------------------------- #


def test_key_continuity_threshold_approvals():
    auth, akp = signer("authority.example")
    members = [f"did:web:m{i}" for i in range(3)]
    pre = build_key_continuity_predelegation(
        auth, mission_credential_id="mission-1", member_dids=members, threshold=2
    )
    from vouch.robotics._verify import verify_typed_credential

    pre_subject = verify_typed_credential(pre, akp.public_key_jwk, "KeyContinuityPredelegation")
    assert pre_subject is not None
    # two authorized members approve the reissuance
    approvals = [
        {"id": "reissue-1", "member": members[i], "supersedes": "mission-1", "epoch": 20}
        for i in range(2)
    ]
    assert verify_key_continuity(
        predelegation_subject=pre_subject,
        reissuance_id="reissue-1",
        supersedes="mission-1",
        approval_subjects=approvals,
    )
    assert not verify_key_continuity(
        predelegation_subject=pre_subject,
        reissuance_id="reissue-1",
        supersedes="mission-1",
        approval_subjects=approvals[:1],
    )


# ---- PAD-115 time quality ------------------------------------------------- #


def test_time_quality_gate():
    s, kp = signer("node.example")
    good = build_time_quality_attestation(
        s, source_class="gnss", since_discipline_s=5, uncertainty_s=0.5
    )
    from vouch.robotics import verify_time_quality_attestation

    ok, sub = verify_time_quality_attestation(good, kp.public_key_jwk)
    assert ok
    assert time_quality_permits(sub, tier="critical")  # 0.5 <= 1.0
    poor = build_time_quality_attestation(
        s, source_class="rc-oscillator", since_discipline_s=1e6, uncertainty_s=120.0
    )
    _, psub = verify_time_quality_attestation(poor, kp.public_key_jwk)
    assert not time_quality_permits(psub, tier="critical")  # 120 > 1
    assert time_quality_permits(psub, tier="routine")  # 120 <= 3600


# ---- PAD-117 autonomy envelope -------------------------------------------- #


def test_autonomy_envelope_narrows_with_staleness():
    auth, kp = signer("authority.example")
    steps = [
        {
            "maxStalenessEpochs": 10,
            "physicalScope": {"maxSpeedMps": 2.0, "allowedZones": ["a", "b"]},
        },
        {"maxStalenessEpochs": 100, "physicalScope": {"maxSpeedMps": 0.5, "allowedZones": ["a"]}},
    ]
    sched = build_autonomy_schedule(auth, subject_did="did:web:node", steps=steps)
    ok, sub = verify_autonomy_schedule(sched, kp.public_key_jwk)
    assert ok
    assert select_envelope(sub, 5)["maxSpeedMps"] == 2.0
    assert select_envelope(sub, 50)["maxSpeedMps"] == 0.5
    assert autonomy_permits(sub, 5, PhysicalAction(speed_mps=1.5, zone="b"))
    assert not autonomy_permits(sub, 50, PhysicalAction(speed_mps=1.5, zone="b"))  # narrowed


def test_autonomy_schedule_rejects_widening():
    auth, _ = signer("authority.example")
    bad = [
        {"maxStalenessEpochs": 10, "physicalScope": {"maxSpeedMps": 0.5}},
        {"maxStalenessEpochs": 100, "physicalScope": {"maxSpeedMps": 2.0}},  # widens
    ]
    with pytest.raises(RoboticsError):
        build_autonomy_schedule(auth, subject_did="did:web:node", steps=bad)


# ---- PAD-118 integrity risk ----------------------------------------------- #


def test_integrity_authority_level():
    assert integrity_authority_level(0.1) == "full"
    assert integrity_authority_level(0.4) == "narrowed"
    assert integrity_authority_level(0.8) == "suspect"


# ---- PAD-122 byzantine sensor agreement ----------------------------------- #


def test_cross_check_flags_outlier():
    subs = [
        {"id": "did:web:a", "value": 10.0},
        {"id": "did:web:b", "value": 10.2},
        {"id": "did:web:c", "value": 9.9},
        {"id": "did:web:liar", "value": 50.0},
    ]
    res = cross_check_perception(subs, tolerance=1.0, threshold=2)
    assert "did:web:liar" in res["flagged"]
    assert set(res["corroborated"]) == {"did:web:a", "did:web:b", "did:web:c"}


# ---- PAD-123 mutual-attestation mesh -------------------------------------- #


def test_node_standing_recent_and_distinct():
    subs = [
        {"id": "did:web:n", "attestor": "did:web:p1", "outcome": "ok", "epoch": 100},
        {"id": "did:web:n", "attestor": "did:web:p2", "outcome": "ok", "epoch": 90},
        {
            "id": "did:web:n",
            "attestor": "did:web:p1",
            "outcome": "ok",
            "epoch": 80,
        },  # older dup for p1
    ]
    st = node_standing(subs, node_did="did:web:n", current_epoch=100, half_life_epochs=10)
    # p1 freshest at 100 -> weight 1.0; p2 at 90 -> weight 0.5; total 1.5
    assert st == pytest.approx(1.5)


# ---- PAD-124 bundle custody ----------------------------------------------- #


def test_bundle_trust_and_custody_chain():
    orig, okp = signer("origin.example")
    bc = bind_credential_to_bundle(
        orig, bundle_id="b-1", payload_hash="sha256:abc", intent={"action": "deliver"}
    )
    ok, _ = verify_bundle_trust(bc, okp.public_key_jwk, payload_hash="sha256:abc")
    assert ok
    bad, _ = verify_bundle_trust(bc, okp.public_key_jwk, payload_hash="sha256:TAMPERED")
    assert not bad
    origin_did = orig.get_did()
    transfers = [
        {"id": "b-1", "custodian": "did:web:relay1", "previousCustodian": origin_did, "epoch": 1},
        {
            "id": "b-1",
            "custodian": "did:web:relay2",
            "previousCustodian": "did:web:relay1",
            "epoch": 2,
        },
    ]
    assert custody_chain_ok(transfers, bundle_id="b-1", originator=origin_did)
    broken = [
        transfers[0],
        {
            "id": "b-1",
            "custodian": "did:web:relay2",
            "previousCustodian": "did:web:GHOST",
            "epoch": 2,
        },
    ]
    assert not custody_chain_ok(broken, bundle_id="b-1", originator=origin_did)
