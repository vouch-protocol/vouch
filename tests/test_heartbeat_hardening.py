"""Heartbeat renewal: signed beats, a time window, missed-beat lapse, and a
validator-checked action Merkle root. Every test runs on a fake clock."""

from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from vouch import Signer, generate_identity, multikey
from vouch.heartbeat import HeartbeatSession, HeartbeatValidator
from vouch.merkle import (
    MerkleTree,
    compute_action_merkle_root,
    hash_leaf,
    root_from_leaf_hashes,
    verify_inclusion,
)

T0 = datetime(2026, 11, 10, 17, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Merkle: no duplicate-last-leaf ambiguity
# ---------------------------------------------------------------------------


def test_duplicated_last_leaf_changes_the_root():
    assert compute_action_merkle_root([b"a", b"b", b"c"]) != compute_action_merkle_root(
        [b"a", b"b", b"c", b"c"]
    )


@pytest.mark.parametrize("n", range(1, 10))
def test_inclusion_proofs_verify_for_every_leaf(n):
    leaves = [f"action-{i}".encode() for i in range(n)]
    tree = MerkleTree(leaves=leaves)
    for i, leaf in enumerate(leaves):
        assert verify_inclusion(leaf=leaf, proof=tree.proof(i), root=tree.root())
    assert not verify_inclusion(leaf=b"other", proof=tree.proof(0), root=tree.root())


@pytest.mark.parametrize("n", range(1, 10))
def test_root_from_leaf_hashes_matches_tree(n):
    leaves = [f"action-{i}".encode() for i in range(n)]
    assert root_from_leaf_hashes([hash_leaf(x) for x in leaves]) == MerkleTree(leaves=leaves).root()


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def _did_key_signer():
    kp = generate_identity()
    raw = base64.urlsafe_b64decode(json.loads(kp.public_key_jwk)["x"] + "==")
    return Signer(
        private_key=kp.private_key_jwk, did="did:key:" + multikey.encode_ed25519_public(raw)
    )


@pytest.fixture
def setup():
    agent = _did_key_signer()
    clock = Clock(T0)
    session = HeartbeatSession(subject_did=agent.did, signer=agent)
    validator = HeartbeatValidator(
        validator_did="did:web:validator.example.com",
        clock=clock,
        interval_seconds=60,
        max_missed_intervals=2,
    )
    return agent, clock, session, validator


def _beat(session, clock, actions=()):
    for a in actions:
        session.record_action(a)
    return session.build_request(now=clock()).to_dict()


def test_signed_beats_on_time_are_accepted(setup):
    _, clock, session, validator = setup
    r0 = validator.validate(_beat(session, clock, [b"read:cal"]))
    assert r0.ok, r0.reasons
    clock.t += timedelta(seconds=60)
    r1 = validator.validate(_beat(session, clock, [b"read:cal", b"read:cal2"]))
    assert r1.ok, r1.reasons
    assert r1.session_voucher["validFrom"] == "2026-11-10T17:01:00Z"


def test_unsigned_beat_is_rejected(setup):
    agent, clock, _, validator = setup
    unsigned = HeartbeatSession(subject_did=agent.did)
    r = validator.validate(unsigned.build_request(now=clock()).to_dict())
    assert not r.ok
    assert "signature_missing" in r.reasons


def test_tampered_beat_is_rejected(setup):
    _, clock, session, validator = setup
    beat = _beat(session, clock, [b"read:cal"])
    beat["behavioralDigest"]["apiCalls"] = 99  # edited after signing
    r = validator.validate(beat)
    assert not r.ok
    assert "signature_invalid" in r.reasons


def test_beat_signed_by_another_key_is_rejected(setup):
    agent, clock, _, validator = setup
    mallory = _did_key_signer()
    forged = HeartbeatSession(subject_did=agent.did, signer=mallory, allow_foreign_signer=True)
    r = validator.validate(forged.build_request(now=clock()).to_dict())
    assert not r.ok
    assert "signature_invalid" in r.reasons


def test_late_beat_is_rejected(setup):
    _, clock, session, validator = setup
    stale = session.build_request(now=clock() - timedelta(hours=6)).to_dict()
    r = validator.validate(stale)
    assert not r.ok
    assert "issued_at_too_old" in r.reasons


def test_future_beat_is_rejected(setup):
    _, clock, session, validator = setup
    ahead = session.build_request(now=clock() + timedelta(minutes=10)).to_dict()
    r = validator.validate(ahead)
    assert not r.ok
    assert "issued_at_in_future" in r.reasons


def test_missed_beats_beyond_the_limit_lapse_the_session(setup):
    agent, clock, session, validator = setup
    assert validator.validate(_beat(session, clock)).ok
    clock.t += timedelta(seconds=60 * 4)  # three intervals missed, limit is 2
    r = validator.validate(_beat(session, clock))
    assert not r.ok
    assert any(x.startswith("missed_heartbeats") for x in r.reasons)
    assert r.session_voucher is None
    # Even a timely beat now is refused until the session is reset.
    clock.t += timedelta(seconds=60)
    r2 = validator.validate(_beat(session, clock))
    assert not r2.ok
    assert "session_lapsed" in r2.reasons
    validator.reset_session(agent.did, session.session_id)
    fresh = HeartbeatSession(subject_did=agent.did, signer=agent)
    assert validator.validate(fresh.build_request(now=clock()).to_dict()).ok


def test_missed_beats_within_the_limit_are_tolerated(setup):
    _, clock, session, validator = setup
    assert validator.validate(_beat(session, clock)).ok
    clock.t += timedelta(seconds=60 * 3)  # two intervals missed, limit is 2
    assert validator.validate(_beat(session, clock)).ok


def test_skipped_interval_indexes_beyond_the_limit_lapse(setup):
    _, clock, session, validator = setup
    assert validator.validate(_beat(session, clock)).ok
    session._interval_index += 5  # the agent claims five beats happened elsewhere
    clock.t += timedelta(seconds=60)
    r = validator.validate(_beat(session, clock))
    assert not r.ok
    assert any(x.startswith("missed_heartbeats") for x in r.reasons)


def test_wrong_action_merkle_root_is_rejected(setup):
    agent, clock, session, validator = setup
    session.record_action(b"read:cal")
    req = session.build_request(now=clock())
    req.action_merkle_root = compute_action_merkle_root([b"something else"])
    r = validator.validate(req.to_dict(resign=agent))
    assert not r.ok
    assert "action_merkle_root_mismatch" in r.reasons


def test_missing_action_leaf_hashes_is_rejected(setup):
    agent, clock, session, validator = setup
    req = session.build_request(now=clock())
    req.action_leaf_hashes = None
    r = validator.validate(req.to_dict(resign=agent))
    assert not r.ok
    assert "action_leaf_hashes_missing" in r.reasons


def test_replay_and_out_of_order_are_still_rejected(setup):
    _, clock, session, validator = setup
    first = _beat(session, clock)
    assert validator.validate(first).ok
    clock.t += timedelta(seconds=30)
    replay = copy.deepcopy(first)
    r = validator.validate(replay)
    assert not r.ok
    assert any(x.startswith("stale_interval_index") for x in r.reasons)
