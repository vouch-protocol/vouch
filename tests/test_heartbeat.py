"""
Unit tests for Heartbeat Protocol orchestration (Specification §11).
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from vouch.heartbeat import (
    HEARTBEAT_PROTOCOL_VERSION,
    HEARTBEAT_REQUEST_TYPE,
    HeartbeatError,
    HeartbeatRequest,
    HeartbeatScheduler,
    HeartbeatSession,
    HeartbeatValidator,
)


AGENT_DID = "did:web:agent.example.com"
VALIDATOR_DID = "did:web:validator.example.com"


class TestHeartbeatRequestSerialization:
    def test_to_dict_shape_matches_spec(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        session.collector.record_api_call("/x", tokens=10)
        session.record_action(b"action_1")
        req = session.build_request()
        d = req.to_dict()
        assert d["version"] == HEARTBEAT_PROTOCOL_VERSION
        assert d["type"] == HEARTBEAT_REQUEST_TYPE
        assert d["subject_did"] == AGENT_DID
        assert "session_id" in d
        assert d["interval_index"] == 0
        assert "issued_at" in d
        assert d["actionMerkleRoot"].startswith("u")
        assert d["canaryCommitment"].startswith("u")
        assert "canaryReveal" not in d  # First interval has no reveal.
        assert d["behavioralDigest"]["apiCalls"] == 1
        assert d["behavioralDigest"]["tokensConsumed"] == 10

    def test_round_trip_through_dict(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        session.record_action(b"a")
        original = session.build_request()
        encoded = original.to_dict()
        decoded = HeartbeatRequest.from_dict(encoded)
        assert decoded.subject_did == original.subject_did
        assert decoded.interval_index == original.interval_index
        assert decoded.action_merkle_root == original.action_merkle_root
        assert decoded.canary_commitment == original.canary_commitment

    def test_from_dict_rejects_wrong_version(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        d = session.build_request().to_dict()
        d["version"] = "0.9"
        with pytest.raises(HeartbeatError):
            HeartbeatRequest.from_dict(d)

    def test_from_dict_rejects_wrong_type(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        d = session.build_request().to_dict()
        d["type"] = "not_a_heartbeat"
        with pytest.raises(HeartbeatError):
            HeartbeatRequest.from_dict(d)

    def test_from_dict_rejects_missing_field(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        d = session.build_request().to_dict()
        del d["actionMerkleRoot"]
        with pytest.raises(HeartbeatError):
            HeartbeatRequest.from_dict(d)


class TestHeartbeatSession:
    def test_interval_index_increments(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        assert session.build_request().interval_index == 0
        assert session.build_request().interval_index == 1
        assert session.build_request().interval_index == 2

    def test_second_request_includes_canary_reveal(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        first = session.build_request()
        second = session.build_request()
        assert first.canary_reveal is None
        assert second.canary_reveal is not None

    def test_actions_aggregate_into_merkle_root(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        # Empty interval has a deterministic root (hash of empty leaf).
        empty_req = session.build_request()

        session2 = HeartbeatSession(subject_did=AGENT_DID)
        session2.record_action(b"act_1")
        session2.record_action(b"act_2")
        nonempty_req = session2.build_request()

        assert empty_req.action_merkle_root != nonempty_req.action_merkle_root

    def test_action_must_be_bytes(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        with pytest.raises(HeartbeatError):
            session.record_action("not bytes")  # type: ignore[arg-type]

    def test_collector_resets_between_intervals(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        session.collector.record_api_call("/x", tokens=5)
        first = session.build_request()
        assert first.behavioral_digest["apiCalls"] == 1
        second = session.build_request()
        # Counters back to zero on the next interval.
        assert second.behavioral_digest["apiCalls"] == 0
        assert second.behavioral_digest["tokensConsumed"] == 0


class TestHeartbeatValidator:
    def test_first_heartbeat_validates_and_issues_voucher(self):
        validator = HeartbeatValidator(validator_did=VALIDATOR_DID)
        session = HeartbeatSession(subject_did=AGENT_DID)
        req = session.build_request().to_dict()

        result = validator.validate(req)
        assert result.ok is True
        assert result.reasons == []
        assert result.session_voucher is not None
        assert result.session_voucher["issuer"] == [VALIDATOR_DID]
        assert "SessionVoucher" in result.session_voucher["type"]
        assert result.session_voucher["credentialSubject"]["id"] == AGENT_DID

    def test_chain_of_heartbeats_validates(self):
        validator = HeartbeatValidator(validator_did=VALIDATOR_DID)
        session = HeartbeatSession(subject_did=AGENT_DID)
        for _ in range(5):
            req = session.build_request().to_dict()
            result = validator.validate(req)
            assert result.ok is True

    def test_skipped_canary_reveal_breaks_chain(self):
        validator = HeartbeatValidator(validator_did=VALIDATOR_DID)
        session = HeartbeatSession(subject_did=AGENT_DID)
        validator.validate(session.build_request().to_dict())

        # Build a second request and strip the reveal: simulating either
        # a malicious agent or a chain restart attempt.
        req2 = session.build_request().to_dict()
        del req2["canaryReveal"]
        result = validator.validate(req2)
        assert result.ok is False
        assert any("canary_chain_broken" in r for r in result.reasons)

    def test_forged_reveal_rejected(self):
        validator = HeartbeatValidator(validator_did=VALIDATOR_DID)
        session = HeartbeatSession(subject_did=AGENT_DID)
        validator.validate(session.build_request().to_dict())

        req2 = session.build_request().to_dict()
        # Replace canaryReveal with a wrong-but-well-formatted multibase value.
        req2["canaryReveal"] = "u" + "A" * 43
        result = validator.validate(req2)
        assert result.ok is False
        assert any("canary_chain_broken" in r for r in result.reasons)

    def test_stale_interval_index_rejected(self):
        validator = HeartbeatValidator(validator_did=VALIDATOR_DID)
        session = HeartbeatSession(subject_did=AGENT_DID)
        first = session.build_request().to_dict()
        second = session.build_request().to_dict()
        validator.validate(first)
        validator.validate(second)
        # Replay the first request -> interval_index already seen.
        result = validator.validate(first)
        assert result.ok is False
        assert any("stale_interval_index" in r for r in result.reasons)

    def test_malformed_request_rejected(self):
        validator = HeartbeatValidator(validator_did=VALIDATOR_DID)
        result = validator.validate({"type": "garbage"})
        assert result.ok is False
        assert any("schema_invalid" in r for r in result.reasons)

    def test_voucher_carries_configured_trust_parameters(self):
        validator = HeartbeatValidator(
            validator_did=VALIDATOR_DID,
            initial_trust=0.9,
            decay_lambda=0.002,
            voucher_valid_seconds=300,
            scope=["read", "write"],
        )
        session = HeartbeatSession(subject_did=AGENT_DID)
        req = session.build_request().to_dict()
        result = validator.validate(req)
        assert result.ok is True
        cs = result.session_voucher["credentialSubject"]
        assert cs["initialTrust"] == 0.9
        assert cs["decayLambda"] == 0.002
        assert cs["scope"] == ["read", "write"]

    def test_session_isolation(self):
        """Two sessions for the same agent must not cross-contaminate canary state."""
        validator = HeartbeatValidator(validator_did=VALIDATOR_DID)
        s1 = HeartbeatSession(subject_did=AGENT_DID)
        s2 = HeartbeatSession(subject_did=AGENT_DID)
        assert s1.session_id != s2.session_id
        assert validator.validate(s1.build_request().to_dict()).ok
        assert validator.validate(s2.build_request().to_dict()).ok
        # Both sessions can progress independently.
        assert validator.validate(s1.build_request().to_dict()).ok
        assert validator.validate(s2.build_request().to_dict()).ok


class TestHeartbeatScheduler:
    @pytest.mark.asyncio
    async def test_scheduler_fires_callback_repeatedly(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        received = []

        async def submit(req):
            received.append(req)

        scheduler = HeartbeatScheduler(
            session=session,
            interval_seconds=0.05,
            submit_callback=submit,
        )
        scheduler.start()
        await asyncio.sleep(0.2)
        await scheduler.stop()
        # Expect at least 2 fires within ~200ms with 50ms interval.
        assert len(received) >= 2

    @pytest.mark.asyncio
    async def test_scheduler_handles_callback_exceptions(self):
        session = HeartbeatSession(subject_did=AGENT_DID)
        failures = []

        async def boom(req):
            raise RuntimeError("nope")

        async def on_failure(exc):
            failures.append(exc)

        scheduler = HeartbeatScheduler(
            session=session,
            interval_seconds=0.05,
            submit_callback=boom,
            on_failure=on_failure,
        )
        scheduler.start()
        await asyncio.sleep(0.15)
        await scheduler.stop()
        assert len(failures) >= 1
        assert isinstance(failures[0], RuntimeError)

    @pytest.mark.asyncio
    async def test_scheduler_rejects_zero_interval(self):
        session = HeartbeatSession(subject_did=AGENT_DID)

        async def submit(req):
            pass

        scheduler = HeartbeatScheduler(
            session=session,
            interval_seconds=0,
            submit_callback=submit,
        )
        with pytest.raises(HeartbeatError):
            scheduler.start()


class TestEndToEndFlow:
    def test_agent_validator_flow_over_multiple_intervals(self):
        validator = HeartbeatValidator(
            validator_did=VALIDATOR_DID,
            initial_trust=1.0,
            decay_lambda=0.01,
            voucher_valid_seconds=60,
        )
        session = HeartbeatSession(subject_did=AGENT_DID)

        vouchers = []
        for i in range(10):
            session.record_action(f"action_{i}".encode())
            session.collector.record_api_call(f"/op/{i}", tokens=5)
            req = session.build_request().to_dict()
            result = validator.validate(req)
            assert result.ok, f"interval {i} failed: {result.reasons}"
            vouchers.append(result.session_voucher)

        # Every voucher should have the agent as subject and validator as issuer.
        for v in vouchers:
            assert v["credentialSubject"]["id"] == AGENT_DID
            assert v["issuer"] == [VALIDATOR_DID]


class TestPluggableStore:
    """
    Verifies that HeartbeatValidator supports custom storage backends via
    HeartbeatStoreInterface. Default MemoryHeartbeatStore preserves the
    pre-refactor behavior; production backends (Redis, Postgres, Kafka,
    S3) plug in here without touching validator code.
    """

    def test_default_uses_memory_store(self):
        from vouch.heartbeat import MemoryHeartbeatStore

        v = HeartbeatValidator(validator_did=VALIDATOR_DID)
        assert isinstance(v.store, MemoryHeartbeatStore)

    def test_validator_survives_restart_when_state_is_persisted(self):
        """
        Simulate validator restart by creating a second validator that
        shares the same store. The second validator MUST continue the
        canary chain from where the first one left off.
        """
        from vouch.heartbeat import MemoryHeartbeatStore

        shared_store = MemoryHeartbeatStore()

        v1 = HeartbeatValidator(validator_did=VALIDATOR_DID, store=shared_store)
        session = HeartbeatSession(subject_did=AGENT_DID)

        first = session.build_request().to_dict()
        assert v1.validate(first).ok

        # "Restart" the validator with the same backing store.
        v2 = HeartbeatValidator(validator_did=VALIDATOR_DID, store=shared_store)
        second = session.build_request().to_dict()
        result = v2.validate(second)
        assert result.ok, f"v2 rejected after restart: {result.reasons}"
        # v2 also rejects stale replays of intervals v1 already saw.
        assert v2.validate(first).ok is False

    def test_custom_store_can_be_a_dict_wrapper(self):
        """
        Any backend implementing HeartbeatStoreInterface works. This
        test wraps a plain dict, demonstrating that the contract is
        the small JSON-serializable state-dict shape.
        """
        from vouch.heartbeat import HeartbeatStoreInterface

        class DictStore(HeartbeatStoreInterface):
            def __init__(self):
                self.d = {}

            def get(self, key):
                return self.d.get(key)

            def put(self, key, state):
                self.d[key] = dict(state)

            def delete(self, key):
                self.d.pop(key, None)

            def known_sessions(self):
                return list(self.d.keys())

        store = DictStore()
        v = HeartbeatValidator(validator_did=VALIDATOR_DID, store=store)
        session = HeartbeatSession(subject_did=AGENT_DID)

        for _ in range(3):
            assert v.validate(session.build_request().to_dict()).ok

        # State persisted to the custom store.
        assert len(store.d) == 1
        state = next(iter(store.d.values()))
        assert state["last_interval"] == 2
        assert state["expecting_reveal"] is True
        assert state["last_commitment"] is not None

    def test_reset_session_removes_state_from_store(self):
        v = HeartbeatValidator(validator_did=VALIDATOR_DID)
        session = HeartbeatSession(subject_did=AGENT_DID)
        v.validate(session.build_request().to_dict())
        assert len(v.known_sessions()) == 1
        v.reset_session(AGENT_DID, session.session_id)
        assert v.known_sessions() == []

    def test_state_dict_is_json_serializable(self):
        """The state-dict contract must be JSON-serializable so production
        backends (Redis SET, Postgres jsonb column, S3 object) can store it."""
        import json
        from vouch.heartbeat import MemoryHeartbeatStore

        store = MemoryHeartbeatStore()
        v = HeartbeatValidator(validator_did=VALIDATOR_DID, store=store)
        session = HeartbeatSession(subject_did=AGENT_DID)
        v.validate(session.build_request().to_dict())

        key = next(iter(store.known_sessions()))
        state = store.get(key)
        # MUST round-trip through JSON.
        round_tripped = json.loads(json.dumps(state))
        assert round_tripped == state
