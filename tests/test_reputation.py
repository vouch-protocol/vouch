"""
Unit tests for the reputation engine.
"""

import pytest
import time

from vouch.reputation import (
    ReputationEngine,
    ReputationScore,
    ReputationEvent,
    MemoryReputationStore,
)


class TestReputationEngine:
    """Tests for ReputationEngine."""

    @pytest.mark.asyncio
    async def test_default_score(self):
        """New agents start with base score of 50."""
        engine = ReputationEngine()
        score = await engine.get_score("did:web:new-agent.com")

        assert score.score == 50
        assert score.tier == "neutral"

    @pytest.mark.asyncio
    async def test_success_increases_score(self):
        """Successful actions increase score."""
        engine = ReputationEngine()
        did = "did:web:good-agent.com"

        initial = await engine.get_score(did)
        new_score = await engine.record_success(did, "Completed task")

        assert new_score > initial.score

    @pytest.mark.asyncio
    async def test_failure_decreases_score(self):
        """Failed actions decrease score."""
        engine = ReputationEngine()
        did = "did:web:failing-agent.com"

        initial = await engine.get_score(did)
        new_score = await engine.record_failure(did, "Task failed")

        assert new_score < initial.score

    @pytest.mark.asyncio
    async def test_slash_penalty(self):
        """Slashing applies significant penalty."""
        engine = ReputationEngine()
        did = "did:web:bad-agent.com"

        # Build up some reputation first
        for _ in range(10):
            await engine.record_success(did)

        score_before = await engine.get_score(did)
        await engine.slash(did, amount=20, reason="Policy violation")
        score_after = await engine.get_score(did)

        assert score_after.score == score_before.score - 20

    @pytest.mark.asyncio
    async def test_boost(self):
        """Boost increases score."""
        engine = ReputationEngine()
        did = "did:web:verified-agent.com"

        initial = await engine.get_score(did)
        new_score = await engine.boost(did, amount=10, reason="Verified credentials")

        assert new_score == initial.score + 10

    @pytest.mark.asyncio
    async def test_score_capped_at_100(self):
        """Score cannot exceed 100."""
        engine = ReputationEngine()
        did = "did:web:excellent-agent.com"

        for _ in range(100):
            await engine.record_success(did)

        score = await engine.get_score(did)
        assert score.score <= 100

    @pytest.mark.asyncio
    async def test_score_floor_at_0(self):
        """Score cannot go below 0."""
        engine = ReputationEngine()
        did = "did:web:terrible-agent.com"

        for _ in range(100):
            await engine.record_failure(did)

        score = await engine.get_score(did)
        assert score.score >= 0

    @pytest.mark.asyncio
    async def test_history_tracking(self):
        """Events are recorded in history."""
        engine = ReputationEngine()
        did = "did:web:tracked-agent.com"

        await engine.record_success(did, "Task 1")
        await engine.record_failure(did, "Task 2")
        await engine.record_success(did, "Task 3")

        history = await engine.get_history(did)

        assert len(history) == 3
        # Events are in chronological order (oldest first)
        assert history[0].reason == "Task 1"

    @pytest.mark.asyncio
    async def test_reset_score(self):
        """Reset returns score to baseline."""
        engine = ReputationEngine()
        did = "did:web:reset-agent.com"

        for _ in range(20):
            await engine.record_success(did)

        await engine.reset(did)
        score = await engine.get_score(did)

        assert score.score == 50


class TestReputationTiers:
    """Tests for reputation tier classification."""

    @pytest.mark.asyncio
    async def test_exceptional_tier(self):
        """Score 90+ is exceptional."""
        engine = ReputationEngine()
        did = "did:web:exceptional.com"

        for _ in range(50):
            await engine.record_success(did)

        score = await engine.get_score(did)
        assert score.tier == "exceptional"

    @pytest.mark.asyncio
    async def test_untrusted_tier(self):
        """Score under 25 is untrusted."""
        engine = ReputationEngine()
        did = "did:web:untrusted.com"

        for _ in range(30):
            await engine.record_failure(did)

        score = await engine.get_score(did)
        assert score.tier == "untrusted"


class TestReputationStatistics:
    """Tests for reputation statistics."""

    @pytest.mark.asyncio
    async def test_success_rate(self):
        """Success rate is calculated correctly."""
        engine = ReputationEngine()
        did = "did:web:stats-agent.com"

        # 3 successes, 1 failure = 75% success rate
        await engine.record_success(did)
        await engine.record_success(did)
        await engine.record_success(did)
        await engine.record_failure(did)

        score = await engine.get_score(did)
        assert score.success_rate == 0.75
        assert score.total_actions == 4
