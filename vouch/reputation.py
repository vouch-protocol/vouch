"""
Vouch Protocol Reputation Engine.

Provides reputation scoring, history tracking, and slashing for AI agents.
Implements a dynamic scoring algorithm with decay toward baseline.
"""

import time
import logging
import asyncio
import math
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Literal
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of reputation-affecting actions."""

    SUCCESS = "success"
    FAILURE = "failure"
    SLASH = "slash"
    BOOST = "boost"


@dataclass
class ReputationEvent:
    """
    A single reputation-affecting event.

    Attributes:
        did: The agent DID.
        action_type: Type of action (success, failure, slash, boost).
        delta: Score change (+/-).
        reason: Description of the event.
        timestamp: Unix timestamp of event.
        metadata: Optional additional data.
    """

    did: str
    action_type: str
    delta: int
    reason: str
    timestamp: int
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ReputationEvent":
        return cls(**data)


@dataclass
class ReputationScore:
    """
    Current reputation score for an agent.

    Attributes:
        did: The agent DID.
        score: Current score (0-100).
        total_actions: Total number of actions recorded.
        success_rate: Percentage of successful actions.
        last_action_at: Timestamp of last action.
        decay_applied: Whether decay was applied to current score.
    """

    did: str
    score: int
    total_actions: int
    success_rate: float
    last_action_at: Optional[int]
    decay_applied: bool = False

    @property
    def tier(self) -> str:
        """Get reputation tier based on score."""
        if self.score >= 90:
            return "exceptional"
        elif self.score >= 75:
            return "trusted"
        elif self.score >= 50:
            return "neutral"
        elif self.score >= 25:
            return "cautionary"
        else:
            return "untrusted"


class ReputationStoreInterface(ABC):
    """Abstract interface for reputation storage."""

    @abstractmethod
    async def get_score(self, did: str) -> int:
        """Get raw score for DID."""
        pass

    @abstractmethod
    async def set_score(self, did: str, score: int) -> None:
        """Set score for DID."""
        pass

    @abstractmethod
    async def add_event(self, event: ReputationEvent) -> None:
        """Record a reputation event."""
        pass

    @abstractmethod
    async def get_events(self, did: str, limit: int = 100) -> List[ReputationEvent]:
        """Get history of events for DID."""
        pass

    @abstractmethod
    async def get_stats(self, did: str) -> Dict:
        """Get statistics for DID."""
        pass


class MemoryReputationStore(ReputationStoreInterface):
    """
    In-memory reputation store for testing and single-instance deployments.
    """

    def __init__(self):
        self._scores: Dict[str, int] = defaultdict(lambda: 50)
        self._events: Dict[str, List[ReputationEvent]] = defaultdict(list)
        self._stats: Dict[str, Dict] = defaultdict(
            lambda: {"successes": 0, "failures": 0, "last_action_at": None}
        )
        self._lock = asyncio.Lock()

    async def get_score(self, did: str) -> int:
        async with self._lock:
            return self._scores[did]

    async def set_score(self, did: str, score: int) -> None:
        async with self._lock:
            self._scores[did] = max(0, min(100, score))

    async def add_event(self, event: ReputationEvent) -> None:
        async with self._lock:
            self._events[event.did].append(event)
            self._stats[event.did]["last_action_at"] = event.timestamp

            if event.action_type == ActionType.SUCCESS.value:
                self._stats[event.did]["successes"] += 1
            elif event.action_type == ActionType.FAILURE.value:
                self._stats[event.did]["failures"] += 1

    async def get_events(self, did: str, limit: int = 100) -> List[ReputationEvent]:
        async with self._lock:
            events = self._events.get(did, [])
            return sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]

    async def get_stats(self, did: str) -> Dict:
        async with self._lock:
            stats = self._stats[did]
            total = stats["successes"] + stats["failures"]
            success_rate = stats["successes"] / total if total > 0 else 0.0

            return {
                "total_actions": total,
                "successes": stats["successes"],
                "failures": stats["failures"],
                "success_rate": success_rate,
                "last_action_at": stats["last_action_at"],
            }


class RedisReputationStore(ReputationStoreInterface):
    """
    Redis-backed reputation store for distributed deployments (10K-50K RPS).

    Provides sub-millisecond reads and fast writes suitable for production.

    Requires: pip install redis

    Example:
        >>> import redis.asyncio as redis
        >>> client = redis.Redis(host='localhost', port=6379)
        >>> store = RedisReputationStore(client)
        >>> engine = ReputationEngine(store=store)
    """

    def __init__(
        self, redis_client, key_prefix: str = "vouch:reputation:", default_score: int = 50
    ):
        self._redis = redis_client
        self._prefix = key_prefix
        self._default_score = default_score

    def _score_key(self, did: str) -> str:
        return f"{self._prefix}score:{did}"

    def _stats_key(self, did: str) -> str:
        return f"{self._prefix}stats:{did}"

    def _events_key(self, did: str) -> str:
        return f"{self._prefix}events:{did}"

    async def get_score(self, did: str) -> int:
        try:
            score = await self._redis.get(self._score_key(did))
            return int(score) if score else self._default_score
        except Exception as e:
            logger.warning(f"Redis get_score error: {e}")
            return self._default_score

    async def set_score(self, did: str, score: int) -> None:
        try:
            clamped = max(0, min(100, score))
            await self._redis.set(self._score_key(did), clamped)
        except Exception as e:
            logger.error(f"Redis set_score error: {e}")
            raise

    async def add_event(self, event: ReputationEvent) -> None:
        import json

        try:
            # Store event in list
            await self._redis.lpush(self._events_key(event.did), json.dumps(event.to_dict()))
            # Trim to last 1000 events
            await self._redis.ltrim(self._events_key(event.did), 0, 999)

            # Update stats
            stats_key = self._stats_key(event.did)
            await self._redis.hset(stats_key, "last_action_at", event.timestamp)

            if event.action_type == ActionType.SUCCESS.value:
                await self._redis.hincrby(stats_key, "successes", 1)
            elif event.action_type == ActionType.FAILURE.value:
                await self._redis.hincrby(stats_key, "failures", 1)
        except Exception as e:
            logger.error(f"Redis add_event error: {e}")
            raise

    async def get_events(self, did: str, limit: int = 100) -> List[ReputationEvent]:
        import json

        try:
            raw_events = await self._redis.lrange(self._events_key(did), 0, limit - 1)
            events = []
            for raw in raw_events:
                data = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
                events.append(ReputationEvent.from_dict(data))
            return events
        except Exception as e:
            logger.warning(f"Redis get_events error: {e}")
            return []

    async def get_stats(self, did: str) -> Dict:
        try:
            stats = await self._redis.hgetall(self._stats_key(did))

            def decode(v):
                return v.decode() if isinstance(v, bytes) else v

            successes = int(decode(stats.get(b"successes", 0)) or 0)
            failures = int(decode(stats.get(b"failures", 0)) or 0)
            last_action = stats.get(b"last_action_at")

            total = successes + failures

            return {
                "total_actions": total,
                "successes": successes,
                "failures": failures,
                "success_rate": successes / total if total > 0 else 0.0,
                "last_action_at": int(decode(last_action)) if last_action else None,
            }
        except Exception as e:
            logger.warning(f"Redis get_stats error: {e}")
            return {
                "total_actions": 0,
                "successes": 0,
                "failures": 0,
                "success_rate": 0.0,
                "last_action_at": None,
            }


class KafkaReputationStore(ReputationStoreInterface):
    """
    Kafka-backed reputation store for high-throughput event streaming (50K+ RPS).

    This store uses Kafka for async event ingestion and Redis for fast score reads.
    Events are streamed to Kafka and a separate consumer updates Redis.

    Architecture:
    - Writes: Async publish to Kafka topic (non-blocking)
    - Reads: From Redis (sub-ms latency)
    - Processing: Separate Flink/Kafka Streams job updates Redis from Kafka

    Requires: pip install aiokafka redis

    Example:
        >>> from aiokafka import AIOKafkaProducer
        >>> import redis.asyncio as redis
        >>>
        >>> producer = AIOKafkaProducer(bootstrap_servers='kafka:9092')
        >>> redis_client = redis.Redis(host='localhost', port=6379)
        >>>
        >>> store = KafkaReputationStore(
        ...     kafka_producer=producer,
        ...     redis_client=redis_client,
        ...     topic="vouch.reputation.events"
        ... )
        >>> engine = ReputationEngine(store=store)
    """

    def __init__(
        self,
        kafka_producer,
        redis_client,
        topic: str = "vouch.reputation.events",
        key_prefix: str = "vouch:reputation:",
    ):
        """
        Initialize Kafka + Redis hybrid store.

        Args:
            kafka_producer: AIOKafkaProducer instance.
            redis_client: Redis async client for fast reads.
            topic: Kafka topic for events.
            key_prefix: Redis key prefix.
        """
        self._producer = kafka_producer
        self._redis = redis_client
        self._topic = topic
        self._prefix = key_prefix
        self._redis_store = RedisReputationStore(redis_client, key_prefix)

    async def get_score(self, did: str) -> int:
        """Read from Redis (fast path)."""
        return await self._redis_store.get_score(did)

    async def set_score(self, did: str, score: int) -> None:
        """Write to Redis (for immediate consistency)."""
        await self._redis_store.set_score(did, score)

    async def add_event(self, event: ReputationEvent) -> None:
        """
        Publish event to Kafka (async, non-blocking).

        The score update is written directly to Redis for consistency,
        while the event is streamed to Kafka for durable storage and
        downstream processing.
        """
        import json

        # Publish to Kafka asynchronously
        try:
            key = event.did.encode("utf-8")
            value = json.dumps(event.to_dict()).encode("utf-8")

            # Fire-and-forget for max throughput
            await self._producer.send(self._topic, key=key, value=value)

            logger.debug(f"Published event to Kafka: {event.did}")
        except Exception as e:
            logger.error(f"Kafka publish error: {e}")
            # Fall back to direct Redis write

        # Also update Redis directly for consistency
        await self._redis_store.add_event(event)

    async def get_events(self, did: str, limit: int = 100) -> List[ReputationEvent]:
        """Read from Redis (events are synced from Kafka by consumer)."""
        return await self._redis_store.get_events(did, limit)

    async def get_stats(self, did: str) -> Dict:
        """Read from Redis."""
        return await self._redis_store.get_stats(did)


# =============================================================================
# Kafka Consumer for Background Processing (separate process)
# =============================================================================


class KafkaReputationConsumer:
    """
    Kafka consumer for processing reputation events.

    Run this as a separate background worker to consume events
    from Kafka and update Redis.

    Example:
        >>> consumer = KafkaReputationConsumer(
        ...     bootstrap_servers='kafka:9092',
        ...     redis_url='redis://localhost:6379',
        ...     topic='vouch.reputation.events',
        ...     group_id='reputation-processor'
        ... )
        >>> await consumer.run()  # Blocks, consuming events
    """

    def __init__(
        self,
        bootstrap_servers: str,
        redis_url: str,
        topic: str = "vouch.reputation.events",
        group_id: str = "reputation-processor",
    ):
        self._bootstrap = bootstrap_servers
        self._redis_url = redis_url
        self._topic = topic
        self._group_id = group_id
        self._running = False

    async def run(self) -> None:
        """Start consuming events and updating Redis."""
        try:
            from aiokafka import AIOKafkaConsumer
            import redis.asyncio as redis_async
        except ImportError:
            raise ImportError("Kafka consumer requires: pip install aiokafka redis")

        import json

        consumer = AIOKafkaConsumer(
            self._topic,
            bootstrap_servers=self._bootstrap,
            group_id=self._group_id,
            auto_offset_reset="earliest",
        )

        redis_client = redis_async.from_url(self._redis_url)
        store = RedisReputationStore(redis_client)

        await consumer.start()
        self._running = True

        logger.info(f"Started Kafka consumer for {self._topic}")

        try:
            async for msg in consumer:
                if not self._running:
                    break

                try:
                    event_data = json.loads(msg.value.decode())
                    event = ReputationEvent.from_dict(event_data)

                    # Process event: update score in Redis
                    current_score = await store.get_score(event.did)
                    new_score = max(0, min(100, current_score + event.delta))
                    await store.set_score(event.did, new_score)

                    logger.debug(f"Processed event for {event.did}: {event.delta:+d}")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
        finally:
            await consumer.stop()
            await redis_client.close()

    def stop(self) -> None:
        """Signal the consumer to stop."""
        self._running = False


class ReputationEngine:
    """
    High-level reputation management engine.

    Features:
    - Dynamic scoring with configurable weights
    - Time-based decay toward baseline
    - Slashing for serious violations
    - History tracking

    Scoring Algorithm:
    - Base score: 50
    - Success: +1 (max 100)
    - Failure: -2
    - Slash: Configurable penalty
    - Decay: Score trends toward 50 after inactivity

    Example:
        >>> engine = ReputationEngine()
        >>>
        >>> # Record actions
        >>> await engine.record_success("did:web:agent.com", "Completed transaction")
        >>> await engine.record_failure("did:web:agent.com", "Failed to respond")
        >>>
        >>> # Get reputation
        >>> score = await engine.get_score("did:web:agent.com")
        >>> print(f"Score: {score.score}, Tier: {score.tier}")
        >>>
        >>> # Slash for violation
        >>> await engine.slash("did:web:agent.com", amount=20, reason="Policy violation")
    """

    DEFAULT_CONFIG = {
        "base_score": 50,
        "max_score": 100,
        "min_score": 0,
        "success_reward": 1,
        "failure_penalty": 2,
        "decay_rate": 0.1,  # Decay 10% of distance to base per day
        "decay_threshold_days": 7,  # Start decay after 7 days inactivity
    }

    def __init__(
        self, store: Optional[ReputationStoreInterface] = None, config: Optional[Dict] = None
    ):
        """
        Initialize the reputation engine.

        Args:
            store: Storage backend for reputation data.
            config: Custom configuration overrides.
        """
        self._store = store or MemoryReputationStore()
        self._config = {**self.DEFAULT_CONFIG, **(config or {})}

    async def record_success(
        self,
        did: str,
        reason: str = "Action completed successfully",
        metadata: Optional[Dict] = None,
    ) -> int:
        """
        Record a successful action.

        Args:
            did: The agent DID.
            reason: Description of success.
            metadata: Optional additional data.

        Returns:
            New score after update.
        """
        return await self._apply_delta(
            did=did,
            delta=self._config["success_reward"],
            action_type=ActionType.SUCCESS,
            reason=reason,
            metadata=metadata or {},
        )

    async def record_failure(
        self, did: str, reason: str = "Action failed", metadata: Optional[Dict] = None
    ) -> int:
        """
        Record a failed action.

        Args:
            did: The agent DID.
            reason: Description of failure.
            metadata: Optional additional data.

        Returns:
            New score after update.
        """
        return await self._apply_delta(
            did=did,
            delta=-self._config["failure_penalty"],
            action_type=ActionType.FAILURE,
            reason=reason,
            metadata=metadata or {},
        )

    async def slash(
        self, did: str, amount: int, reason: str, metadata: Optional[Dict] = None
    ) -> int:
        """
        Apply a slashing penalty for serious violations.

        Args:
            did: The agent DID.
            amount: Points to deduct (positive number).
            reason: Reason for slashing.
            metadata: Optional additional data.

        Returns:
            New score after slashing.
        """
        return await self._apply_delta(
            did=did,
            delta=-abs(amount),
            action_type=ActionType.SLASH,
            reason=reason,
            metadata=metadata or {},
        )

    async def boost(
        self, did: str, amount: int, reason: str, metadata: Optional[Dict] = None
    ) -> int:
        """
        Apply a reputation boost (e.g., for verified credentials).

        Args:
            did: The agent DID.
            amount: Points to add.
            reason: Reason for boost.
            metadata: Optional additional data.

        Returns:
            New score after boost.
        """
        return await self._apply_delta(
            did=did,
            delta=abs(amount),
            action_type=ActionType.BOOST,
            reason=reason,
            metadata=metadata or {},
        )

    async def _apply_delta(
        self, did: str, delta: int, action_type: ActionType, reason: str, metadata: Dict
    ) -> int:
        """Apply a score change and record event."""
        now = int(time.time())

        # Get current score with decay applied
        current = await self._get_score_with_decay(did)

        # Calculate new score
        new_score = max(self._config["min_score"], min(self._config["max_score"], current + delta))

        # Save new score
        await self._store.set_score(did, new_score)

        # Record event
        event = ReputationEvent(
            did=did,
            action_type=action_type.value,
            delta=delta,
            reason=reason,
            timestamp=now,
            metadata=metadata,
        )
        await self._store.add_event(event)

        logger.debug(f"Reputation update: {did} {delta:+d} -> {new_score}")

        return new_score

    async def _get_score_with_decay(self, did: str) -> int:
        """Get score with time-based decay applied."""
        current = await self._store.get_score(did)
        stats = await self._store.get_stats(did)

        last_action = stats.get("last_action_at")
        if not last_action:
            return current

        # Calculate days since last action
        days_inactive = (time.time() - last_action) / 86400

        if days_inactive < self._config["decay_threshold_days"]:
            return current

        # Apply decay toward base score
        base = self._config["base_score"]
        decay_days = days_inactive - self._config["decay_threshold_days"]
        decay_factor = math.pow(1 - self._config["decay_rate"], decay_days)

        # Decay pulls score toward base
        distance_from_base = current - base
        decayed_score = base + (distance_from_base * decay_factor)

        return int(round(decayed_score))

    async def get_score(self, did: str) -> ReputationScore:
        """
        Get full reputation score for an agent.

        Args:
            did: The agent DID.

        Returns:
            ReputationScore with current score and metadata.
        """
        raw_score = await self._store.get_score(did)
        decayed_score = await self._get_score_with_decay(did)
        stats = await self._store.get_stats(did)

        return ReputationScore(
            did=did,
            score=decayed_score,
            total_actions=stats.get("total_actions", 0),
            success_rate=stats.get("success_rate", 0.0),
            last_action_at=stats.get("last_action_at"),
            decay_applied=(decayed_score != raw_score),
        )

    async def get_history(self, did: str, limit: int = 100) -> List[ReputationEvent]:
        """
        Get reputation history for an agent.

        Args:
            did: The agent DID.
            limit: Maximum events to return.

        Returns:
            List of ReputationEvent objects.
        """
        return await self._store.get_events(did, limit)

    async def reset(self, did: str) -> None:
        """Reset reputation to base score (admin function)."""
        await self._store.set_score(did, self._config["base_score"])
        logger.info(f"Reset reputation for {did}")
