"""
Vouch Protocol Key Revocation Registry.

Provides key revocation tracking to prevent use of compromised keys.
Supports memory, Redis, and HTTP (remote registry) backends.
"""

import time
import logging
import json
import asyncio
from abc import ABC, abstractmethod
from typing import Optional, List, Dict
from dataclasses import dataclass, field, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class RevocationRecord:
    """
    Represents a key revocation event.

    Attributes:
        did: The revoked DID.
        revoked_at: Unix timestamp of revocation.
        reason: Reason for revocation.
        revoked_by: DID of authority that issued revocation.
        effective_from: Optional timestamp from which tokens should be rejected.
    """

    did: str
    revoked_at: int
    reason: str
    revoked_by: Optional[str] = None
    effective_from: Optional[int] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "RevocationRecord":
        """Create from dictionary."""
        return cls(**data)


class RevocationStoreInterface(ABC):
    """Abstract interface for revocation storage backends."""

    @abstractmethod
    async def add_revocation(self, record: RevocationRecord) -> None:
        """Add a revocation record."""
        pass

    @abstractmethod
    async def is_revoked(self, did: str) -> bool:
        """Check if a DID is revoked."""
        pass

    @abstractmethod
    async def get_revocation(self, did: str) -> Optional[RevocationRecord]:
        """Get revocation record for a DID."""
        pass

    @abstractmethod
    async def list_revocations(self) -> List[RevocationRecord]:
        """List all revocations."""
        pass

    @abstractmethod
    async def remove_revocation(self, did: str) -> bool:
        """Remove a revocation (reinstate key)."""
        pass


class MemoryRevocationStore(RevocationStoreInterface):
    """
    In-memory revocation store for testing and single-instance deployments.

    Example:
        >>> store = MemoryRevocationStore()
        >>> await store.add_revocation(RevocationRecord(
        ...     did="did:web:compromised-agent.com",
        ...     revoked_at=int(time.time()),
        ...     reason="Key compromised"
        ... ))
        >>> await store.is_revoked("did:web:compromised-agent.com")
        True
    """

    def __init__(self):
        self._revocations: Dict[str, RevocationRecord] = {}
        self._lock = asyncio.Lock()

    async def add_revocation(self, record: RevocationRecord) -> None:
        """Add a revocation record."""
        async with self._lock:
            self._revocations[record.did] = record
            logger.info(f"Revoked DID: {record.did} - Reason: {record.reason}")

    async def is_revoked(self, did: str) -> bool:
        """Check if DID is revoked."""
        async with self._lock:
            if did not in self._revocations:
                return False

            record = self._revocations[did]

            # Check effective_from if set
            if record.effective_from and time.time() < record.effective_from:
                return False

            return True

    async def get_revocation(self, did: str) -> Optional[RevocationRecord]:
        """Get revocation record."""
        async with self._lock:
            return self._revocations.get(did)

    async def list_revocations(self) -> List[RevocationRecord]:
        """List all revocations."""
        async with self._lock:
            return list(self._revocations.values())

    async def remove_revocation(self, did: str) -> bool:
        """Remove revocation (reinstate key)."""
        async with self._lock:
            if did in self._revocations:
                del self._revocations[did]
                logger.info(f"Reinstated DID: {did}")
                return True
            return False


class RedisRevocationStore(RevocationStoreInterface):
    """
    Redis-backed revocation store for distributed deployments.

    Example:
        >>> import redis.asyncio as redis
        >>> client = redis.Redis(host='localhost', port=6379)
        >>> store = RedisRevocationStore(client)
    """

    def __init__(self, redis_client, key_prefix: str = "vouch:revoked:"):
        self._redis = redis_client
        self._prefix = key_prefix
        self._list_key = f"{key_prefix}:list"

    def _key(self, did: str) -> str:
        """Generate prefixed key."""
        return f"{self._prefix}{did}"

    async def add_revocation(self, record: RevocationRecord) -> None:
        """Add revocation to Redis."""
        try:
            await self._redis.set(self._key(record.did), json.dumps(record.to_dict()))
            await self._redis.sadd(self._list_key, record.did)
            logger.info(f"Revoked DID: {record.did}")
        except Exception as e:
            logger.error(f"Redis revocation error: {e}")
            raise

    async def is_revoked(self, did: str) -> bool:
        """Check if DID is revoked."""
        try:
            exists = await self._redis.exists(self._key(did))
            if not exists:
                return False

            # Check effective_from
            record = await self.get_revocation(did)
            if record and record.effective_from:
                if time.time() < record.effective_from:
                    return False

            return True
        except Exception as e:
            logger.warning(f"Redis check error: {e}")
            return False

    async def get_revocation(self, did: str) -> Optional[RevocationRecord]:
        """Get revocation record from Redis."""
        try:
            data = await self._redis.get(self._key(did))
            if data:
                return RevocationRecord.from_dict(json.loads(data))
            return None
        except Exception as e:
            logger.warning(f"Redis get error: {e}")
            return None

    async def list_revocations(self) -> List[RevocationRecord]:
        """List all revocations."""
        try:
            dids = await self._redis.smembers(self._list_key)
            records = []
            for did in dids:
                did_str = did.decode() if isinstance(did, bytes) else did
                record = await self.get_revocation(did_str)
                if record:
                    records.append(record)
            return records
        except Exception as e:
            logger.warning(f"Redis list error: {e}")
            return []

    async def remove_revocation(self, did: str) -> bool:
        """Remove revocation from Redis."""
        try:
            deleted = await self._redis.delete(self._key(did))
            await self._redis.srem(self._list_key, did)
            return deleted > 0
        except Exception as e:
            logger.warning(f"Redis remove error: {e}")
            return False


class HTTPRevocationStore(RevocationStoreInterface):
    """
    HTTP-based revocation store that fetches from remote .well-known endpoints.

    Fetches revocation list from:
    https://{domain}/.well-known/did-revocations.json

    Example:
        >>> store = HTTPRevocationStore(cache_ttl=300)
        >>> await store.is_revoked("did:web:example.com:agent1")
    """

    def __init__(self, cache_ttl: int = 300, http_timeout: float = 10.0):
        self._cache: Dict[str, tuple] = {}  # domain -> (records, fetched_at)
        self._cache_ttl = cache_ttl
        self._timeout = http_timeout
        self._lock = asyncio.Lock()

    async def _fetch_revocations(self, domain: str) -> List[RevocationRecord]:
        """Fetch revocation list from domain."""
        import httpx

        url = f"https://{domain}/.well-known/did-revocations.json"

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(url)

                if response.status_code == 404:
                    return []  # No revocations published

                response.raise_for_status()
                data = response.json()

                records = []
                for item in data.get("revocations", []):
                    records.append(RevocationRecord.from_dict(item))

                return records
        except Exception as e:
            logger.debug(f"Failed to fetch revocations from {domain}: {e}")
            return []

    def _extract_domain(self, did: str) -> Optional[str]:
        """Extract domain from did:web identifier."""
        if not did.startswith("did:web:"):
            return None
        parts = did.split(":")
        if len(parts) >= 3:
            return parts[2].split("/")[0]
        return None

    async def is_revoked(self, did: str) -> bool:
        """Check if DID is revoked by querying its domain."""
        domain = self._extract_domain(did)
        if not domain:
            return False

        async with self._lock:
            # Check cache
            if domain in self._cache:
                records, fetched_at = self._cache[domain]
                if time.time() - fetched_at < self._cache_ttl:
                    return any(r.did == did for r in records)

            # Fetch fresh
            records = await self._fetch_revocations(domain)
            self._cache[domain] = (records, time.time())

            return any(r.did == did for r in records)

    async def add_revocation(self, record: RevocationRecord) -> None:
        """HTTP store is read-only."""
        raise NotImplementedError("HTTP revocation store is read-only")

    async def get_revocation(self, did: str) -> Optional[RevocationRecord]:
        """Get revocation record if exists."""
        domain = self._extract_domain(did)
        if not domain:
            return None

        if domain in self._cache:
            records, _ = self._cache[domain]
            for r in records:
                if r.did == did:
                    return r
        return None

    async def list_revocations(self) -> List[RevocationRecord]:
        """List cached revocations."""
        all_records = []
        for records, _ in self._cache.values():
            all_records.extend(records)
        return all_records

    async def remove_revocation(self, did: str) -> bool:
        """HTTP store is read-only."""
        raise NotImplementedError("HTTP revocation store is read-only")


class RevocationRegistry:
    """
    High-level revocation registry with multiple backend support.

    Combines local store (write) with remote HTTP check (read) for
    comprehensive revocation checking.

    Example:
        >>> registry = RevocationRegistry()
        >>>
        >>> # Revoke a key
        >>> await registry.revoke(
        ...     did="did:web:compromised.com",
        ...     reason="Private key leaked",
        ...     revoked_by="did:web:authority.com"
        ... )
        >>>
        >>> # Check before verification
        >>> if await registry.is_revoked(agent_did):
        ...     raise ValueError("Agent key has been revoked")
    """

    def __init__(
        self,
        local_store: Optional[RevocationStoreInterface] = None,
        check_remote: bool = True,
        remote_cache_ttl: int = 300,
    ):
        """
        Initialize the revocation registry.

        Args:
            local_store: Local store for tracking revocations.
            check_remote: Whether to check remote .well-known endpoints.
            remote_cache_ttl: TTL for remote revocation cache.
        """
        self._local = local_store or MemoryRevocationStore()
        self._remote = HTTPRevocationStore(cache_ttl=remote_cache_ttl) if check_remote else None

    async def revoke(
        self,
        did: str,
        reason: str,
        revoked_by: Optional[str] = None,
        effective_from: Optional[int] = None,
    ) -> RevocationRecord:
        """
        Revoke a DID.

        Args:
            did: The DID to revoke.
            reason: Reason for revocation.
            revoked_by: Authority issuing the revocation.
            effective_from: Optional future timestamp for delayed revocation.

        Returns:
            The created RevocationRecord.
        """
        record = RevocationRecord(
            did=did,
            revoked_at=int(time.time()),
            reason=reason,
            revoked_by=revoked_by,
            effective_from=effective_from,
        )

        await self._local.add_revocation(record)
        return record

    async def is_revoked(self, did: str) -> bool:
        """
        Check if a DID is revoked (local or remote).

        Args:
            did: The DID to check.

        Returns:
            True if revoked, False otherwise.
        """
        # Check local first
        if await self._local.is_revoked(did):
            return True

        # Check remote if enabled
        if self._remote:
            if await self._remote.is_revoked(did):
                return True

        return False

    async def get_revocation(self, did: str) -> Optional[RevocationRecord]:
        """Get revocation details for a DID."""
        record = await self._local.get_revocation(did)
        if record:
            return record

        if self._remote:
            return await self._remote.get_revocation(did)

        return None

    async def reinstate(self, did: str) -> bool:
        """
        Reinstate a revoked DID (remove local revocation).

        Args:
            did: The DID to reinstate.

        Returns:
            True if reinstated, False if not found.
        """
        return await self._local.remove_revocation(did)

    async def list_local_revocations(self) -> List[RevocationRecord]:
        """List all local revocations."""
        return await self._local.list_revocations()

    def export_for_wellknown(self) -> dict:
        """
        Export revocations for .well-known/did-revocations.json

        Returns:
            Dictionary suitable for JSON serialization.
        """
        import asyncio

        records = asyncio.get_event_loop().run_until_complete(self._local.list_revocations())

        return {"revocations": [r.to_dict() for r in records], "updated_at": int(time.time())}
