"""
Vouch Shield - Trust Registry.

Manages trusted and blocked DIDs using the existing revocation infrastructure.
Extends RevocationStoreInterface to support allowlist mode.
"""

import asyncio
import os
import json
import logging
from typing import Optional, List, Set
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from vouch.revocation import (
    RevocationStoreInterface,
    MemoryRevocationStore,
    RevocationRecord,
)

logger = logging.getLogger(__name__)


def _run(coro):
    """Run a coroutine from synchronous code, leaving global state as found.

    ``asyncio.get_event_loop()`` is deprecated and raises once nothing has a
    current loop set. ``asyncio.run()`` would clear the current loop on exit,
    which breaks any code elsewhere in the process that still relies on the
    older accessor, so this restores whatever loop was set beforehand.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        # Already inside a running loop, which cannot be re-entered. Give the
        # coroutine its own loop on a worker thread instead of failing.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()

    try:
        previous = asyncio.get_event_loop_policy().get_event_loop()
    except RuntimeError:
        previous = None

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(previous)


class TrustStatus(Enum):
    """Trust status for a DID."""

    TRUSTED = "trusted"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


@dataclass
class TrustConfig:
    """Configuration for trust registry."""

    config_path: Optional[str] = None
    strict_mode: bool = True  # If True, unknown DIDs are blocked


class TrustRegistry:
    """
    Manages trusted and blocked DIDs.

    Uses the existing revocation infrastructure for blocklist,
    and adds allowlist functionality.

    Example:
        >>> registry = TrustRegistry()
        >>> registry.trust("did:vouch:publisher123")
        >>> registry.get_status("did:vouch:publisher123")
        TrustStatus.TRUSTED
    """

    def __init__(
        self,
        revocation_store: Optional[RevocationStoreInterface] = None,
        config_path: Optional[str] = None,
        strict_mode: bool = True,
    ):
        """
        Initialize the trust registry.

        Args:
            revocation_store: Backend for blocklist (defaults to memory store).
            config_path: Path to JSON config file with trusted/blocked DIDs.
            strict_mode: If True, unknown DIDs are treated as blocked.
        """
        self._revocation_store = revocation_store or MemoryRevocationStore()
        self._trusted_dids: Set[str] = set()
        self._strict_mode = strict_mode
        self._config_path = config_path or self._default_config_path()

        self._load_config()

    def _default_config_path(self) -> str:
        """Get default config path."""
        vouch_dir = Path.home() / ".vouch"
        vouch_dir.mkdir(exist_ok=True)
        return str(vouch_dir / "trust_registry.json")

    def _load_config(self) -> None:
        """Load trust config from file."""
        try:
            if os.path.exists(self._config_path):
                with open(self._config_path, "r") as f:
                    config = json.load(f)
                    self._trusted_dids = set(config.get("trusted_dids", []))

                    # Load blocked DIDs into revocation store
                    for did in config.get("blocked_dids", []):
                        record = RevocationRecord(
                            did=did, revoked_at=0, reason="Loaded from config"
                        )
                        _run(self._revocation_store.add_revocation(record))

                    logger.info(
                        f"Loaded trust config: {len(self._trusted_dids)} trusted, "
                        f"{len(config.get('blocked_dids', []))} blocked"
                    )
        except Exception as e:
            logger.warning(f"Could not load trust config: {e}")

    def save_config(self) -> None:
        """Save trust config to file."""
        blocked = _run(self._revocation_store.list_revocations())

        config = {
            "trusted_dids": list(self._trusted_dids),
            "blocked_dids": [r.did for r in blocked],
        }

        with open(self._config_path, "w") as f:
            json.dump(config, f, indent=2)

    def trust(self, did: str) -> None:
        """Add a DID to the trusted list."""
        self._trusted_dids.add(did)
        # Remove from blocked if present
        _run(self._revocation_store.remove_revocation(did))
        logger.info(f"Trusted DID: {did}")

    def block(self, did: str, reason: str = "Manually blocked") -> None:
        """Add a DID to the blocked list."""
        self._trusted_dids.discard(did)
        import time

        record = RevocationRecord(did=did, revoked_at=int(time.time()), reason=reason)
        _run(self._revocation_store.add_revocation(record))
        logger.info(f"Blocked DID: {did} - {reason}")

    def remove(self, did: str) -> None:
        """Remove a DID from all lists (reset to unknown)."""
        self._trusted_dids.discard(did)
        _run(self._revocation_store.remove_revocation(did))

    def get_status(self, did: str) -> TrustStatus:
        """Get the trust status of a DID."""
        # Check blocked first (revocation takes precedence)
        is_blocked = _run(self._revocation_store.is_revoked(did))
        if is_blocked:
            return TrustStatus.BLOCKED

        if did in self._trusted_dids:
            return TrustStatus.TRUSTED

        return TrustStatus.UNKNOWN

    def is_allowed(self, did: str) -> bool:
        """Check if a DID is allowed to execute (trusted or non-strict unknown)."""
        status = self.get_status(did)

        if status == TrustStatus.BLOCKED:
            return False

        if status == TrustStatus.TRUSTED:
            return True

        # Unknown DID
        return not self._strict_mode

    def get_trusted(self) -> List[str]:
        """Get all trusted DIDs."""
        return list(self._trusted_dids)

    def get_blocked(self) -> List[str]:
        """Get all blocked DIDs."""
        records = _run(self._revocation_store.list_revocations())
        return [r.did for r in records]
