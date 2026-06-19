"""
Vouch Protocol Key Registry.

Provides a pre-loaded registry of known agent public keys for
high-performance verification without DID resolution.
"""

import json
import logging
import asyncio
from typing import Dict, Optional, List, Set
from dataclasses import dataclass, field
from pathlib import Path
import threading

logger = logging.getLogger(__name__)


@dataclass
class AgentInfo:
    """Information about a registered agent."""

    did: str
    public_key_jwk: str
    name: Optional[str] = None
    organization: Optional[str] = None
    reputation_score: int = 50
    is_trusted: bool = True
    metadata: Dict = field(default_factory=dict)


class KeyRegistry:
    """
    Pre-loaded registry of agent public keys.

    Provides instant key lookup without network calls, ideal for
    high-throughput verification of known agents.

    Example:
        >>> registry = KeyRegistry()
        >>> registry.load_from_file('agents.json')
        >>>
        >>> # Fast lookup
        >>> key = registry.get_key('did:web:agent.com')
        >>> if key:
        ...     valid, passport = Verifier.verify(token, public_key_jwk=key)
    """

    def __init__(self):
        """Initialize the registry."""
        self._agents: Dict[str, AgentInfo] = {}
        self._lock = threading.RLock()
        self._trusted_dids: Set[str] = set()

    def register(self, agent: AgentInfo) -> None:
        """Register an agent."""
        with self._lock:
            self._agents[agent.did] = agent
            if agent.is_trusted:
                self._trusted_dids.add(agent.did)
            logger.debug(f"Registered agent: {agent.did}")

    def register_key(
        self, did: str, public_key_jwk: str, name: Optional[str] = None, is_trusted: bool = True
    ) -> None:
        """Register a public key for a DID."""
        self.register(
            AgentInfo(did=did, public_key_jwk=public_key_jwk, name=name, is_trusted=is_trusted)
        )

    def get_key(self, did: str) -> Optional[str]:
        """Get public key for a DID."""
        with self._lock:
            agent = self._agents.get(did)
            return agent.public_key_jwk if agent else None

    def get_agent(self, did: str) -> Optional[AgentInfo]:
        """Get full agent info for a DID."""
        with self._lock:
            return self._agents.get(did)

    def is_registered(self, did: str) -> bool:
        """Check if a DID is registered."""
        with self._lock:
            return did in self._agents

    def is_trusted(self, did: str) -> bool:
        """Check if a DID is trusted."""
        with self._lock:
            return did in self._trusted_dids

    def unregister(self, did: str) -> bool:
        """Remove an agent from the registry."""
        with self._lock:
            if did in self._agents:
                del self._agents[did]
                self._trusted_dids.discard(did)
                return True
            return False

    def load_from_file(self, path: str) -> int:
        """
        Load agents from a JSON file.

        Expected format:
        {
            "agents": [
                {
                    "did": "did:web:agent.com",
                    "public_key_jwk": "{...}",
                    "name": "Agent Name",
                    "is_trusted": true
                }
            ]
        }

        Returns:
            Number of agents loaded.
        """
        try:
            with open(path, "r") as f:
                data = json.load(f)

            agents = data.get("agents", [])
            count = 0

            for agent_data in agents:
                try:
                    agent = AgentInfo(
                        did=agent_data["did"],
                        public_key_jwk=agent_data["public_key_jwk"],
                        name=agent_data.get("name"),
                        organization=agent_data.get("organization"),
                        reputation_score=agent_data.get("reputation_score", 50),
                        is_trusted=agent_data.get("is_trusted", True),
                        metadata=agent_data.get("metadata", {}),
                    )
                    self.register(agent)
                    count += 1
                except KeyError as e:
                    logger.warning(f"Invalid agent entry: missing {e}")

            logger.info(f"Loaded {count} agents from {path}")
            return count

        except Exception as e:
            logger.error(f"Failed to load registry from {path}: {e}")
            return 0

    def save_to_file(self, path: str) -> bool:
        """Save registry to a JSON file."""
        try:
            with self._lock:
                agents_data = []
                for agent in self._agents.values():
                    agents_data.append(
                        {
                            "did": agent.did,
                            "public_key_jwk": agent.public_key_jwk,
                            "name": agent.name,
                            "organization": agent.organization,
                            "reputation_score": agent.reputation_score,
                            "is_trusted": agent.is_trusted,
                            "metadata": agent.metadata,
                        }
                    )

            with open(path, "w") as f:
                json.dump({"agents": agents_data}, f, indent=2)

            logger.info(f"Saved {len(agents_data)} agents to {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save registry to {path}: {e}")
            return False

    def export_for_verifier(self) -> Dict[str, str]:
        """Export as dict for Verifier trusted_roots parameter."""
        with self._lock:
            return {
                did: agent.public_key_jwk for did, agent in self._agents.items() if agent.is_trusted
            }

    def list_agents(self, trusted_only: bool = False) -> List[AgentInfo]:
        """List all registered agents."""
        with self._lock:
            if trusted_only:
                return [a for a in self._agents.values() if a.is_trusted]
            return list(self._agents.values())

    @property
    def count(self) -> int:
        """Number of registered agents."""
        return len(self._agents)

    @property
    def trusted_count(self) -> int:
        """Number of trusted agents."""
        return len(self._trusted_dids)


# Global registry instance
_global_registry: Optional[KeyRegistry] = None


def get_registry() -> KeyRegistry:
    """Get or create the global registry instance."""
    global _global_registry
    if _global_registry is None:
        _global_registry = KeyRegistry()
    return _global_registry
