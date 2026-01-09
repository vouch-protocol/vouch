# vouch/pro/organizations.py
"""
Organization Directory for Chain of Trust verification.

Organizations must be registered in the Vouch directory to be
recognized as valid issuers of employment credentials.

Storage: Cloudflare KV (production) or local cache (development)
"""

import json
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class VerifiedOrganization:
    """
    A verified organization that can issue credentials.
    
    Attributes:
        did: Organization's DID (e.g., did:vouch:nyt)
        name: Display name (e.g., "The New York Times")
        domain: Official domain (e.g., "nytimes.com")
        verification_date: When org was verified
        tier: Organization tier (e.g., "enterprise", "pro")
        public_key: Base64-encoded public key for credential verification
        metadata: Additional metadata
    """
    did: str
    name: str
    domain: str
    verification_date: str
    tier: str
    public_key: str  # Base64-encoded Ed25519 public key
    logo_url: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerifiedOrganization":
        """Create from dictionary."""
        return cls(**data)


# =============================================================================
# Organization Directory
# =============================================================================

class OrganizationDirectory:
    """
    Directory of verified organizations.
    
    In production, this would be backed by Cloudflare KV.
    For development, uses an in-memory cache.
    """
    
    def __init__(self, kv_namespace: Optional[Any] = None):
        """
        Initialize directory.
        
        Args:
            kv_namespace: Cloudflare KV namespace (None for local dev)
        """
        self.kv = kv_namespace
        self._local_cache: Dict[str, VerifiedOrganization] = {}
        
        # Seed with some example orgs for development
        self._seed_dev_orgs()
    
    def _seed_dev_orgs(self):
        """Seed development organizations."""
        dev_orgs = [
            VerifiedOrganization(
                did="did:vouch:nyt",
                name="The New York Times",
                domain="nytimes.com",
                verification_date="2026-01-01T00:00:00Z",
                tier="enterprise",
                public_key="",  # Would be real key in production
            ),
            VerifiedOrganization(
                did="did:vouch:reuters",
                name="Reuters",
                domain="reuters.com",
                verification_date="2026-01-01T00:00:00Z",
                tier="enterprise",
                public_key="",
            ),
            VerifiedOrganization(
                did="did:vouch:bbc",
                name="BBC",
                domain="bbc.com",
                verification_date="2026-01-01T00:00:00Z",
                tier="enterprise",
                public_key="",
            ),
        ]
        
        for org in dev_orgs:
            self._local_cache[org.did] = org
    
    async def lookup(self, did: str) -> Optional[VerifiedOrganization]:
        """
        Look up organization by DID.
        
        Args:
            did: Organization's DID
            
        Returns:
            VerifiedOrganization if found, None otherwise
        """
        # Check local cache first
        if did in self._local_cache:
            return self._local_cache[did]
        
        # Check KV if available
        if self.kv:
            try:
                data = await self.kv.get(f"org:{did}")
                if data:
                    return VerifiedOrganization.from_dict(json.loads(data))
            except Exception:
                pass
        
        return None
    
    def lookup_sync(self, did: str) -> Optional[VerifiedOrganization]:
        """Synchronous lookup (for non-async contexts)."""
        return self._local_cache.get(did)
    
    async def register(self, org: VerifiedOrganization) -> bool:
        """
        Register a new organization (admin only).
        
        Args:
            org: Organization to register
            
        Returns:
            True if successful
        """
        self._local_cache[org.did] = org
        
        if self.kv:
            try:
                await self.kv.put(f"org:{org.did}", json.dumps(org.to_dict()))
            except Exception:
                return False
        
        return True
    
    async def is_verified(self, did: str) -> bool:
        """Check if organization is verified."""
        org = await self.lookup(did)
        return org is not None


# =============================================================================
# Helper Functions
# =============================================================================

# Global directory instance (singleton)
_directory: Optional[OrganizationDirectory] = None


def get_directory() -> OrganizationDirectory:
    """Get the global organization directory."""
    global _directory
    if _directory is None:
        _directory = OrganizationDirectory()
    return _directory


async def lookup_organization(did: str) -> Optional[VerifiedOrganization]:
    """Look up an organization by DID."""
    return await get_directory().lookup(did)


def lookup_organization_sync(did: str) -> Optional[VerifiedOrganization]:
    """Synchronous lookup."""
    return get_directory().lookup_sync(did)


async def is_verified_organization(did: str) -> bool:
    """Check if an organization is verified."""
    return await get_directory().is_verified(did)


def is_verified_organization_sync(did: str) -> bool:
    """Synchronous check."""
    return get_directory().lookup_sync(did) is not None
