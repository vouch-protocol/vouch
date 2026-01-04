"""
Vouch Protocol - The Identity & Reputation Standard for AI Agents.

This package provides cryptographic identity binding for autonomous AI agents,
enabling verifiable proof of intent and non-repudiation.
"""

__version__ = "1.3.1"

# Core signing/verification
from .signer import Signer
from .verifier import Verifier, Passport, VerificationError, DelegationLink
from .auditor import Auditor

# Key management
from .keys import generate_identity, KeyPair
from .kms import RotatingKeyProvider, KeyConfig

# Audio signing
from .audio import AudioSigner, SignedAudioFrame


# Enterprise features (lazy imports to avoid requiring optional deps)
def __getattr__(name):
    """Lazy loading of enterprise features."""
    if name == "AsyncVerifier":
        from .async_verifier import AsyncVerifier

        return AsyncVerifier
    elif name == "VerificationResult":
        from .async_verifier import VerificationResult

        return VerificationResult
    elif name in ("MemoryCache", "RedisCache", "TieredCache", "CacheInterface"):
        from . import cache

        return getattr(cache, name)
    elif name in ("MemoryNonceTracker", "RedisNonceTracker", "NonceTrackerInterface"):
        from . import nonce

        return getattr(nonce, name)
    elif name in (
        "MemoryRateLimiter",
        "RedisRateLimiter",
        "CompositeRateLimiter",
        "RateLimitResult",
    ):
        from . import ratelimit

        return getattr(ratelimit, name)
    elif name in ("VouchMetrics", "get_metrics"):
        from . import metrics

        return getattr(metrics, name)
    elif name in ("KeyRegistry", "AgentInfo", "get_registry"):
        from . import registry

        return getattr(registry, name)
    # Revocation
    elif name in (
        "RevocationRegistry",
        "RevocationRecord",
        "MemoryRevocationStore",
        "RedisRevocationStore",
    ):
        from . import revocation

        return getattr(revocation, name)
    # Reputation
    elif name in (
        "ReputationEngine",
        "ReputationScore",
        "ReputationEvent",
        "MemoryReputationStore",
        "RedisReputationStore",
        "KafkaReputationStore",
        "KafkaReputationConsumer",
    ):
        from . import reputation

        return getattr(reputation, name)
    # Cloud KMS
    elif name in ("CloudKMSProvider", "AWSKMSProvider", "GCPKMSProvider", "AzureKeyVaultProvider"):
        from . import kms

        return getattr(kms, name)
    raise AttributeError(f"module 'vouch' has no attribute '{name}'")


__all__ = [
    "__version__",
    # Core
    "Signer",
    "Verifier",
    "Passport",
    "VerificationError",
    "DelegationLink",
    "Auditor",
    # Key management
    "generate_identity",
    "KeyPair",
    "RotatingKeyProvider",
    "KeyConfig",
    # Audio
    "AudioSigner",
    "SignedAudioFrame",
    # Enterprise (lazy loaded)
    "AsyncVerifier",
    "VerificationResult",
    # Caching
    "MemoryCache",
    "RedisCache",
    "TieredCache",
    "CacheInterface",
    # Nonce tracking
    "MemoryNonceTracker",
    "RedisNonceTracker",
    "NonceTrackerInterface",
    # Rate limiting
    "MemoryRateLimiter",
    "RedisRateLimiter",
    "CompositeRateLimiter",
    "RateLimitResult",
    # Metrics
    "VouchMetrics",
    "get_metrics",
    # Registry
    "KeyRegistry",
    "AgentInfo",
    "get_registry",
    # Revocation
    "RevocationRegistry",
    "RevocationRecord",
    "MemoryRevocationStore",
    "RedisRevocationStore",
    # Reputation
    "ReputationEngine",
    "ReputationScore",
    "ReputationEvent",
    "MemoryReputationStore",
    "RedisReputationStore",
    "KafkaReputationStore",
    "KafkaReputationConsumer",
    # Cloud KMS
    "CloudKMSProvider",
    "AWSKMSProvider",
    "GCPKMSProvider",
    "AzureKeyVaultProvider",
]
