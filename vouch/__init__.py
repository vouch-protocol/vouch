"""
Vouch Protocol - The Identity & Reputation Standard for AI Agents.

This package provides cryptographic identity binding for autonomous AI agents,
enabling verifiable proof of intent and non-repudiation.
"""

__version__ = "1.6.0"

# Core signing/verification
from .signer import Signer
from .verifier import Verifier, Passport, VerificationError, DelegationLink, verify
from .auditor import Auditor

# Key management
from .keys import generate_identity, KeyPair
from .kms import RotatingKeyProvider, KeyConfig

# Deterministic, zero-prompt signing for agent tool calls. Wrap a tool once and
# every call is signed in Python before it runs - no reliance on the model
# choosing to call a signing tool. See vouch.autosign and the framework
# adapters under vouch.integrations.*.
from .autosign import (
    current_credential,
    delegate,
    protect,
    resolve_signer,
    sign_intent,
    signed,
)

# Audio signing
from .audio import AudioSigner, SignedAudioResult


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
    # BitstringStatusList (credential-level status, Specification §11.2)
    elif name in (
        "StatusList",
        "StatusListError",
        "FilesystemStatusListStore",
        "build_status_list_credential",
        "build_status_list_entry",
        "verify_status",
    ):
        from . import status_list

        return getattr(status_list, name)
    elif name in ("StatusListFetcher", "StatusListFetchError"):
        from . import status_list_fetcher

        return getattr(status_list_fetcher, name)
    # State Verifiability runtime (Specification §15)
    elif name in (
        "TrustEntropyError",
        "TrustEvaluation",
        "compute_trust_at",
        "evaluate_trust",
        "check_trust_threshold",
        "half_life_seconds",
        "time_until_threshold",
        "TRUST_THRESHOLD_HIGH_STAKES",
        "TRUST_THRESHOLD_MEDIUM_STAKES",
        "TRUST_THRESHOLD_LOW_STAKES",
    ):
        from . import trust_entropy

        return getattr(trust_entropy, name)
    elif name in (
        "BehavioralAttestationError",
        "BehavioralCollector",
        "BehavioralSample",
        "validate_behavioral_digest",
        "mean_drift_scorer",
        "max_drift_scorer",
        "ewma_drift_scorer",
    ):
        from . import behavioral_attestation

        return getattr(behavioral_attestation, name)
    elif name in (
        "CanaryChain",
        "CanaryChainError",
        "CanaryHeartbeat",
        "CanaryVerifier",
        "compute_commitment",
        "verify_reveal",
    ):
        from . import canary

        return getattr(canary, name)
    elif name in (
        "MerkleError",
        "MerkleTree",
        "InclusionProof",
        "ProofStep",
        "hash_leaf",
        "hash_node",
        "verify_inclusion",
        "compute_action_merkle_root",
    ):
        from . import merkle

        return getattr(merkle, name)
    elif name in (
        "HeartbeatError",
        "HeartbeatRequest",
        "HeartbeatSession",
        "HeartbeatScheduler",
        "HeartbeatValidator",
        "HeartbeatValidationResult",
        "HeartbeatStoreInterface",
        "MemoryHeartbeatStore",
        "HEARTBEAT_PROTOCOL_VERSION",
        "HEARTBEAT_REQUEST_TYPE",
    ):
        from . import heartbeat

        return getattr(heartbeat, name)
    elif name in (
        "HeartbeatQuorum",
        "QuorumError",
        "QuorumPolicy",
        "QuorumResult",
        "QuorumValidator",
        "ROLE_GENERAL",
        "ROLE_POLICY",
        "ROLE_BEHAVIORAL",
        "ROLE_BUDGET",
    ):
        from . import quorum

        return getattr(quorum, name)
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
    # Outcome-evidence credentials (commit-before-outcome verdicts + settlement)
    elif name in (
        "AccountabilityError",
        "commit_outcome",
        "verify_commitment",
        "attest_outcome",
        "verify_attestation",
        "accountability_pointer",
        "commitment_digest",
        "timestamp_anchor",
        "claims_precedence",
        "PRECEDENCE_PRE_OUTCOME",
        "PRECEDENCE_EXISTENCE",
        "OUTCOME_COMMITMENT_TYPE",
        "OUTCOME_ATTESTATION_TYPE",
    ):
        from . import accountability

        return getattr(accountability, name)
    # Reputation receipts and aggregation (evidence-backed reputation)
    elif name in (
        "ReceiptError",
        "Signal",
        "build_state_receipt",
        "verify_state_receipt",
        "build_penalty_receipt",
        "verify_penalty_receipt",
        "normalize_receipt",
        "receipt_subject",
        "STATE_RECEIPT_TYPE",
        "PENALTY_RECEIPT_TYPE",
    ):
        from . import receipts

        return getattr(receipts, name)
    elif name in (
        "ReputationScore",
        "aggregate",
        "aggregate_receipts",
        "AGGREGATION_VERSION",
    ):
        from . import reputation_aggregate

        return getattr(reputation_aggregate, name)
    elif name in (
        "ReputationLedger",
        "LedgerError",
        "build_reputation_credential",
        "verify_reputation_credential",
        "REPUTATION_CREDENTIAL_TYPE",
    ):
        from . import reputation_ledger

        return getattr(reputation_ledger, name)
    elif name in (
        "ReputationPolicy",
        "ReputationDecision",
        "evaluate_reputation",
        "policy_for_stakes",
        "reputation_pointer",
    ):
        from . import reputation_policy

        return getattr(reputation_policy, name)
    elif name in (
        "PortabilityError",
        "build_reputation_proof",
        "verify_reputation_proof",
        "REPUTATION_PROOF_TYPE",
    ):
        from . import reputation_portability

        return getattr(reputation_portability, name)
    elif name in (
        "DisputeError",
        "build_dispute",
        "build_dispute_resolution",
        "verify_dispute",
        "verify_dispute_resolution",
        "DISPUTE_TYPE",
        "DISPUTE_RESOLUTION_TYPE",
    ):
        from . import reputation_disputes

        return getattr(reputation_disputes, name)
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
    "verify",
    "Passport",
    "VerificationError",
    "DelegationLink",
    "Auditor",
    # Key management
    "generate_identity",
    "KeyPair",
    "RotatingKeyProvider",
    "KeyConfig",
    # Deterministic agent-tool signing
    "protect",
    "signed",
    "delegate",
    "sign_intent",
    "current_credential",
    "resolve_signer",
    # Audio
    "AudioSigner",
    "SignedAudioResult",
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
    # BitstringStatusList
    "StatusList",
    "StatusListError",
    "FilesystemStatusListStore",
    "StatusListFetcher",
    "StatusListFetchError",
    "build_status_list_credential",
    "build_status_list_entry",
    "verify_status",
    # Reputation
    "ReputationEngine",
    "ReputationScore",
    "ReputationEvent",
    "MemoryReputationStore",
    "RedisReputationStore",
    "KafkaReputationStore",
    "KafkaReputationConsumer",
    # Outcome-evidence credentials
    "AccountabilityError",
    "commit_outcome",
    "verify_commitment",
    "attest_outcome",
    "verify_attestation",
    "accountability_pointer",
    "commitment_digest",
    "timestamp_anchor",
    "claims_precedence",
    "PRECEDENCE_PRE_OUTCOME",
    "PRECEDENCE_EXISTENCE",
    "OUTCOME_COMMITMENT_TYPE",
    "OUTCOME_ATTESTATION_TYPE",
    # Reputation receipts and aggregation
    "ReceiptError",
    "Signal",
    "build_state_receipt",
    "verify_state_receipt",
    "build_penalty_receipt",
    "verify_penalty_receipt",
    "normalize_receipt",
    "receipt_subject",
    "ReputationScore",
    "aggregate",
    "aggregate_receipts",
    "AGGREGATION_VERSION",
    "ReputationLedger",
    "LedgerError",
    "build_reputation_credential",
    "verify_reputation_credential",
    "REPUTATION_CREDENTIAL_TYPE",
    "ReputationPolicy",
    "ReputationDecision",
    "evaluate_reputation",
    "policy_for_stakes",
    "reputation_pointer",
    "build_reputation_proof",
    "verify_reputation_proof",
    "REPUTATION_PROOF_TYPE",
    "build_dispute",
    "build_dispute_resolution",
    "verify_dispute",
    "verify_dispute_resolution",
    "DISPUTE_TYPE",
    "DISPUTE_RESOLUTION_TYPE",
    # Cloud KMS
    "CloudKMSProvider",
    "AWSKMSProvider",
    "GCPKMSProvider",
    "AzureKeyVaultProvider",
]
