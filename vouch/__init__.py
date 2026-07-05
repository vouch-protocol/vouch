"""
Vouch Protocol - The Identity & Reputation Standard for AI Agents.

This package provides cryptographic identity binding for autonomous AI agents,
enabling verifiable proof of intent and non-repudiation.
"""

__version__ = "1.6.0"

# Core signing/verification
from .signer import Signer, sign
from .verifier import Verifier, Passport, VerificationError, DelegationLink, verify
from .auditor import Auditor

# One-object identity and the read-friendly credential wrapper (ergonomic sugar
# over Signer/Verifier; the credential dict stays the canonical wire form).
from .agent import Agent
from .credential import Credential

# Key management
from .keys import generate_identity, KeyPair
from .kms import RotatingKeyProvider, KeyConfig

# Where a minted identity is saved (secure by default). See vouch.keystore.
from .keystore import (
    EncryptedFileKeyStore,
    KeyringKeyStore,
    KeyStore,
    MemoryKeyStore,
    resolve_default_store,
)

# Deterministic, zero-prompt signing for agent tool calls. Wrap a tool once and
# every call is signed in Python before it runs - no reliance on the model
# choosing to call a signing tool. See vouch.autosign and the framework
# adapters under vouch.integrations.*.
from .autosign import (
    current_credential,
    current_token_header,
    delegate,
    protect,
    resolve_signer,
    sign_intent,
    signed,
)

# Receiving-side verification guards: a server-side gate and one-line tool
# guards (the counterpart to protect/sign on the sending side).
from .gate import CredentialGate, GateResult
from .mcp_guard import guard_mcp, guard_tools, require_signed

# Cross-device identity: per-device keys delegated from a root, with full chain
# verification back to a trusted root (the key never travels). See vouch.fleet.
from .fleet import DeviceRegistry, FleetResult, enroll_device, verify_delegated_chain

# Root-identity recovery by Shamir secret sharing (split the root across
# guardians; any threshold reconstruct it). See vouch.recovery.
from .recovery import (
    combine_shares,
    recover_identity,
    split_identity,
    split_secret,
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
    # Proof-of-Integration recognition primitive (PAD-072)
    elif name in (
        "ProofOfIntegrationError",
        "build_integration_challenge",
        "answer_integration_challenge",
        "verify_integration_response",
        "proof_of_integration_block",
        "CHALLENGE_TYPE",
        "RESPONSE_TYPE",
    ):
        from . import proof_of_integration

        return getattr(proof_of_integration, name)
    # Liveness-conformance-decaying recognition trust (PAD-073)
    elif name in (
        "LivenessError",
        "build_conformance_receipt",
        "verify_conformance_receipt",
        "last_conformant",
        "consumable_trust",
        "should_revoke",
        "revocation_entry",
        "CONFORMANCE_RECEIPT_TYPE",
    ):
        from . import liveness_conformance

        return getattr(liveness_conformance, name)
    # Reasoned Action Proofs (justification bound to the action, PAD-017/071)
    elif name in (
        "ReasonedActionError",
        "REASONED_ACTION_TYPE",
        "evidence_anchor",
        "build_justification",
        "justification_digest",
        "artifact_digest",
        "build_escrow_receipt",
        "verify_escrow_receipt",
        "LocalEscrow",
        "sign_reasoned_action",
        "check_reasoned_action",
        "verify_reasoned_action",
        "verify_justification",
    ):
        from . import reasoning

        return getattr(reasoning, name)
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
    # FROST(Ed25519) threshold signing (needs the native vouch_core_uniffi
    # library). The ceremony functions (generate_key, commit, sign_share,
    # aggregate) have names too generic to export at the top level without
    # colliding with unrelated symbols (aggregate is already reputation
    # aggregation); use vouch.threshold.generate_key(...) directly.
    elif name in (
        "ThresholdError",
        "ThresholdSigner",
        "KeyShare",
        "GroupPublicKey",
        "GenerateKeyResult",
    ):
        from . import threshold

        return getattr(threshold, name)
    raise AttributeError(f"module 'vouch' has no attribute '{name}'")


__all__ = [
    "__version__",
    # Core
    "Signer",
    "sign",
    "Verifier",
    "verify",
    "Agent",
    "Credential",
    "Passport",
    "VerificationError",
    "DelegationLink",
    "Auditor",
    # Key management
    "generate_identity",
    "KeyPair",
    "RotatingKeyProvider",
    "KeyConfig",
    # Key storage (secure by default)
    "KeyStore",
    "MemoryKeyStore",
    "EncryptedFileKeyStore",
    "KeyringKeyStore",
    "resolve_default_store",
    # Deterministic agent-tool signing
    "protect",
    "signed",
    "delegate",
    "sign_intent",
    "current_credential",
    "current_token_header",
    "resolve_signer",
    # Receiving-side verification guards
    "CredentialGate",
    "GateResult",
    "require_signed",
    "enroll_device",
    "verify_delegated_chain",
    "FleetResult",
    "DeviceRegistry",
    "split_secret",
    "combine_shares",
    "split_identity",
    "recover_identity",
    "guard_mcp",
    "guard_tools",
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
    # Proof-of-Integration recognition primitive (PAD-072)
    "ProofOfIntegrationError",
    "build_integration_challenge",
    "answer_integration_challenge",
    "verify_integration_response",
    "proof_of_integration_block",
    "CHALLENGE_TYPE",
    "RESPONSE_TYPE",
    # Liveness-conformance-decaying recognition trust (PAD-073)
    "LivenessError",
    "build_conformance_receipt",
    "verify_conformance_receipt",
    "last_conformant",
    "consumable_trust",
    "should_revoke",
    "revocation_entry",
    "CONFORMANCE_RECEIPT_TYPE",
    # Reasoned Action Proofs (justification bound to the action)
    "ReasonedActionError",
    "REASONED_ACTION_TYPE",
    "evidence_anchor",
    "build_justification",
    "justification_digest",
    "artifact_digest",
    "build_escrow_receipt",
    "verify_escrow_receipt",
    "LocalEscrow",
    "sign_reasoned_action",
    "check_reasoned_action",
    "verify_reasoned_action",
    "verify_justification",
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
    # FROST(Ed25519) threshold signing
    "ThresholdError",
    "ThresholdSigner",
    "KeyShare",
    "GroupPublicKey",
    "GenerateKeyResult",
]
