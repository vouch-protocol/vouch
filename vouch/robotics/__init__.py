"""
Vouch robotics primitives.

Open, vendor-neutral formats and reference implementations for accountable
robots and embodied agents:

  - identity: hardware-rooted robot identity + lifecycle credential profile.
  - provenance: model-and-config provenance attestation, re-signable on OTA.
  - capability: physical capability scope (force, speed, zones, shifts).
  - handshake: robot-to-robot bounded-trust handshake across domains.
  - blackbox: encrypted append-only flight recorder + kill-switch credential.
  - passport: scannable (QR/NFC) robot passport and verifier.
  - liveness: robot heartbeat with safety-envelope conformance and trust decay.
  - revocation: whole-DID kill and surgical per-credential revocation.
  - safety_record: incident/near-miss ledger + portable safety-record credential.
  - lease: short-lived, offline-verifiable delegation lease (open cross-vendor chain).
  - physical_quorum: M-of-N approvals for high-consequence physical actions.
  - lifecycle: ownership transfer, key rotation, and decommissioning.
  - perception: signed, tamper-evident provenance for captured sensor frames.
  - conformance: machine-checkable mapping from credentials to safety regulations.
  - pq: hybrid post-quantum signing and backward-compatible verification.
  - embodiment: cross-embodiment identity continuity for an agent across bodies.
  - custody: physical custody handoff chain for a task or object across actors.
  - access: bounded, revocable robot access to physical infrastructure resources.
  - fusion: signed provenance binding a fused world model to its input frames.
  - wear: signed wear and degradation attestation with capability auto-attenuation.
"""

from .capability import (
    PhysicalAction,
    attenuates,
    build_physical_scope_credential,
    check_physical_action,
)
from .identity import (
    HardwareRootOfTrust,
    SoftwareRootOfTrust,
    lifecycle_event,
    mint_robot_identity,
    verify_robot_identity,
)
from .provenance import (
    build_provenance_attestation,
    config_hash,
    verify_provenance_attestation,
)
from .handshake import (
    BoundedSession,
    TrustPolicy,
    build_accept,
    build_confirm,
    build_hello,
    verify_accept,
    verify_confirm,
)
from .blackbox import (
    BlackBoxLog,
    build_killswitch_credential,
    open_entry,
    verify_blackbox_chain,
    verify_killswitch_credential,
)
from .passport import (
    build_passport,
    decode_passport,
    encode_passport,
    verify_passport,
)
from .liveness import (
    MotionCollector,
    MotionSample,
    build_robot_heartbeat,
    is_live,
    validate_motion_digest,
    verify_robot_heartbeat,
)
from .revocation import (
    RevocationRegistry,
    attach_credential_status,
    build_status_list_credential,
    build_status_list_entry,
    check_credential_status,
)
from .safety_record import (
    EVENT_TYPES,
    SEVERITIES,
    SafetyEventLog,
    build_safety_record,
    summarize_entries,
    validate_safety_summary,
    verify_safety_log,
    verify_safety_record,
)
from .perception import (
    MODALITIES,
    PerceptionLog,
    build_perception_attestation,
    hash_frame,
    verify_perception_attestation,
    verify_perception_log,
)
from .lease import (
    build_delegation_lease,
    lease_permits,
    verify_delegation_lease,
)
from .physical_quorum import (
    build_action_approval,
    verify_action_authorization,
)
from .lifecycle import (
    build_decommission,
    build_key_rotation,
    build_ownership_transfer,
    verify_custody_chain,
    verify_decommission,
    verify_key_history,
    verify_key_rotation,
    verify_ownership_transfer,
)
from .conformance import (
    PROFILES,
    build_conformance_attestation,
    check_conformance,
    profile,
    report_digest,
    verify_conformance_attestation,
)
from .pq import (
    HYBRID_CRYPTOSUITE,
    is_pq,
    migrate_to_pq,
    sign_pq,
    verify_pq,
    verify_robot_credential,
)
from .embodiment import (
    build_embodiment,
    check_no_fork,
    verify_continuity_chain,
    verify_embodiment,
)
from .custody import (
    build_handoff,
    holder_at,
    locate_condition_change,
    verify_handoff,
    verify_handoff_chain,
)
from .access import (
    AuthorizeResult,
    attenuates_grant,
    authorize_access,
    build_access_grant,
    build_access_request,
    verify_access_grant,
)
from .fusion import (
    FUSED_PERCEPTION_TYPE,
    build_fused_attestation,
    fusion_inputs_digest,
    hash_fused_output,
    verify_fused_attestation,
    verify_fusion_inputs,
)
from .wear import (
    WEAR_ATTESTATION_TYPE,
    attenuate_for_wear,
    build_wear_attestation,
    verify_wear_attestation,
    verify_wear_chain,
)

__all__ = [
    # identity
    "HardwareRootOfTrust",
    "SoftwareRootOfTrust",
    "mint_robot_identity",
    "verify_robot_identity",
    "lifecycle_event",
    # provenance
    "build_provenance_attestation",
    "verify_provenance_attestation",
    "config_hash",
    # capability
    "PhysicalAction",
    "build_physical_scope_credential",
    "check_physical_action",
    "attenuates",
    # handshake
    "TrustPolicy",
    "BoundedSession",
    "build_hello",
    "build_accept",
    "verify_accept",
    "build_confirm",
    "verify_confirm",
    # blackbox + kill switch
    "BlackBoxLog",
    "open_entry",
    "verify_blackbox_chain",
    "build_killswitch_credential",
    "verify_killswitch_credential",
    # passport
    "build_passport",
    "encode_passport",
    "decode_passport",
    "verify_passport",
    # liveness (robot heartbeat + conformance + trust decay)
    "MotionCollector",
    "MotionSample",
    "build_robot_heartbeat",
    "verify_robot_heartbeat",
    "validate_motion_digest",
    "is_live",
    # revocation
    "RevocationRegistry",
    "attach_credential_status",
    "check_credential_status",
    "build_status_list_credential",
    "build_status_list_entry",
    # perception provenance (signed sensor-frame provenance)
    "hash_frame",
    "PerceptionLog",
    "verify_perception_log",
    "build_perception_attestation",
    "verify_perception_attestation",
    "MODALITIES",
    # delegation lease (offline-verifiable, nesting cross-vendor chain)
    "build_delegation_lease",
    "verify_delegation_lease",
    "lease_permits",
    # physical quorum (M-of-N approvals for high-consequence actions)
    "build_action_approval",
    "verify_action_authorization",
    # lifecycle (ownership transfer, key rotation, decommissioning)
    "build_ownership_transfer",
    "verify_ownership_transfer",
    "verify_custody_chain",
    "build_key_rotation",
    "verify_key_rotation",
    "verify_key_history",
    "build_decommission",
    "verify_decommission",
    # conformance (credentials mapped to safety and AI regulations)
    "PROFILES",
    "profile",
    "check_conformance",
    "report_digest",
    "build_conformance_attestation",
    "verify_conformance_attestation",
    # post-quantum (hybrid signing + backward-compatible verification)
    "HYBRID_CRYPTOSUITE",
    "sign_pq",
    "is_pq",
    "verify_pq",
    "verify_robot_credential",
    "migrate_to_pq",
    # embodiment (cross-embodiment identity continuity + fork detection)
    "build_embodiment",
    "verify_embodiment",
    "verify_continuity_chain",
    "check_no_fork",
    # custody handoff (physical task/object across human and robot actors)
    "build_handoff",
    "verify_handoff",
    "verify_handoff_chain",
    "holder_at",
    "locate_condition_change",
    # infrastructure access (bounded, revocable robot access to physical resources)
    "AuthorizeResult",
    "build_access_grant",
    "verify_access_grant",
    "build_access_request",
    "authorize_access",
    "attenuates_grant",
    # fused-sensor provenance (fused world model bound to its input frames)
    "FUSED_PERCEPTION_TYPE",
    "hash_fused_output",
    "fusion_inputs_digest",
    "build_fused_attestation",
    "verify_fused_attestation",
    "verify_fusion_inputs",
    # wear and degradation (self-attested degradation + capability auto-attenuation)
    "WEAR_ATTESTATION_TYPE",
    "build_wear_attestation",
    "verify_wear_attestation",
    "verify_wear_chain",
    "attenuate_for_wear",
    # safety record (incident/near-miss ledger + portable record)
    "SafetyEventLog",
    "verify_safety_log",
    "summarize_entries",
    "build_safety_record",
    "verify_safety_record",
    "validate_safety_summary",
    "EVENT_TYPES",
    "SEVERITIES",
]
