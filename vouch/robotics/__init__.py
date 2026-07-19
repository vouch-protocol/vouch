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
  - consent: bystander-consent evidence binding a consent basis to a robot capture.
  - teleop: accountable teleoperation handoff, who or what was in control of a robot.
  - odd: operating-domain conformance, a robot attests it stayed in its certified domain.
  - swarm: multi-robot swarm membership and collective-action attribution.
  - handover: safe robot-to-human handover with an envelope attestation and receipt.
  - root_identity: bind a hardware-rooted robot to a recognized manufacturer under a pinned root.
  - halos: signed, tamper-evident safety-evidence record for an NVIDIA Halos-certified stack.
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
from .presence import (
    build_presence_attestation,
    check_presence,
    expected_doppler_hz,
    expected_range_m,
    radial_velocity_mps,
    verify_presence_attestation,
)
from .geoscope import (
    build_geoscoped_grant,
    geoscope_permits,
    region_attenuates,
    region_contains,
    verify_geoscoped_grant,
)
from .freshness import (
    build_freshness_token,
    decay_permits,
    decay_weight,
    verify_freshness_token,
)
from .dtn_revocation import (
    build_conditional_revocation,
    build_non_revocation_proof,
    build_revocation_accumulator_root,
    build_validity_root,
    build_validity_witness,
    conditional_revocation_active,
    verify_conditional_revocation,
    verify_non_revocation,
    verify_validity_witness,
)
from .accumulator import SparseMerkleTree, verify_non_revocation_proof
from .orbital import MU_EARTH, propagate_two_body, reachable_two_body
from .localization import (
    build_beam_presence,
    build_proof_of_location,
    build_range_observation,
    count_consistent,
    kinematically_reachable,
    location_confirmed,
    verify_beam_presence,
    verify_range_observation,
    within_beam,
)
from .quorum_trust import (
    accept_trust_state_update,
    build_continuity_approval,
    build_distress_attestation,
    build_key_continuity_predelegation,
    build_trust_state_update,
    is_quarantined,
    verify_distress_attestation,
    verify_key_continuity,
    verify_trust_state_update,
)
from .edge_trust import (
    autonomy_permits,
    build_autonomy_schedule,
    build_integrity_risk_attestation,
    build_time_quality_attestation,
    integrity_authority_level,
    select_envelope,
    time_quality_permits,
    verify_autonomy_schedule,
    verify_integrity_risk_attestation,
    verify_time_quality_attestation,
)
from .perception_consensus import (
    build_interaction_attestation,
    build_perception_claim,
    cross_check_perception,
    node_standing,
    verify_interaction_attestation,
    verify_perception_claim,
)
from .bundle import (
    bind_credential_to_bundle,
    build_custody_transfer,
    custody_chain_ok,
    verify_bundle_trust,
    verify_custody_transfer,
)
from .hardware import (
    ClockSource,
    DopplerSensor,
    EpochSource,
    IntegrityMonitor,
    NavigationSource,
    PointingSource,
    RangeSensor,
    SimulatedClock,
    SimulatedDopplerSensor,
    SimulatedEpochSource,
    SimulatedIntegrityMonitor,
    SimulatedNavigation,
    SimulatedPointing,
    SimulatedRangeSensor,
    TimeQuality,
    capture_beam_presence,
    capture_integrity_risk,
    capture_presence_attestation,
    capture_range_observation,
    capture_time_quality,
    check_kinematics_live,
    issue_freshness_token,
    verify_presence_live,
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
from .consent import (
    CONSENT_BASES,
    CONSENT_EVIDENCE_TYPE,
    CONSENT_TOKEN_TYPE,
    build_consent_evidence,
    build_consent_token,
    hash_capture,
    verify_consent_evidence,
    verify_consent_token,
)
from .teleop import (
    CONTROL_HANDOFF_TYPE,
    CONTROL_MODES,
    ControlContinuity,
    build_control_handoff,
    check_control_continuity,
    controller_at,
    verify_control_chain,
    verify_control_handoff,
)
from .odd import (
    ODD_CONFORMANCE_TYPE,
    OPERATING_DOMAIN_TYPE,
    ODDResult,
    build_odd_conformance,
    build_odd_credential,
    check_in_domain,
    verify_odd_conformance,
    verify_odd_credential,
)
from .swarm import (
    COLLECTIVE_ACTION_TYPE,
    SWARM_MEMBERSHIP_TYPE,
    build_collective_action,
    build_swarm_membership,
    verify_collective_action,
    verify_swarm_membership,
)
from .handover import (
    HANDOVER_ACK_TYPE,
    HUMAN_HANDOVER_TYPE,
    build_handover_ack,
    build_human_handover,
    verify_handover_ack,
    verify_human_handover,
)
from .root_identity import (
    ACTION_ISSUE_ROBOT_IDENTITY,
    RobotIdentityChainResult,
    build_robot_identity,
    verify_robot_identity_chain,
)
from .halos import (
    HALOS_EVENT_SOURCES,
    HALOS_SAFETY_EVIDENCE_TYPE,
    HalosError,
    SafetyEventRecorder,
    build_safety_evidence,
    verify_safety_evidence,
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
    # channel-geometry proof of presence (PAD-108)
    "build_presence_attestation",
    "verify_presence_attestation",
    "check_presence",
    "expected_range_m",
    "radial_velocity_mps",
    "expected_doppler_hz",
    # ephemeris-scoped delegation authority (PAD-109)
    "build_geoscoped_grant",
    "verify_geoscoped_grant",
    "geoscope_permits",
    "region_contains",
    "region_attenuates",
    # presenter freshness + graded trust decay (PAD-107, PAD-119)
    "build_freshness_token",
    "verify_freshness_token",
    "decay_weight",
    "decay_permits",
    # DTN revocation: dead-man + carried validity witness (PAD-112, PAD-120)
    "build_conditional_revocation",
    "verify_conditional_revocation",
    "conditional_revocation_active",
    "build_validity_root",
    "build_validity_witness",
    "verify_validity_witness",
    # dynamic revocation accumulator (PAD-120): sparse Merkle tree
    "SparseMerkleTree",
    "verify_non_revocation_proof",
    "build_revocation_accumulator_root",
    "build_non_revocation_proof",
    "verify_non_revocation",
    # two-body orbital propagation for kinematic plausibility (PAD-114)
    "MU_EARTH",
    "propagate_two_body",
    "reachable_two_body",
    # localization: proof-of-location, kinematic plausibility, beam presence (PAD-113/114/121)
    "build_range_observation",
    "verify_range_observation",
    "count_consistent",
    "location_confirmed",
    "build_proof_of_location",
    "kinematically_reachable",
    "within_beam",
    "build_beam_presence",
    "verify_beam_presence",
    # quorum/swarm: quarantine, quorum-of-orbits, key continuity (PAD-110/111/116)
    "build_distress_attestation",
    "verify_distress_attestation",
    "is_quarantined",
    "build_trust_state_update",
    "verify_trust_state_update",
    "accept_trust_state_update",
    "build_key_continuity_predelegation",
    "build_continuity_approval",
    "verify_key_continuity",
    # edge trust: time-quality, autonomy envelope, integrity risk (PAD-115/117/118)
    "build_time_quality_attestation",
    "verify_time_quality_attestation",
    "time_quality_permits",
    "build_autonomy_schedule",
    "verify_autonomy_schedule",
    "select_envelope",
    "autonomy_permits",
    "build_integrity_risk_attestation",
    "verify_integrity_risk_attestation",
    "integrity_authority_level",
    # perception consensus + mesh (PAD-122, PAD-123)
    "build_perception_claim",
    "verify_perception_claim",
    "cross_check_perception",
    "build_interaction_attestation",
    "verify_interaction_attestation",
    "node_standing",
    # DTN bundle custody binding (PAD-124)
    "bind_credential_to_bundle",
    "verify_bundle_trust",
    "build_custody_transfer",
    "verify_custody_transfer",
    "custody_chain_ok",
    # hardware-facing seam: sensor Protocols, simulated impls, capture adapters
    "NavigationSource",
    "RangeSensor",
    "DopplerSensor",
    "PointingSource",
    "ClockSource",
    "EpochSource",
    "IntegrityMonitor",
    "TimeQuality",
    "SimulatedNavigation",
    "SimulatedRangeSensor",
    "SimulatedDopplerSensor",
    "SimulatedPointing",
    "SimulatedClock",
    "SimulatedEpochSource",
    "SimulatedIntegrityMonitor",
    "capture_presence_attestation",
    "verify_presence_live",
    "capture_range_observation",
    "capture_beam_presence",
    "capture_time_quality",
    "capture_integrity_risk",
    "issue_freshness_token",
    "check_kinematics_live",
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
    # bystander consent (consent basis bound to a robot capture, privacy-preserving)
    "CONSENT_EVIDENCE_TYPE",
    "CONSENT_TOKEN_TYPE",
    "CONSENT_BASES",
    "hash_capture",
    "build_consent_token",
    "verify_consent_token",
    "build_consent_evidence",
    "verify_consent_evidence",
    # teleoperation handoff (who or what controlled a robot, autonomy vs human)
    "CONTROL_HANDOFF_TYPE",
    "CONTROL_MODES",
    "ControlContinuity",
    "build_control_handoff",
    "verify_control_handoff",
    "verify_control_chain",
    "controller_at",
    "check_control_continuity",
    # operating-domain conformance (robot attests it stayed in its certified ODD)
    "OPERATING_DOMAIN_TYPE",
    "ODD_CONFORMANCE_TYPE",
    "ODDResult",
    "build_odd_credential",
    "verify_odd_credential",
    "check_in_domain",
    "build_odd_conformance",
    "verify_odd_conformance",
    # swarm accountability (membership + collective-action attribution)
    "SWARM_MEMBERSHIP_TYPE",
    "COLLECTIVE_ACTION_TYPE",
    "build_swarm_membership",
    "verify_swarm_membership",
    "build_collective_action",
    "verify_collective_action",
    # human handover (robot-to-human release with envelope attestation + receipt)
    "HUMAN_HANDOVER_TYPE",
    "HANDOVER_ACK_TYPE",
    "build_human_handover",
    "verify_human_handover",
    "build_handover_ack",
    "verify_handover_ack",
    # root-of-trust robot identity (hardware-rooted robot bound to a recognized manufacturer)
    "ACTION_ISSUE_ROBOT_IDENTITY",
    "RobotIdentityChainResult",
    "build_robot_identity",
    "verify_robot_identity_chain",
    # halos safety evidence (signed tamper-evident record for a Halos-certified stack)
    "HALOS_SAFETY_EVIDENCE_TYPE",
    "HALOS_EVENT_SOURCES",
    "HalosError",
    "SafetyEventRecorder",
    "build_safety_evidence",
    "verify_safety_evidence",
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
