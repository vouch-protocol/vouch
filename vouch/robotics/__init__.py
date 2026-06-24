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
  - perception: signed, tamper-evident provenance for captured sensor frames.
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
