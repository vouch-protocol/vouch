#!/usr/bin/env python3
"""
Generate the robotics interop vector (Phase 5.1-5.3).

Deterministic (fixed seeds, fixed validFrom). Pins the new byte-level
computations so other languages reproduce them: the hardware-root binding inside
a RobotIdentityCredential, and the config hash inside a ModelProvenanceAttestation.

Run:  python test-vectors/robotics/generate.py
"""

import base64
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vouch import Signer
from vouch.robotics import (
    MotionCollector,
    PerceptionLog,
    SafetyEventLog,
    SoftwareRootOfTrust,
    build_action_approval,
    build_decommission,
    build_delegation_lease,
    build_key_rotation,
    build_ownership_transfer,
    build_status_list_entry,
    config_hash,
    hash_frame,
    mint_robot_identity,
)

ROBOT_SEED = bytes(range(32))
HW_SEED = bytes([7] * 32)
ROBOT_DID = "did:web:robot.example.com"
VALID_FROM = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def main():
    sk = Ed25519PrivateKey.from_private_bytes(ROBOT_SEED)
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_jwk = json.dumps({"kty": "OKP", "crv": "Ed25519", "d": b64u(ROBOT_SEED), "x": b64u(pub)})
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub)}

    signer = Signer(private_key=priv_jwk, did=ROBOT_DID)
    root = SoftwareRootOfTrust(seed=HW_SEED, kind="TPM")
    identity = mint_robot_identity(
        signer, root, make="Acme Robotics", model="AR-7", serial="SN-000123",
        owner="did:web:owner.example.com", valid_from=VALID_FROM,
        lifecycle=[{"event": "manufactured", "timestamp": "2026-01-01T00:00:00Z"}],
    )

    config = {"temperature": 0.0, "max_torque": 12.5, "guardrails": ["no_humans_zone"]}

    # Liveness: a deterministic motion digest from fixed samples against a scope.
    physical_scope = {
        "maxForceN": 80.0,
        "maxSpeedMps": 1.5,
        "maxSpeedNearHumansMps": 0.25,
        "allowedZones": ["cell-3"],
    }
    collector = MotionCollector(scope=physical_scope)
    collector.record(force_n=12.0, speed_mps=0.4, near_humans=False, zone="cell-3")
    collector.record(force_n=20.0, speed_mps=0.2, near_humans=True, zone="cell-3")
    motion_digest = collector.digest()

    # Safety record: a deterministic hash-linked ledger (fixed timestamps).
    log = SafetyEventLog()
    log.append("near_miss", severity="low", details={"zone": "cell-3"},
               timestamp="2026-01-01T00:00:00Z")
    log.append("envelope_breach", severity="high", timestamp="2026-01-01T00:01:00Z")
    safety_entries = log.entries()
    safety_summary = log.summarize()

    # Revocation: a deterministic BitstringStatusList credentialStatus entry.
    status_entry = build_status_list_entry(
        status_list_credential="https://fleet.example.com/status/1",
        status_list_index=42,
    )

    # Perception: a deterministic frame hash and a hash-linked perception log.
    sample_frame = bytes(range(64))
    plog = PerceptionLog()
    plog.record(sensor_id="cam-front", modality="camera", frame=sample_frame,
                timestamp="2026-01-01T00:00:00Z")
    plog.record(sensor_id="lidar-top", modality="lidar", frame_hash=hash_frame(b"scan-0"),
                timestamp="2026-01-01T00:00:01Z")
    perception_entries = plog.entries()

    # Lease: a Python-signed delegation lease other languages VERIFY (not
    # reproduce, since the proof carries a wall-clock created). A long window so
    # the fixture verifies at any realistic current time.
    lease = build_delegation_lease(
        signer, robot_did=ROBOT_DID, lease_id="lease-vector-1",
        scope=physical_scope, valid_seconds=10 * 365 * 24 * 60 * 60, valid_from=VALID_FROM,
    )

    # Physical quorum: two Python-signed approvals from fixed approver keys, for a
    # fixed action. Other languages verify the M-of-N reaches threshold 2.
    def signer_from_seed(seed: bytes, did: str):
        s = Ed25519PrivateKey.from_private_bytes(seed)
        p = s.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        jwk = json.dumps({"kty": "OKP", "crv": "Ed25519", "d": b64u(seed), "x": b64u(p)})
        return Signer(private_key=jwk, did=did), {"kty": "OKP", "crv": "Ed25519", "x": b64u(p)}

    approver1, approver1_pub = signer_from_seed(bytes([1] * 32), "did:web:approver-1.example.com")
    approver2, approver2_pub = signer_from_seed(bytes([2] * 32), "did:web:approver-2.example.com")
    action_id = "vector-action-1"
    approvals = [
        build_action_approval(approver1, action_id=action_id, robot_did=ROBOT_DID,
                              valid_from=VALID_FROM),
        build_action_approval(approver2, action_id=action_id, robot_did=ROBOT_DID,
                              valid_from=VALID_FROM),
    ]

    # Lifecycle: Python-signed transfer, key rotation, and decommission that other
    # languages verify. The key rotation is signed by the robot's current key
    # (robot_public_key_jwk verifies it).
    owner_a, owner_a_pub = signer_from_seed(bytes([3] * 32), "did:web:owner-a.example.com")
    authority, authority_pub = signer_from_seed(bytes([4] * 32), "did:web:authority.example.com")
    new_robot, _ = signer_from_seed(bytes([5] * 32), ROBOT_DID)
    ownership_transfer = build_ownership_transfer(
        owner_a, robot_did=ROBOT_DID, to_owner="did:web:owner-b.example.com",
        transferred_at=VALID_FROM,
    )
    key_rotation = build_key_rotation(
        signer, robot_did=ROBOT_DID, new_key_multibase=new_robot.get_public_key_multikey(),
        rotated_at=VALID_FROM,
    )
    decommission = build_decommission(
        authority, robot_did=ROBOT_DID, reason="end of service life",
        final_disposition="recycled", decommissioned_at=VALID_FROM,
    )

    doc = {
        "description": (
            "Robotics interop vector. Pins the deterministic byte-level "
            "computations so other languages reproduce them: the hardware-root "
            "binding (RobotIdentityCredential), the config hash "
            "(ModelProvenanceAttestation), the motion digest (liveness), the "
            "hash-linked safety ledger and its summary (safety_record), the "
            "credentialStatus entry (revocation), and the frame hash plus the "
            "hash-linked perception log (perception). It also includes "
            "Python-signed credentials other languages VERIFY rather than "
            "reproduce: a delegation lease, a set of physical-quorum approvals, and "
            "the lifecycle credentials (ownership transfer, key rotation, "
            "decommission). Credential proof values are not pinned because the "
            "proof carries a wall-clock created timestamp."
        ),
        "version": "1.4",
        "robot_public_key_jwk": public_jwk,
        "robot_identity_credential": identity,
        "config": config,
        "expected_config_hash": config_hash(config),
        "physical_scope": physical_scope,
        "expected_motion_digest": motion_digest,
        "safety_log_entries": safety_entries,
        "expected_safety_log_head": log.head(),
        "expected_safety_summary": safety_summary,
        "expected_credential_status_entry": status_entry,
        "expected_frame_hash": hash_frame(sample_frame),
        "perception_log_entries": perception_entries,
        "expected_perception_log_head": plog.head(),
        "delegation_lease_credential": lease,
        "quorum_action_id": action_id,
        "quorum_approvals": approvals,
        "quorum_approver_keys": {
            "did:web:approver-1.example.com": approver1_pub,
            "did:web:approver-2.example.com": approver2_pub,
        },
        "ownership_transfer_credential": ownership_transfer,
        "ownership_transfer_owner_key": owner_a_pub,
        "key_rotation_credential": key_rotation,
        "decommission_credential": decommission,
        "decommission_authority_key": authority_pub,
    }
    path = os.path.join(os.path.dirname(__file__), "vector.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
