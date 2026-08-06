"""
EU AI Act evidence pack for a robot, assembled from Vouch robotics credentials.

A robot presents four signed credentials -- a hardware-rooted identity, a model
provenance attestation, a physical capability scope, and a safety record
anchored to a tamper-evident ledger -- and the conformance checker maps them
onto the EU AI Act high-risk requirements (Reg (EU) 2024/1689, Arts. 12-15).
An assessor then signs a point-in-time conformance attestation that an auditor
or notified body can verify offline.

Run it:  python examples/robotics_ai_act_evidence_pack.py
"""

import base64
import hashlib

from vouch import Signer, generate_identity
from vouch.robotics import (
    SoftwareRootOfTrust,
    build_conformance_attestation,
    build_physical_scope_credential,
    build_provenance_attestation,
    build_safety_record,
    check_conformance,
    mint_robot_identity,
    verify_conformance_attestation,
)
from vouch.robotics.safety_record import SafetyEventLog

PROFILE_ID = "eu-ai-act-high-risk"

ROBOT_CONFIG = {"temperature": 0.0, "max_torque": 12.5}


def make_party(domain: str):
    """Generate an identity for one party and wrap it in a Signer."""
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def digest(data: bytes) -> str:
    """Multibase (base64url) SHA-256, the hash form Vouch credentials carry."""
    return "u" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode(
        "ascii"
    )


def build_evidence_pack(robot, robot_did, authority):
    """
    Build the credential set the EU AI Act high-risk profile checks:

      - RobotIdentityCredential (Art. 12 traceability rests on knowing the robot)
      - ModelProvenanceAttestation (Art. 13 transparency, Art. 15 known build)
      - PhysicalCapabilityScope (Art. 14 human oversight via enforced limits)
      - RobotSafetyRecordCredential (Art. 12 automatic recording of events)
    """
    root = SoftwareRootOfTrust(kind="TPM")  # reference; a real deployment uses a TPM
    identity = mint_robot_identity(
        robot, root, make="Acme Robotics", model="AR-7", serial="SN-000123"
    )

    provenance = build_provenance_attestation(
        robot,
        robot_did=robot_did,
        model_name="Gemini Robotics ER 2",
        weights_hash=digest(b"gemini-robotics-er-2-weights"),
        safety_policy=digest(b"factory-floor-safety-policy-v3"),
        config=ROBOT_CONFIG,
        version="2.0",
    )

    scope = build_physical_scope_credential(
        robot,
        subject_did=robot_did,
        max_force_n=80.0,
        max_speed_mps=1.5,
        max_speed_near_humans_mps=0.5,
        allowed_zones=["cell-3"],
    )

    ledger = SafetyEventLog()
    ledger.append("near_miss", severity="low", details={"note": "pallet edge proximity"})
    ledger.append("manual_override", severity="info", actor="did:web:operator.example.com")
    record = build_safety_record(authority, robot_did=robot_did, summary=ledger.summarize())

    return [identity, provenance, scope, record]


def main() -> None:
    robot_kp, robot = make_party("ar7.example.com")
    assessor_kp, assessor = make_party("assessor.example.com")

    credentials = build_evidence_pack(robot, robot_kp.did, assessor)
    report = check_conformance(credentials, PROFILE_ID)

    print(f"profile: {report['profileId']}  ({report['regime']})")
    for req in report["requirements"]:
        mark = "PASS" if req["satisfied"] else "GAP "
        print(f"  [{mark}] {req['clause']}: {req['title']}")
    print(f"conforms: {report['conforms']}  ({report['satisfiedCount']}/{report['totalCount']})")

    attestation = build_conformance_attestation(assessor, robot_did=robot_kp.did, report=report)
    ok, subject = verify_conformance_attestation(attestation, assessor_kp.public_key_jwk)
    print(f"attestation verifies: {ok}  reportDigest={subject['reportDigest'][:16]}...")


if __name__ == "__main__":
    main()
