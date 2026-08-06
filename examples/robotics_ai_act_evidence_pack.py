"""
Regulatory evidence pack for a robot, assembled from Vouch robotics credentials.

A robot presents signed credentials -- a hardware-rooted identity, a model
provenance attestation, a physical capability scope, a safety record anchored
to a tamper-evident ledger, a heartbeat carrying a motion digest, and
perception provenance for its sensor frames -- and the conformance checker
maps them onto all five built-in regulatory profiles:

  - eu-ai-act-high-risk   EU AI Act high-risk systems (Reg (EU) 2024/1689)
  - iso-10218             ISO 10218-1/-2 industrial robots
  - iso-ts-15066          ISO/TS 15066 collaborative robots
  - eu-machinery-2023-1230  EU Machinery Regulation 2023/1230
  - ul-3300               UL 3300 service and mobile robots

The checker first reports the gaps a partial credential set leaves open, then
the full evidence pack closes them, and an assessor signs one point-in-time
conformance attestation per profile that an auditor or notified body can
verify offline.

Run it:  python examples/robotics_ai_act_evidence_pack.py
"""

import base64
import hashlib

from vouch import Signer, generate_identity
from vouch.robotics import (
    PROFILES,
    MotionCollector,
    PerceptionLog,
    SafetyEventLog,
    SoftwareRootOfTrust,
    build_conformance_attestation,
    build_perception_attestation,
    build_physical_scope_credential,
    build_provenance_attestation,
    build_robot_heartbeat,
    build_safety_record,
    check_conformance,
    hash_frame,
    mint_robot_identity,
    verify_conformance_attestation,
)

ALL_PROFILE_IDS = [
    "eu-ai-act-high-risk",
    "iso-10218",
    "iso-ts-15066",
    "eu-machinery-2023-1230",
    "ul-3300",
]

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


def build_base_credentials(robot, robot_did, authority):
    """
    Build the four base credentials: identity, model provenance, physical
    scope, and a safety record over a tamper-evident ledger. These satisfy
    eu-ai-act-high-risk, iso-10218, and eu-machinery-2023-1230, but leave
    gaps in iso-ts-15066 (no motion monitoring) and ul-3300 (no perception
    integrity).
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


def build_monitoring_credentials(robot, robot_did, scope_credential):
    """
    Build the two credentials that close the remaining gaps:

      - a RobotHeartbeatCredential whose motion digest proves the last
        interval stayed inside the physical envelope (ISO/TS 15066 continuous
        monitoring), collected with a MotionCollector against the scope;
      - a PerceptionProvenanceCredential binding a captured camera frame to
        the robot's key over a hash-linked perception log (UL 3300 sensing
        integrity).
    """
    scope = scope_credential["credentialSubject"]["physicalScope"]
    collector = MotionCollector(scope=scope)
    collector.record(force_n=12.0, speed_mps=0.4, near_humans=True, zone="cell-3")
    collector.record(force_n=25.0, speed_mps=1.1, near_humans=False, zone="cell-3")
    heartbeat = build_robot_heartbeat(
        robot,
        session_id="shift-A",
        interval_index=0,
        motion_digest=collector.digest(),
        interval_seconds=30,
    )

    frame = b"\x89frame-bytes-from-the-front-camera"
    log = PerceptionLog()
    log.record(sensor_id="cam-front", modality="camera", frame=frame)
    perception = build_perception_attestation(
        robot,
        robot_did=robot_did,
        sensor_id="cam-front",
        modality="camera",
        frame_hash=hash_frame(frame),
        log_head=log.head(),
    )

    return [heartbeat, perception]


def build_evidence_pack(robot, robot_did, authority):
    """Build the full six-credential evidence pack covering all five profiles."""
    base = build_base_credentials(robot, robot_did, authority)
    scope_credential = base[2]
    return base + build_monitoring_credentials(robot, robot_did, scope_credential)


def check_all_profiles(credentials):
    """Run the conformance checker over every built-in profile."""
    return {pid: check_conformance(credentials, pid) for pid in ALL_PROFILE_IDS}


def sign_attestations(assessor, robot_did, reports):
    """Sign one point-in-time conformance attestation per profile report."""
    return {
        pid: build_conformance_attestation(assessor, robot_did=robot_did, report=report)
        for pid, report in reports.items()
    }


def print_summary(reports):
    for pid, report in reports.items():
        verdict = "CONFORMS" if report["conforms"] else "GAPS"
        print(
            f"  {pid:24s} {verdict:8s} "
            f"({report['satisfiedCount']}/{report['totalCount']})  {report['regime']}"
        )
        for req in report["requirements"]:
            if not req["satisfied"]:
                print(f"    gap: {req['clause']}: {req['title']}")


def main() -> None:
    robot_kp, robot = make_party("ar7.example.com")
    assessor_kp, assessor = make_party("assessor.example.com")

    # The base credential set leaves gaps in two of the five profiles.
    base = build_base_credentials(robot, robot_kp.did, assessor)
    print("base credential set (identity, provenance, scope, safety record):")
    print_summary(check_all_profiles(base))

    # The heartbeat and perception credentials close them.
    credentials = base + build_monitoring_credentials(robot, robot_kp.did, base[2])
    print(f"\nfull evidence pack ({len(credentials)} credentials):")
    reports = check_all_profiles(credentials)
    print_summary(reports)

    # One signed, offline-verifiable conformance attestation per profile.
    print(f"\nsigned attestations ({len(PROFILES)} profiles):")
    attestations = sign_attestations(assessor, robot_kp.did, reports)
    for pid, attestation in attestations.items():
        ok, subject = verify_conformance_attestation(attestation, assessor_kp.public_key_jwk)
        print(f"  {pid:24s} verifies={ok}  reportDigest={subject['reportDigest'][:16]}...")


if __name__ == "__main__":
    main()
