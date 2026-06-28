"""
The life of an accountable robot: a tour of every Vouch robotics capability.

One robot, AR-7, is born, certified, put to work, watched, delegated to,
governed, recorded, resold, and finally retired, with each step cryptographically
accountable. The demo walks all thirteen robotics capabilities end to end. Every
step asserts an invariant and prints PASS or FAIL, and the script exits non-zero
if any invariant breaks, so it doubles as a smoke test.

Run it:  python examples/robotics_demo.py
"""

import os
import sys

from vouch import Signer, generate_identity
from vouch.robotics import (
    BlackBoxLog,
    MotionCollector,
    PerceptionLog,
    PhysicalAction,
    SafetyEventLog,
    SoftwareRootOfTrust,
    TrustPolicy,
    attach_credential_status,
    build_accept,
    build_action_approval,
    build_confirm,
    build_decommission,
    build_delegation_lease,
    build_hello,
    build_killswitch_credential,
    build_key_rotation,
    build_ownership_transfer,
    build_passport,
    build_perception_attestation,
    build_physical_scope_credential,
    build_provenance_attestation,
    build_robot_heartbeat,
    build_safety_record,
    build_status_list_credential,
    check_credential_status,
    check_physical_action,
    decode_passport,
    encode_passport,
    hash_frame,
    is_live,
    lease_permits,
    mint_robot_identity,
    verify_accept,
    verify_action_authorization,
    verify_confirm,
    verify_decommission,
    verify_delegation_lease,
    verify_key_rotation,
    verify_ownership_transfer,
    verify_passport,
    verify_perception_attestation,
    verify_provenance_attestation,
    verify_robot_identity,
    verify_safety_record,
)
from vouch.status_list import StatusList

_failures = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global _failures
    if not ok:
        _failures += 1
    tail = f"  {detail}" if detail else ""
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{tail}")


def step(n: int, title: str) -> None:
    print(f"\n{n:>2}. {title}")


def _signer(domain: str):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def main() -> None:
    print("The life of an accountable robot (AR-7)\n" + "=" * 39)
    robot_kp, robot = _signer("ar7.fleet.example.com")
    owner_kp, owner = _signer("acme-logistics.example.com")
    authority_kp, authority = _signer("safety-authority.example.com")
    robot_did = robot.get_did()

    # 1. Hardware-rooted identity
    step(1, "Birth: a hardware-rooted identity")
    root = SoftwareRootOfTrust(kind="TPM")  # reference; production uses a real TPM
    identity = mint_robot_identity(
        robot, root, make="Acme Robotics", model="AR-7", serial="SN-000123", owner=owner.get_did()
    )
    ok, subject = verify_robot_identity(identity, robot_kp.public_key_jwk)
    check("identity binds to the hardware root", ok, f"{subject['make']} {subject['model']}")

    # 2. Model and config provenance
    step(2, "Certification: what model and safety policy it runs")
    config = {"temperature": 0.0, "max_torque": 12.5, "guardrails": ["no_humans_zone"]}
    prov = build_provenance_attestation(
        robot,
        robot_did=robot_did,
        model_name="OpenVLA-7B",
        weights_hash="uWEIGHTS",
        safety_policy="uPOLICY",
        config=config,
        version="2.1.0",
    )
    ok, _ = verify_provenance_attestation(prov, robot_kp.public_key_jwk, config=config)
    check("provenance verifies and config hash reproduces", ok)
    ok_tampered, _ = verify_provenance_attestation(
        prov, robot_kp.public_key_jwk, config={**config, "max_torque": 99}
    )
    check("a different config is detected", not ok_tampered)

    # 3. Physical capability scope
    step(3, "Limits: physical capability scope")
    scope_cred = build_physical_scope_credential(
        robot,
        subject_did=robot_did,
        max_force_n=80.0,
        max_speed_mps=1.5,
        max_speed_near_humans_mps=0.25,
        allowed_zones=["cell-3"],
    )
    scope = scope_cred["credentialSubject"]["physicalScope"]
    check(
        "a gentle move near a person is allowed",
        check_physical_action(
            scope, PhysicalAction(force_n=10.0, speed_mps=0.2, near_humans=True, zone="cell-3")
        ).ok,
    )
    check(
        "speeding near a person is refused",
        not check_physical_action(
            scope, PhysicalAction(speed_mps=1.2, near_humans=True, zone="cell-3")
        ).ok,
    )

    # 4. Living-trust heartbeat
    step(4, "On the job: a living-trust heartbeat")
    good = MotionCollector(scope=scope)
    good.record(force_n=12.0, speed_mps=0.4, near_humans=False, zone="cell-3")
    hb = build_robot_heartbeat(
        robot,
        session_id="shift-1",
        interval_index=0,
        motion_digest=good.digest(),
        interval_seconds=30,
    )
    check("a fresh, in-envelope robot is live", is_live(hb))
    breached = MotionCollector(scope=scope)
    breached.record(force_n=140.0, speed_mps=0.4, zone="cell-3")  # over the force cap
    hb_bad = build_robot_heartbeat(
        robot,
        session_id="shift-1",
        interval_index=1,
        motion_digest=breached.digest(),
        interval_seconds=30,
    )
    check("a robot that breached its envelope loses trust", not is_live(hb_bad))

    # 5. Robot-to-robot handshake
    step(5, "Teamwork: a robot-to-robot trust handshake")
    peer_kp, peer = _signer("ar9.fleet.example.com")
    policy = TrustPolicy(trusted_domains={"ar7.fleet.example.com"})
    hello = build_hello(robot, proposed_scope=["lift", "carry", "scan"])
    accept = build_accept(
        peer,
        hello=hello,
        hello_public_key=robot_kp.public_key_jwk,
        policy=policy,
        offered_scope=["carry", "scan", "weld"],
    )
    ok, session = verify_accept(accept, peer_kp.public_key_jwk, expected_nonce=hello["nonce"])
    check(
        "the cooperation scope is the intersection",
        ok and session.scope == ["carry", "scan"],
        str(session.scope) if ok else "",
    )
    confirm = build_confirm(robot, session=session)
    check(
        "both robots confirm the bounded session",
        verify_confirm(
            confirm,
            robot_kp.public_key_jwk,
            session_id=session.session_id,
            expected_nonce=session.nonce,
        ),
    )

    # 6. Black box and kill switch
    step(6, "Flight recorder: an encrypted black box and a kill switch")
    box = BlackBoxLog(key=os.urandom(32))
    box.append("move", {"zone": "cell-3", "force_n": 12.0})
    box.append("pick", {"object": "tote-42"})
    from vouch.robotics import verify_blackbox_chain

    chain_ok, _ = verify_blackbox_chain(box.entries())
    check("the black-box chain is tamper-evident", chain_ok)
    kill = build_killswitch_credential(authority, target=robot_did, reason="emergency stop")
    from vouch.robotics import verify_killswitch_credential

    ok, _ = verify_killswitch_credential(
        kill, authority_kp.public_key_jwk, trusted_authorities={authority.get_did()}
    )
    check("only an attested authority can trigger the kill switch", ok)
    ok_imposter, _ = verify_killswitch_credential(
        kill, authority_kp.public_key_jwk, trusted_authorities={"did:web:not-the-authority"}
    )
    check("a stranger cannot trigger it", not ok_imposter)

    # 7. Scannable passport
    step(7, "Identity card: a scannable offline passport")
    passport = build_passport(
        robot,
        robot_did=robot_did,
        make="Acme Robotics",
        model="AR-7",
        owner=owner.get_did(),
        authorized_actions=["lift", "carry"],
        certification="ISO-10218",
    )
    uri = encode_passport(passport)
    ok, _ = verify_passport(decode_passport(uri), robot_kp.public_key_jwk)
    check("anyone can verify the passport offline", ok, uri[:24] + "...")

    # 8. Credential revocation
    step(8, "Recall: surgical credential revocation")
    list_url = "https://fleet.example.com/status/robots"
    revocable = attach_credential_status(
        dict(scope_cred), robot, status_list_credential=list_url, status_list_index=7
    )
    sl = StatusList(status_list_id=list_url)
    sl.set_status(7, True)  # the authority revokes this capability grant
    status_cred = build_status_list_credential(issuer_did=authority.get_did(), status_list=sl)
    check(
        "a revoked capability credential reads as revoked",
        check_credential_status(revocable, status_cred),
    )

    # 9. Accountable safety record
    step(9, "History: a tamper-evident safety record")
    log = SafetyEventLog()
    log.append("near_miss", severity="low", details={"zone": "cell-3"})
    log.append("envelope_breach", severity="high")
    record = build_safety_record(authority, robot_did=robot_did, summary=log.summarize())
    ok, rsub = verify_safety_record(record, authority_kp.public_key_jwk)
    check("the safety record verifies", ok, f"{rsub['totalEvents']} events" if ok else "")
    entries = log.entries()
    entries[0]["severity"] = "info"  # try to downgrade a near-miss
    from vouch.robotics import verify_safety_log

    tampered_ok, _ = verify_safety_log(entries)
    check("altering an event breaks the ledger chain", not tampered_ok)

    # 10. Perception provenance
    step(10, "Senses: provenance for what the cameras saw")
    frame = bytes(range(64))
    plog = PerceptionLog()
    entry = plog.record(sensor_id="cam-front", modality="camera", frame=frame)
    att = build_perception_attestation(
        robot,
        robot_did=robot_did,
        sensor_id="cam-front",
        modality="camera",
        frame_hash=entry["frameHash"],
        log_head=plog.head(),
    )
    ok, _ = verify_perception_attestation(att, robot_kp.public_key_jwk, frame=frame)
    check("the robot proves what its camera captured", ok)
    ok_swap, _ = verify_perception_attestation(att, robot_kp.public_key_jwk, frame=b"a fake frame")
    check("a substituted frame is detected", not ok_swap)

    # 11. Offline delegation lease
    step(11, "At the edge: an offline delegation lease")
    lease = build_delegation_lease(
        owner, robot_did=robot_did, lease_id="aisle-7", scope=scope, valid_seconds=3600
    )
    ok, lsub = verify_delegation_lease(lease, owner_kp.public_key_jwk)
    check("the robot verifies its lease with no network", ok)
    check(
        "the lease permits an in-scope action",
        lease_permits(lsub, PhysicalAction(force_n=10.0, zone="cell-3"), lease),
    )
    check(
        "the lease refuses an out-of-scope zone",
        not lease_permits(lsub, PhysicalAction(zone="cell-9"), lease),
    )

    # 12. Physical quorum
    step(12, "Two-person rule: a physical quorum for a dangerous action")
    a1_kp, a1 = _signer("supervisor-1.example.com")
    a2_kp, a2 = _signer("supervisor-2.example.com")
    keys = {a1.get_did(): a1_kp.public_key_jwk, a2.get_did(): a2_kp.public_key_jwk}
    approvals = [
        build_action_approval(a1, action_id="weld-7", robot_did=robot_did),
        build_action_approval(a2, action_id="weld-7", robot_did=robot_did),
    ]
    ok, who = verify_action_authorization(
        approvals, action_id="weld-7", robot_did=robot_did, approver_keys=keys, threshold=2
    )
    check("two of two supervisors authorize the weld", ok, f"{len(who)} approvers")
    ok_one, _ = verify_action_authorization(
        approvals[:1], action_id="weld-7", robot_did=robot_did, approver_keys=keys, threshold=2
    )
    check("one approval alone is not enough", not ok_one)

    # 13. Lifecycle: transfer, rotation, decommission
    step(13, "End of life: ownership transfer, key rotation, decommission")
    buyer = "did:web:second-owner.example.com"
    transfer = build_ownership_transfer(owner, robot_did=robot_did, to_owner=buyer)
    ok, _ = verify_ownership_transfer(transfer, owner_kp.public_key_jwk)
    check("the owner transfers the robot to a new owner", ok)
    new_key = generate_identity(domain="ar7.fleet.example.com")
    new_mb = Signer(private_key=new_key.private_key_jwk, did=robot_did).get_public_key_multikey()
    rotation = build_key_rotation(robot, robot_did=robot_did, new_key_multibase=new_mb)
    ok, _ = verify_key_rotation(rotation, robot_kp.public_key_jwk)
    check("the current key authorizes its successor", ok)
    retired = build_decommission(
        authority, robot_did=robot_did, reason="end of service life", final_disposition="recycled"
    )
    ok, _ = verify_decommission(
        retired, authority_kp.public_key_jwk, trusted_authorities={authority.get_did()}
    )
    check("an authority retires the robot at end of life", ok)

    print("\n" + "=" * 39)
    if _failures:
        print(f"{_failures} check(s) FAILED")
        sys.exit(1)
    print("All checks passed. AR-7 was accountable from birth to retirement.")


if __name__ == "__main__":
    main()
