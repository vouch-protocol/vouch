"""
Robotics primitives demo (Phase 5.1-5.3).

Run it:  python examples/robotics_demo.py
"""

from vouch import Signer, generate_identity
from vouch.robotics import (
    PhysicalAction,
    SoftwareRootOfTrust,
    build_physical_scope_credential,
    build_provenance_attestation,
    check_physical_action,
    mint_robot_identity,
    verify_provenance_attestation,
    verify_robot_identity,
)


def main() -> None:
    kp = generate_identity(domain="robot.example.com")
    robot = Signer(private_key=kp.private_key_jwk, did=kp.did)

    # 5.1 hardware-rooted identity
    root = SoftwareRootOfTrust(kind="TPM")  # reference; real deployment uses a TPM
    identity = mint_robot_identity(
        robot, root, make="Acme Robotics", model="AR-7", serial="SN-000123"
    )
    ok, subject = verify_robot_identity(identity, kp.public_key_jwk)
    print(
        f"identity verifies: {ok}  {subject['make']} {subject['model']} (root={subject['hardwareRoot']['kind']})"
    )

    # 5.2 model + config provenance
    config = {"temperature": 0.0, "max_torque": 12.5}
    prov = build_provenance_attestation(
        robot,
        robot_did=kp.did,
        model_name="OpenVLA-7B",
        weights_hash="uWEIGHTSHASH",
        safety_policy="uPOLICYHASH",
        config=config,
        version="2.1.0",
    )
    ok, psub = verify_provenance_attestation(prov, kp.public_key_jwk, config=config)
    print(
        f"provenance verifies: {ok}  model={psub['vla']['modelName']} configHash={psub['vla']['configHash'][:12]}..."
    )

    # 5.3 physical capability scope
    cred = build_physical_scope_credential(
        robot,
        subject_did=kp.did,
        max_force_n=100,
        max_speed_mps=2.0,
        max_speed_near_humans_mps=0.5,
        allowed_zones=["zone-A"],
    )
    scope = cred["credentialSubject"]["physicalScope"]
    safe = check_physical_action(
        scope, PhysicalAction(force_n=50, speed_mps=0.4, near_humans=True, zone="zone-A")
    )
    unsafe = check_physical_action(scope, PhysicalAction(speed_mps=1.5, near_humans=True))
    print(f"slow near a human: ok={safe.ok}")
    print(f"fast near a human: ok={unsafe.ok}  reasons={unsafe.reasons}")


if __name__ == "__main__":
    main()
