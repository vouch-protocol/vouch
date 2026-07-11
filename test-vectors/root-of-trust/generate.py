"""
Deterministic generator for the Root of Trust interop test vector.

Produces the three authority-layer credential types (VouchRootOfTrust,
RecognizedIssuerCredential, AgentIdentityCredential) from fixed Ed25519 seeds
and fixed timestamps, so every language SDK can reproduce byte-identical
proofValues and verify the same chain.

Run:  python test-vectors/root-of-trust/generate.py   # rewrites vector.json
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vouch import multikey
from vouch.signer import Signer
from vouch.root_of_trust import (
    ACTION_ISSUE_AGENT_IDENTITY,
    ACTION_ISSUE_ROBOT_IDENTITY,
    build_agent_identity,
    build_recognized_issuer,
    build_root_of_trust,
)
from vouch.robotics import SoftwareRootOfTrust, build_robot_identity, mint_robot_identity

# Fixed 32-byte Ed25519 seeds (test material only, never for production).
ROOT_SEED = bytes([1]) * 32
ISSUER_SEED = bytes([2]) * 32
AGENT_SEED = bytes([3]) * 32
MANUFACTURER_SEED = bytes([4]) * 32
ROBOT_SEED = bytes([5]) * 32
HW_ROOT_SEED = bytes([6]) * 32

# Fixed issuance time and a very long validity so the vector never expires.
FIXED_TIME = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
CENTURY_SECONDS = 100 * 365 * 24 * 3600

ROOT_ID = "urn:uuid:11111111-1111-1111-1111-111111111111"
RECOGNITION_ID = "urn:uuid:22222222-2222-2222-2222-222222222222"
IDENTITY_ID = "urn:uuid:33333333-3333-3333-3333-333333333333"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _signer_from_seed(seed: bytes) -> Signer:
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk = json.dumps({"kty": "OKP", "crv": "Ed25519", "d": _b64url(seed), "x": _b64url(pub)})
    did = "did:key:" + multikey.encode_ed25519_public(pub)
    return Signer(jwk, did)


def build_vectors() -> dict:
    """Build the full vector object deterministically."""
    root = _signer_from_seed(ROOT_SEED)
    issuer = _signer_from_seed(ISSUER_SEED)
    agent = _signer_from_seed(AGENT_SEED)

    root_cred = build_root_of_trust(
        root,
        name="Vouch Machine Identity Root",
        valid_seconds=CENTURY_SECONDS,
        valid_from=FIXED_TIME,
        created=FIXED_TIME,
        credential_id=ROOT_ID,
    )
    recognition = build_recognized_issuer(
        root,
        issuer_did=issuer.did,
        recognized_actions=[ACTION_ISSUE_AGENT_IDENTITY],
        valid_seconds=CENTURY_SECONDS,
        valid_from=FIXED_TIME,
        created=FIXED_TIME,
        credential_id=RECOGNITION_ID,
    )
    identity = build_agent_identity(
        issuer,
        subject_did=agent.did,
        attributes={"owner": "Acme", "model": "gpt-x", "capabilityClass": "shopping"},
        valid_seconds=CENTURY_SECONDS,
        valid_from=FIXED_TIME,
        created=FIXED_TIME,
        credential_id=IDENTITY_ID,
    )

    # Robot identity: a recognized manufacturer binds a hardware-rooted robot,
    # anchored to the same pinned root. Deterministic proofs from fixed seeds.
    manufacturer = _signer_from_seed(MANUFACTURER_SEED)
    robot = _signer_from_seed(ROBOT_SEED)
    robot_recognition = build_recognized_issuer(
        root,
        issuer_did=manufacturer.did,
        recognized_actions=[ACTION_ISSUE_ROBOT_IDENTITY],
        valid_seconds=CENTURY_SECONDS,
        valid_from=FIXED_TIME,
        created=FIXED_TIME,
        credential_id="urn:uuid:44444444-4444-4444-4444-444444444444",
    )
    hw_root = SoftwareRootOfTrust(seed=HW_ROOT_SEED, kind="TPM")
    robot_hardware_credential = mint_robot_identity(
        robot,
        hw_root,
        make="Acme Robotics",
        model="AR-7",
        serial="SN-000123",
        valid_seconds=CENTURY_SECONDS,
        valid_from=FIXED_TIME,
        created=FIXED_TIME,
    )
    robot_key_mb = robot.get_public_key_multikey()
    robot_authority_identity = build_robot_identity(
        manufacturer,
        robot_did=robot.did,
        hardware_key_multibase=robot_key_mb,
        attributes={"make": "Acme Robotics", "model": "AR-7", "serial": "SN-000123"},
        valid_seconds=CENTURY_SECONDS,
        valid_from=FIXED_TIME,
        created=FIXED_TIME,
        credential_id="urn:uuid:55555555-5555-5555-5555-555555555555",
    )
    robot_pub_raw = Ed25519PrivateKey.from_private_bytes(ROBOT_SEED).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    robot_public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(robot_pub_raw)}

    return {
        "description": (
            "Vouch Protocol Root of Trust interop vector. Built from fixed Ed25519 "
            "seeds and a fixed timestamp. Every SDK must reproduce identical "
            "proofValues and verify the chain (agent identity anchored to the root). "
            "It also includes a robot-identity binding: a recognized manufacturer "
            "issues an authority robot identity for a hardware-rooted robot, anchored "
            "to the same root, which every SDK verifies with verifyRobotIdentityChain "
            "confirming both recognized-manufacturer provenance and hardware-rooting."
        ),
        "trustedRoot": root.did,
        "seeds": {
            "root": "0x01 x32",
            "issuer": "0x02 x32",
            "agent": "0x03 x32",
            "manufacturer": "0x04 x32",
            "robot": "0x05 x32",
            "hardwareRoot": "0x06 x32",
        },
        "rootOfTrust": root_cred,
        "recognizedIssuer": recognition,
        "agentIdentity": identity,
        "robotRecognizedIssuer": robot_recognition,
        "robotHardwareCredential": robot_hardware_credential,
        "robotAuthorityIdentity": robot_authority_identity,
        "robotPublicKey": robot_public_jwk,
        "expected": {
            "verifyIdentityChain": True,
            "agentDid": agent.did,
            "issuerDid": issuer.did,
            "verifyRobotIdentityChain": True,
            "robotDid": robot.did,
            "robotIssuerDid": manufacturer.did,
            "hardwareRooted": True,
        },
    }


if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(__file__), "vector.json")
    with open(out_path, "w") as handle:
        json.dump(build_vectors(), handle, indent=2)
        handle.write("\n")
    print(f"wrote {out_path}")
