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
    SoftwareRootOfTrust,
    config_hash,
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

    doc = {
        "description": (
            "Robotics interop vector (Phase 5.1-5.3). Pins the hardware-root "
            "binding inside a RobotIdentityCredential and the config hash used by "
            "ModelProvenanceAttestation. Both compose the shared JCS + SHA-256 + "
            "multibase primitives."
        ),
        "version": "1.0",
        "robot_public_key_jwk": public_jwk,
        "robot_identity_credential": identity,
        "config": config,
        "expected_config_hash": config_hash(config),
    }
    path = os.path.join(os.path.dirname(__file__), "vector.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
