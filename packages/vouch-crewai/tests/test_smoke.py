"""Smoke tests for the vouch-crewai package.

The signing path is verified through the shared helper so the test is robust
whether or not CrewAI is installed (CrewAI wraps sign_request in a tool object).
"""

import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto.common import base64url_decode

from vouch import Verifier, generate_identity
from vouch.integrations._common import load_signer, sign_tool_call_json


def test_package_exports():
    import vouch_crewai

    assert vouch_crewai.sign_request is not None
    assert vouch_crewai.VouchCrewTools is not None


def test_signing_path_verifies():
    kp = generate_identity()
    os.environ["VOUCH_PRIVATE_KEY"] = kp.private_key_jwk
    os.environ["VOUCH_DID"] = "did:web:agent.example.com"

    out = sign_tool_call_json(load_signer(), "read", "https://api.example.com", "customer:123")
    cred = json.loads(out)
    assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"

    pub = Ed25519PublicKey.from_public_bytes(base64url_decode(json.loads(kp.public_key_jwk)["x"]))
    ok, _ = Verifier.verify_credential(cred, public_key=pub)
    assert ok is True
