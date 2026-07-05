"""Smoke tests for the vouch-langchain package."""

import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto.common import base64url_decode

from vouch import Verifier, generate_identity


def test_package_exports():
    import vouch_langchain

    assert vouch_langchain.VouchSignerTool is not None
    assert vouch_langchain.VouchSignerInput is not None


def test_tool_issues_verifying_credential():
    kp = generate_identity()
    os.environ["VOUCH_PRIVATE_KEY"] = kp.private_key_jwk
    os.environ["VOUCH_DID"] = "did:web:agent.example.com"

    from vouch_langchain import VouchSignerTool

    out = VouchSignerTool()._run("read", "https://api.example.com", "customer:123")
    cred = json.loads(out)
    assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"

    pub = Ed25519PublicKey.from_public_bytes(base64url_decode(json.loads(kp.public_key_jwk)["x"]))
    ok, _ = Verifier.verify_credential(cred, public_key=pub)
    assert ok is True
