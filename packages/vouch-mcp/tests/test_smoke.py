"""Smoke tests for the vouch-mcp package.

These prove the package imports, the server object is the official FastMCP
type with the expected tools registered, and the signing path the server uses
produces a credential that verifies.
"""

import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto.common import base64url_decode

from vouch import Verifier, generate_identity
from vouch.integrations._common import sign_tool_call_json


def test_package_exports():
    import vouch_mcp

    assert callable(vouch_mcp.main)
    assert type(vouch_mcp.mcp).__name__ == "FastMCP"


def test_registered_tool_names():
    import asyncio

    import vouch_mcp

    tools = asyncio.run(vouch_mcp.mcp.list_tools())
    names = {t.name for t in tools}
    assert {"sign_action", "create_session", "get_identity"} <= names


def test_signing_path_verifies():
    kp = generate_identity()
    os.environ["VOUCH_PRIVATE_KEY"] = kp.private_key_jwk
    os.environ["VOUCH_DID"] = "did:web:agent.example.com"

    from vouch.integrations._common import load_signer

    out = sign_tool_call_json(load_signer(), "read", "https://api.example.com", "customer:123")
    cred = json.loads(out)
    assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"

    pub = Ed25519PublicKey.from_public_bytes(base64url_decode(json.loads(kp.public_key_jwk)["x"]))
    ok, _ = Verifier.verify_credential(cred, public_key=pub)
    assert ok is True
