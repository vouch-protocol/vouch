"""Smoke tests for the vouch-mcp package.

These prove the package imports, the server object is the official SDK's
high-level server type with the expected tools registered, and the server's
signing path produces a credential that verifies. They pass against both
mcp 1.x (FastMCP) and mcp 2.x (MCPServer, the 2026-07-28 protocol revision).
"""

import asyncio
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto.common import base64url_decode

from vouch import Verifier, generate_identity


def test_package_exports():
    import vouch_mcp

    assert callable(vouch_mcp.main)
    # mcp 1.x names the high-level server class FastMCP; mcp 2.x (the
    # 2026-07-28 protocol revision) renamed it MCPServer.
    assert type(vouch_mcp.mcp).__name__ in ("FastMCP", "MCPServer")


def test_registered_tool_names():
    import vouch_mcp

    tools = asyncio.run(vouch_mcp.mcp.list_tools())
    names = {t.name for t in tools}
    assert {
        "sign",
        "verify",
        "create_session",
        "check_revocation",
        "get_identity",
        "evaluate_freshness",
        "verify_disconnected_edge",
    } <= names


def test_sign_and_verify_roundtrip():
    kp = generate_identity("agent.example.com")
    os.environ["VOUCH_PRIVATE_KEY"] = kp.private_key_jwk
    os.environ["VOUCH_DID"] = kp.did

    from vouch.autosign import reset_default_signer

    reset_default_signer()

    from vouch.integrations.mcp import server

    out = server.sign("read", "https://api.example.com", "customer:123")
    cred = json.loads(out)
    assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"

    pub = Ed25519PublicKey.from_public_bytes(base64url_decode(json.loads(kp.public_key_jwk)["x"]))
    ok, _ = Verifier.verify(cred, public_key=pub)
    assert ok is True

    verdict = server.verify(out, public_key=None)
    assert "VERIFIED" in verdict or "REJECTED" in verdict
