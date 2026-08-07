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
        "scan",
        "decode_did",
        "delegate",
        "check_action",
        "check_trust",
        "disclose_ai_origin",
        "create_authority_state",
        "verify_authority_state",
        "check_authority_freshness",
        "reputation",
        "attribute",
        "robot_check_action",
        "robot_check_conformance",
        "robot_verify_conformance_attestation",
        "robot_verify_credential",
    } <= names


def _configure(kp):
    os.environ["VOUCH_PRIVATE_KEY"] = kp.private_key_jwk
    os.environ["VOUCH_DID"] = kp.did
    from vouch.autosign import reset_default_signer

    reset_default_signer()
    from vouch.integrations.mcp import server

    return server


def test_sign_and_verify_roundtrip_offline_key():
    # did:web cannot be resolved offline in a test, so supply the issuer key
    # directly (the offline verification path).
    kp = generate_identity("agent.example.com")
    server = _configure(kp)

    out = server.sign("read", "https://api.example.com", "customer:123")
    cred = json.loads(out)
    assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"

    pub = Ed25519PublicKey.from_public_bytes(base64url_decode(json.loads(kp.public_key_jwk)["x"]))
    ok, _ = Verifier.verify(cred, public_key=pub)
    assert ok is True

    # The verify tool accepts the genuine credential when given the key...
    assert "VERIFIED" in server.verify(out, public_key=kp.public_key_jwk)
    # ...and rejects a tampered one.
    bad = json.loads(out)
    bad["proof"]["proofValue"] = "z" + ("2" * (len(bad["proof"]["proofValue"]) - 1))
    assert "REJECTED" in server.verify(json.dumps(bad), public_key=kp.public_key_jwk)


def test_verify_resolves_did_key_and_rejects_forgery():
    # did:key is self-certifying (the key is in the DID), so the no-key path
    # resolves it offline. This is the regression guard for the fail-open bug:
    # a forged or tampered credential must be REJECTED, not VERIFIED.
    from vouch.root_of_trust import generate_did_key_identity

    kp = generate_did_key_identity()
    assert kp.did.startswith("did:key:")
    server = _configure(kp)

    out = server.sign("read", "https://api.example.com", "customer:123")

    # Genuine credential, no key passed -> resolver fetches it from the DID.
    assert "VERIFIED" in server.verify(out)

    # Corrupted signature, no key passed -> must be rejected.
    bad_sig = json.loads(out)
    bad_sig["proof"]["proofValue"] = "z" + ("2" * (len(bad_sig["proof"]["proofValue"]) - 1))
    assert "REJECTED" in server.verify(json.dumps(bad_sig))

    # Tampered intent, no key passed -> must be rejected.
    bad_intent = json.loads(out)
    bad_intent["credentialSubject"]["intent"]["action"] = "delete"
    assert "REJECTED" in server.verify(json.dumps(bad_intent))


def test_verify_fails_closed_when_key_unresolvable():
    # A did:web that cannot be resolved must yield REJECTED on the no-key path,
    # never VERIFIED on structural checks alone.
    kp = generate_identity("unresolvable.example.invalid")
    server = _configure(kp)

    out = server.sign("read", "https://api.example.com", "customer:123")
    assert "REJECTED" in server.verify(out)
