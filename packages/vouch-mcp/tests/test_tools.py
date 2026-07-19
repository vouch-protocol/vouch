"""Functional tests for the vouch-mcp tool surface.

``test_smoke.py`` proves the tools *register*; this proves they *work*. Each
test drives a tool function directly (the same callables the MCP transport
dispatches to) and asserts on its string verdict, so a regression in a tool's
body -- not just its signature -- is caught.

The tools are thin wrappers over the ``vouch`` library primitives, so these
tests double as a contract check that the wiring (argument shapes, error
paths, output formatting) stays correct as those primitives evolve.
"""

import asyncio
import base64
import json
import os
import tempfile

import pytest

from vouch import generate_identity
from vouch.multikey import encode_ed25519_public


@pytest.fixture()
def server_with_identity():
    """Configure a fresh identity and return the loaded MCP server module.

    Mirrors ``test_smoke.test_sign_and_verify_roundtrip``: set the env, reset
    the process-wide default signer so it re-resolves, then import the server.
    """
    kp = generate_identity("agent.example.com")
    os.environ["VOUCH_PRIVATE_KEY"] = kp.private_key_jwk
    os.environ["VOUCH_DID"] = kp.did

    from vouch.autosign import reset_default_signer

    reset_default_signer()

    from vouch.integrations.mcp import server

    return server, kp


def _multikey_for(kp):
    x = base64.urlsafe_b64decode(json.loads(kp.public_key_jwk)["x"] + "==")
    return encode_ed25519_public(x)


# --- Tier 1: key hygiene and DID inspection ---------------------------------


def test_scan_flags_a_leaked_seed(server_with_identity):
    server, _ = server_with_identity
    out = server.scan("ED25519_PRIVATE_KEY=" + "0123456789abcdef" * 4)
    assert "LEAK RISK" in out
    assert "SEED_ENV_VAR" in out


def test_scan_reports_clean_text(server_with_identity):
    server, _ = server_with_identity
    assert server.scan("just an ordinary log line, nothing secret here") == (
        "CLEAN: no leaked key material detected."
    )


def test_decode_did_reports_ed25519(server_with_identity):
    server, kp = server_with_identity
    mk = _multikey_for(kp)
    # Accept both the bare Multikey and the did:key form (with a fragment).
    for key in (mk, f"did:key:{mk}", f"did:key:{mk}#{mk}"):
        out = server.decode_did(key)
        assert "DECODED" in out
        assert "Ed25519" in out
        assert "32" in out


def test_decode_did_rejects_garbage(server_with_identity):
    server, _ = server_with_identity
    assert server.decode_did("not-a-multikey").startswith("REJECTED")


# --- Tier 2: authority, trust-over-time, transparency -----------------------


def test_delegate_issues_a_narrowed_grant(server_with_identity):
    server, _ = server_with_identity
    out = server.delegate(
        action="charge", target="api.bank", resource="invoices", valid_seconds=600
    )
    grant = json.loads(out)
    assert "VouchCredential" in grant["type"]
    assert grant["proof"]["cryptosuite"] == "eddsa-jcs-2022"


def test_check_action_allows_and_denies(server_with_identity):
    server, _ = server_with_identity
    caps = json.dumps({"filesystem": "read"})
    assert server.check_action("read_file", caps, json.dumps({"filesystem": "read"})).startswith(
        "ALLOW"
    )
    assert server.check_action("write_file", caps, json.dumps({"filesystem": "write"})).startswith(
        "DENY"
    )


def test_check_trust_passes_a_fresh_voucher(server_with_identity):
    server, _ = server_with_identity
    voucher = server.create_session("calendar", valid_seconds=3600)
    # A brand-new voucher's trust is ~1.0, comfortably above 0.5.
    assert server.check_trust(voucher, threshold=0.5).startswith("ALLOW")
    # No trust can exceed the initial 1.0, so a threshold above it must deny.
    assert server.check_trust(voucher, threshold=1.5).startswith("DENY")


def test_disclose_ai_origin_signs_a_verifiable_credential(server_with_identity):
    server, _ = server_with_identity
    out = server.disclose_ai_origin("sha256:abc123", content_ref="doc://report")
    cred = json.loads(out)
    assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"
    # The tool's own verify path should accept what it just signed.
    assert "VERIFIED" in server.verify(out, public_key=None)


# --- Tier 3: accountability -------------------------------------------------


def test_reputation_scores_from_outcomes(server_with_identity):
    server, _ = server_with_identity
    events = json.dumps(
        [
            {"outcome": "success"},
            {"outcome": "success"},
            {"outcome": "failure", "reason": "timeout"},
        ]
    )
    out = asyncio.run(server.reputation("did:web:peer.example.com", events))
    assert "REPUTATION" in out
    assert "total actions: 3" in out
    assert "66.67%" in out  # 2 of 3 succeeded


def test_reputation_rejects_non_array(server_with_identity):
    server, _ = server_with_identity
    out = asyncio.run(server.reputation("did:web:peer.example.com", '{"not":"a list"}'))
    assert out.startswith("Error")


def test_attribute_summarizes_and_blames(server_with_identity):
    server, _ = server_with_identity
    from vouch.attribution import AttributionSession
    from vouch.signer import Signer

    ai = generate_identity("ai.example.com")
    human = Signer.from_keypair(generate_identity("human.example.com"))

    workdir = tempfile.mkdtemp()
    session = AttributionSession(
        workdir,
        ai_did=ai.did,
        ai_private_key_jwk=ai.private_key_jwk,
        ai_public_key_jwk=ai.public_key_jwk,
        model="test-model",
    )
    session.record_edit("hello.py", after_content="print('ai wrote this')\n", before_content="")
    manifest = session.finalize(files={"hello.py": "print('ai wrote this')\n"}, human_signer=human)
    manifest_json = json.dumps(manifest)

    summary = server.attribute(manifest_json)
    assert "SUMMARY" in summary
    assert "aiPercent" in summary

    blame = server.attribute(manifest_json, path="hello.py")
    assert "BLAME hello.py" in blame
    assert "ai-assistant" in blame
