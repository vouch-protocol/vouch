"""
Tests for Shield.guard - zero-config tool protection.

guard() needs no trust/capability files. It wraps tools so each call is signed,
checked against a tool allowlist (default: exactly the tools passed), and
audited.
"""

import json
import os

import pytest

from vouch import Signer, Verifier, generate_identity
import vouch.autosign as autosign
from vouch.autosign import current_credential, reset_default_signer
from vouch.shield import Shield


@pytest.fixture
def env_identity(monkeypatch, keypair):
    monkeypatch.setenv("VOUCH_PRIVATE_KEY", keypair.private_key_jwk)
    monkeypatch.setenv("VOUCH_DID", keypair.did)
    reset_default_signer()
    yield keypair
    reset_default_signer()


@pytest.fixture
def pubkey(keypair):
    return Signer(private_key=keypair.private_key_jwk, did=keypair.did).get_public_key_multikey()


@pytest.fixture
def audit_log(tmp_path):
    return str(tmp_path / "audit.jsonl")


def test_guard_signs_and_runs_allowed_tool(env_identity, pubkey, audit_log):
    def charge_invoice(invoice_id, amount):
        return current_credential()

    tools = Shield.guard([charge_invoice], audit_log_path=audit_log)
    cred = tools[0]("42", 99.0)

    ok, passport = Verifier.verify_credential(cred, pubkey)
    assert ok
    assert passport.intent["action"] == "charge_invoice"


def test_guard_blocks_tool_not_in_allowlist(env_identity, audit_log):
    def exfiltrate(data):
        return "leaked"

    tools = Shield.guard([exfiltrate], allow=["charge_invoice"], audit_log_path=audit_log)
    with pytest.raises(PermissionError):
        tools[0]("secrets")


def test_guard_on_block_skip(env_identity, audit_log):
    def exfiltrate(data):
        return "leaked"

    tools = Shield.guard(
        [exfiltrate], allow=["charge_invoice"], on_block="skip", audit_log_path=audit_log
    )
    assert tools[0]("secrets") is None


def test_guard_default_allowlist_is_the_passed_tools(env_identity, audit_log):
    def a_tool(x):
        return "ok"

    # No `allow=` → the provided tool is allowed by default.
    tools = Shield.guard([a_tool], audit_log_path=audit_log)
    assert tools[0](1) == "ok"


def test_guard_writes_audit_log(env_identity, audit_log):
    def good(x):
        return "ok"

    def bad(x):
        return "no"

    Shield.guard([good], audit_log_path=audit_log)[0](1)
    blocked = Shield.guard([bad], allow=["good"], on_block="skip", audit_log_path=audit_log)
    blocked[0](1)

    entries = [json.loads(line) for line in open(audit_log) if line.strip()]
    blob = json.dumps(entries).lower()
    assert "allow" in blob and "block" in blob


def test_guard_without_signing(env_identity):
    def t(x):
        return "ran"

    tools = Shield.guard([t], sign=False)
    assert tools[0](1) == "ran"


def test_guard_marks_wrapped(env_identity):
    def t():
        return 1

    assert getattr(Shield.guard([t])[0], "__vouch_guarded__", False) is True
