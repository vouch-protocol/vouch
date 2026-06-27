"""
Tests for the deterministic agent-tool signing layer (vouch.autosign) and the
framework integration adapters that re-export it.

The point of this layer: a tool call is signed in Python *before* it runs, with
no dependence on the model choosing to call a signing tool. These tests pin that
behaviour — every protected call produces a verifiable credential, the wrapped
function still runs and returns normally, and signing never blocks the call.
"""

import pytest

from vouch import Signer, Verifier, generate_identity
import vouch.autosign as autosign
from vouch.autosign import (
    current_credential,
    protect,
    reset_default_signer,
    sign_intent,
    signed,
)


@pytest.fixture
def env_identity(monkeypatch, keypair):
    """Provision an identity via env vars and reset the cached signer."""
    monkeypatch.setenv("VOUCH_PRIVATE_KEY", keypair.private_key_jwk)
    monkeypatch.setenv("VOUCH_DID", keypair.did)
    reset_default_signer()
    yield keypair
    reset_default_signer()


@pytest.fixture
def pubkey(keypair):
    return Signer(
        private_key=keypair.private_key_jwk, did=keypair.did
    ).get_public_key_multikey()


def _verify(cred, pubkey):
    ok, passport = Verifier.verify_credential(cred, pubkey)
    return ok, passport


class TestSignIntent:
    def test_signs_verifiable_credential(self, env_identity, pubkey):
        cred = sign_intent("charge", target="api.bank.example.com", resource="inv/42")
        ok, passport = _verify(cred, pubkey)
        assert ok
        assert passport.intent["action"] == "charge"
        assert passport.intent["target"] == "api.bank.example.com"
        assert passport.intent["resource"] == "inv/42"

    def test_defaults_required_fields(self, env_identity, pubkey):
        # action alone is enough; target/resource get safe defaults.
        cred = sign_intent("ping")
        ok, passport = _verify(cred, pubkey)
        assert ok
        assert passport.intent["target"] == "unspecified"
        assert passport.intent["resource"] == "unspecified"

    def test_publishes_current_credential(self, env_identity):
        cred = sign_intent("act", target="t", resource="r")
        assert current_credential() == cred

    def test_no_identity_returns_none(self, monkeypatch):
        monkeypatch.delenv("VOUCH_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("VOUCH_DID", raising=False)
        monkeypatch.delenv("VOUCH_AUTO_IDENTITY", raising=False)
        # Point the keystore at an empty dir so no on-disk identity is found.
        monkeypatch.setattr(autosign.KeyManager, "list_identities", lambda self: [])
        reset_default_signer()
        assert sign_intent("act") is None
        reset_default_signer()


class TestSignedDecorator:
    def test_bare_decorator_signs_and_runs(self, env_identity, pubkey):
        ran = {}

        @signed
        def charge_invoice(invoice_id, amount, target=None):
            ran["args"] = (invoice_id, amount)
            return "ok"

        result = charge_invoice("42", 99.0, target="api.bank.example.com")
        assert result == "ok"  # underlying function still runs and returns
        assert ran["args"] == ("42", 99.0)

        ok, passport = _verify(current_credential(), pubkey)
        assert ok
        assert passport.intent["action"] == "charge_invoice"  # from fn name
        assert passport.intent["target"] == "api.bank.example.com"  # from kwarg

    def test_decorator_with_explicit_intent(self, env_identity, pubkey):
        @signed(action="pay", target="bank.example.com", resource="acct/1")
        def do_pay(amount):
            return amount

        assert do_pay(10) == 10
        ok, passport = _verify(current_credential(), pubkey)
        assert ok
        assert passport.intent["action"] == "pay"
        assert passport.intent["target"] == "bank.example.com"

    def test_injects_credential_when_declared(self, env_identity):
        seen = {}

        @signed
        def tool_with_cred(x, vouch_credential=None):
            seen["cred"] = vouch_credential
            return x

        tool_with_cred(1)
        assert isinstance(seen["cred"], dict)
        assert seen["cred"] == current_credential()

    def test_signing_failure_does_not_block_call(self, env_identity, monkeypatch):
        # Force signing to blow up; the wrapped call must still succeed.
        monkeypatch.setattr(
            autosign, "sign_intent", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        )

        @signed
        def still_runs():
            return "fine"

        assert still_runs() == "fine"

    def test_marks_wrapped(self, env_identity):
        @signed
        def f():
            return 1

        assert getattr(f, "__vouch_signed__", False) is True


class TestProtect:
    def test_wraps_plain_callables(self, env_identity, pubkey):
        def send_email(to, body):
            return current_credential()

        def search_db(query):
            return current_credential()

        wrapped = protect([send_email, search_db])
        c1 = wrapped[0]("x@y.com", "hi")
        c2 = wrapped[1](query="select 1")
        assert _verify(c1, pubkey)[0]
        assert _verify(c2, pubkey)[0]

    def test_idempotent(self, env_identity):
        def f():
            return 1

        once = protect([f])
        twice = protect(once)
        assert twice[0] is once[0]  # already-signed tools are not re-wrapped


class TestCrewAIAdapter:
    """The CrewAI adapter must also wrap tool *objects* (which hold a .func)."""

    def test_wraps_tool_object_in_place(self, env_identity, pubkey):
        from vouch.integrations.crewai import protect as crew_protect

        captured = {}

        class FakeCrewTool:  # mimics a CrewAI structured tool
            def __init__(self, fn):
                self.func = fn
                self.name = "Charge"

        def charge(invoice_id, amount, target=None):
            captured["cred"] = current_credential()
            return "charged"

        ct = FakeCrewTool(charge)
        out = crew_protect([ct])

        assert out[0] is ct  # same object, list shape preserved
        assert ct.func("42", 99.0, target="bank.example.com") == "charged"
        ok, passport = _verify(captured["cred"], pubkey)
        assert ok
        assert passport.intent["target"] == "bank.example.com"

    def test_namespace_exports(self):
        import vouch.integrations.crewai as vc

        for name in ("protect", "signed", "sign_intent", "current_credential", "autosign"):
            assert hasattr(vc, name), name


@pytest.mark.parametrize(
    "module",
    [
        "vouch.integrations.crewai",
        "vouch.integrations.langchain",
        "vouch.integrations.autogen",
        "vouch.integrations.autogpt",
        "vouch.integrations.vertex_ai",
        "vouch.integrations.google",
    ],
)
def test_every_integration_exposes_deterministic_signers(module):
    import importlib

    mod = importlib.import_module(module)
    for name in ("protect", "signed", "sign_intent", "current_credential"):
        assert hasattr(mod, name), f"{module} missing {name}"
