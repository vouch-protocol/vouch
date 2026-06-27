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


class TestVerifyOneLiner:
    """vouch.verify is the receiving-side counterpart to protect()/sign_intent."""

    def test_offline_with_key(self, env_identity, keypair, pubkey):
        import vouch

        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)
        cred = signer.sign_credential({"action": "a", "target": "t", "resource": "r"})

        ok, passport = vouch.verify(cred, public_key=pubkey)
        assert ok
        assert passport.intent["action"] == "a"
        # JWK form is accepted too
        assert vouch.verify(cred, public_key=keypair.public_key_jwk)[0]

    def test_verifies_current_credential_by_default(self, env_identity, keypair, pubkey):
        import vouch

        @signed(target="api.example.com")
        def do(x):
            return None

        do(1)
        # No credential argument: verify whatever was just signed.
        ok, passport = vouch.verify(public_key=pubkey)
        assert ok
        assert passport.intent["target"] == "api.example.com"

    def test_tamper_is_rejected(self, env_identity, keypair, pubkey):
        import copy

        import vouch

        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)
        cred = signer.sign_credential({"action": "a", "target": "t", "resource": "r"})
        tampered = copy.deepcopy(cred)
        tampered["credentialSubject"]["intent"]["action"] = "STEAL"

        assert vouch.verify(tampered, public_key=pubkey)[0] is False

    def test_no_credential_returns_false_none(self, env_identity):
        import vouch

        autosign._current_credential.set(None)
        assert vouch.verify() == (False, None)


class TestDecoratorAutosignEngine:
    """install_decorator_autosign patches a framework's @tool decorator."""

    def _fake_module(self):
        import types

        mod = types.ModuleType("fakefw")

        def tool(*dargs, **dkw):
            # bare: tool(func) ; factory: tool("name")(func)
            if len(dargs) == 1 and callable(dargs[0]) and not dkw:
                fn = dargs[0]
                fn._toolname = fn.__name__
                return fn

            def deco(fn):
                fn._toolname = dargs[0] if dargs else "x"
                return fn

            return deco

        mod.tool = tool
        return mod

    def test_factory_style_is_signed(self, env_identity, pubkey):
        mod = self._fake_module()
        assert autosign.install_decorator_autosign(mod, "tool") is True

        @mod.tool("Charge")
        def charge(invoice_id, target=None):
            return current_credential()

        cred = charge("42", target="bank.example.com")
        assert _verify(cred, pubkey)[0]
        assert charge._toolname == "Charge"  # framework metadata preserved

    def test_bare_style_is_signed(self, env_identity, pubkey):
        mod = self._fake_module()
        autosign.install_decorator_autosign(mod, "tool")

        @mod.tool
        def ping(target=None):
            return current_credential()

        assert _verify(ping(target="svc"), pubkey)[0]

    def test_idempotent(self, env_identity):
        mod = self._fake_module()
        assert autosign.install_decorator_autosign(mod, "tool") is True
        assert autosign.install_decorator_autosign(mod, "tool") is False


# Every agent integration exposes the deterministic signing primitives.
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


# Only the decorator-based frameworks expose autosign(); the function-based ones
# deliberately do not (protect() is their one-liner).
@pytest.mark.parametrize(
    "module,has_autosign",
    [
        ("vouch.integrations.crewai", True),
        ("vouch.integrations.langchain", True),
        ("vouch.integrations.autogpt", True),
        ("vouch.integrations.autogen", False),
        ("vouch.integrations.vertex_ai", False),
        ("vouch.integrations.google", False),
    ],
)
def test_autosign_only_where_a_decorator_exists(module, has_autosign):
    import importlib

    mod = importlib.import_module(module)
    assert hasattr(mod, "autosign") is has_autosign


def test_legacy_signing_tools_are_gone():
    """The LLM-driven 'mint a token' tools were removed (no legacy in use)."""
    import importlib

    import vouch.integrations.crewai as crewai
    import vouch.integrations.langchain as langchain

    for removed in ("sign_request", "VouchCrewTools", "VouchSignerTool"):
        assert not hasattr(crewai, removed), f"crewai still exposes {removed}"
    for removed in ("VouchSignerTool", "VouchSignerInput"):
        assert not hasattr(langchain, removed), f"langchain still exposes {removed}"

    # The deleted modules should no longer import.
    for gone in (
        "vouch.integrations.autogen.tool",
        "vouch.integrations.vertex_ai.tool",
    ):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(gone)
