"""
Tests for the additive developer-experience sugar:

  1. vouch.Agent              - one object holding identity + signer
  2. vouch.sign / vouch.verify - top-level one-liners
  3. Signer.sign_credential(action=, target=, resource=) named-arg intent
  4. vouch.verify default DID resolution, including did:key (offline)
  5. CredentialPassport accessors + vouch.Credential wrapper
  6. vouch.require_signed / vouch.guard_mcp / vouch.guard_tools
  7. Signer.from_keypair

Everything here is sugar over the canonical dict credential. The tests assert
the sugar produces and accepts exactly the same credential as the existing
Signer/Verifier path.
"""

import json

import pytest

import vouch
from vouch import (
    Agent,
    Credential,
    Signer,
    Verifier,
    generate_identity,
    guard_mcp,
    guard_tools,
    require_signed,
    sign,
    verify,
)

INTENT = {"action": "read", "target": "did:web:files", "resource": "https://files/x"}


# ---------------------------------------------------------------------------
# Item 7: Signer.from_keypair
# ---------------------------------------------------------------------------


def test_from_keypair_matches_manual_construction(keypair):
    s1 = Signer.from_keypair(keypair)
    cred = s1.sign_credential(intent=INTENT)
    ok, passport = Verifier.verify_credential(cred, public_key=keypair.public_key_jwk)
    assert ok
    assert passport.iss == keypair.did


def test_from_keypair_requires_did():
    kp = generate_identity()  # no domain -> did is None
    with pytest.raises(ValueError):
        Signer.from_keypair(kp)


# ---------------------------------------------------------------------------
# Item 3: named-argument intent on sign_credential
# ---------------------------------------------------------------------------


def test_named_args_equivalent_to_intent_dict(signer, keypair):
    by_dict = signer.sign_credential(intent=INTENT)
    by_named = signer.sign_credential(
        action="read", target="did:web:files", resource="https://files/x"
    )
    assert by_dict["credentialSubject"]["intent"] == by_named["credentialSubject"]["intent"]
    ok, _ = Verifier.verify_credential(by_named, public_key=keypair.public_key_jwk)
    assert ok


def test_named_args_override_intent_dict(signer):
    cred = signer.sign_credential(intent=INTENT, resource="https://files/override")
    intent = cred["credentialSubject"]["intent"]
    assert intent["resource"] == "https://files/override"
    assert intent["action"] == "read"


def test_missing_required_intent_field_raises(signer):
    with pytest.raises(ValueError):
        signer.sign_credential(action="read")  # no target/resource


def test_intent_dict_is_not_mutated(signer):
    original = dict(INTENT)
    signer.sign_credential(intent=INTENT, action="write")
    assert INTENT == original  # named arg did not leak back into the caller dict


# ---------------------------------------------------------------------------
# Item 2: top-level sign / verify
# ---------------------------------------------------------------------------


def test_top_level_sign_and_verify(keypair):
    signed = sign(keypair, action="read", target="did:web:files", resource="https://files/x")
    ok, who = verify(signed, keypair.public_key_jwk)
    assert ok
    assert who.action == "read"
    assert who.resource == "https://files/x"


def test_top_level_sign_matches_signer_output(keypair):
    via_helper = sign(keypair, intent=INTENT)
    via_signer = Signer.from_keypair(keypair).sign_credential(intent=INTENT)
    # Same structure (ids/proofs differ); the intent and issuer must match.
    assert via_helper["credentialSubject"]["intent"] == via_signer["credentialSubject"]["intent"]
    assert via_helper["issuer"] == via_signer["issuer"]


def test_verify_rejects_wrong_key(keypair):
    signed = sign(keypair, intent=INTENT)
    other = generate_identity("other.example")
    ok, _ = verify(signed, other.public_key_jwk)
    assert not ok


def test_verify_accepts_json_string(keypair):
    signed = sign(keypair, intent=INTENT)
    ok, who = verify(json.dumps(signed), keypair.public_key_jwk)
    assert ok
    assert who.resource == INTENT["resource"]


# ---------------------------------------------------------------------------
# Item 1: Agent wrapper
# ---------------------------------------------------------------------------


def test_agent_mint_sign_self_verify():
    agent = Agent("agent.example", persist=False)
    assert agent.did == "did:web:agent.example"
    signed = agent.sign(action="read", target="did:web:files", resource="https://files/x")
    ok, who = agent.verify(signed)  # knows its own key, no network
    assert ok
    assert who.issuer == agent.did
    assert who.action == "read"


def test_agent_did_key_when_no_domain():
    agent = Agent(persist=False)
    assert agent.did.startswith("did:key:")
    signed = agent.sign(action="write", target="t", resource="r")
    # did:key resolves offline through the default verify path.
    ok, who = verify(signed)
    assert ok
    assert who.issuer == agent.did


def test_agent_load_roundtrip():
    agent = Agent("agent.example", persist=False, allow_key_export=True)
    signed = agent.sign(intent=INTENT)
    reloaded = Agent.load(agent.private_key_jwk, agent.did)
    assert reloaded.did == agent.did
    assert reloaded.public_key_jwk == agent.public_key_jwk
    ok, _ = reloaded.verify(signed)
    assert ok


def test_agent_from_keypair(keypair):
    agent = Agent.from_keypair(keypair)
    signed = agent.sign(intent=INTENT)
    ok, _ = Verifier.verify_credential(signed, public_key=keypair.public_key_jwk)
    assert ok


def test_agent_verify_other_issuer_offline_key():
    a = Agent("a.example", persist=False)
    b = Agent("b.example", persist=False)
    signed_by_b = b.sign(intent=INTENT)
    # a does not know b's key and b is did:web (no network here); an explicit
    # key still verifies offline.
    ok, who = a.verify(signed_by_b, public_key=b.public_key_jwk)
    assert ok
    assert who.issuer == b.did


def test_agent_delegate_and_chain():
    principal = Agent("principal.example", persist=False)
    grant = principal.delegate(
        action="charge", target="api.bank", resource="https://api.bank/invoices"
    )
    worker = Agent("worker.example", persist=False)
    child = worker.sign(
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices/42",
        parent_credential=grant,
    )
    chain = child["credentialSubject"]["delegationChain"]
    assert len(chain) == 1
    assert chain[0]["issuer"] == principal.did


# ---------------------------------------------------------------------------
# Item 4: did:key resolution in the default verify path
# ---------------------------------------------------------------------------


def test_did_key_resolves_without_network():
    agent = Agent(persist=False)  # did:key
    signed = agent.sign(intent=INTENT)
    ok, who = verify(signed)  # no key, no trusted root -> resolved from did:key
    assert ok
    assert who.issuer == agent.did


def test_did_key_resolution_allowed_even_offline_flag():
    agent = Agent(persist=False)
    signed = agent.sign(intent=INTENT)
    # did:key needs no network, so it works with resolution disabled too.
    ok, _ = verify(signed, allow_did_resolution=False)
    assert ok


def test_did_key_tampered_credential_fails():
    agent = Agent(persist=False)
    signed = agent.sign(intent=INTENT)
    signed["credentialSubject"]["intent"]["resource"] = "https://files/evil"
    ok, _ = verify(signed)
    assert not ok


# ---------------------------------------------------------------------------
# Item 5: result accessors + Credential wrapper
# ---------------------------------------------------------------------------


def test_passport_accessors(keypair):
    signed = sign(keypair, intent=INTENT)
    ok, p = verify(signed, keypair.public_key_jwk)
    assert ok
    assert p.action == "read"
    assert p.target == "did:web:files"
    assert p.resource == "https://files/x"
    assert p.issuer == p.iss == keypair.did
    assert p.is_expired is False


def test_passport_is_expired_true(keypair):
    expired = Signer(
        private_key=keypair.private_key_jwk, did=keypair.did, default_expiry_seconds=-60
    ).sign_credential(intent=INTENT)
    # Structural verification with skew large enough to still parse a passport.
    ok, p = Verifier.verify_credential(
        expired, public_key=keypair.public_key_jwk, clock_skew_seconds=3600
    )
    assert ok
    assert p.is_expired is True


def test_credential_wrapper_accessors(keypair):
    signed = sign(keypair, intent=INTENT)
    c = Credential(signed)
    assert c.action == "read"
    assert c.target == "did:web:files"
    assert c.resource == "https://files/x"
    assert c.issuer == keypair.did
    assert c.intent == INTENT
    assert c.is_expired is False


def test_credential_wrapper_verify_and_json(keypair):
    signed = sign(keypair, intent=INTENT)
    c = Credential(signed)
    ok, p = c.verify(keypair.public_key_jwk)
    assert ok
    assert p.action == "read"
    # to_json round-trips to the same dict
    assert json.loads(c.to_json()) == signed
    assert c.to_dict() is signed


def test_credential_wrapper_from_json_string(keypair):
    signed = sign(keypair, intent=INTENT)
    c = Credential(json.dumps(signed))
    assert c.resource == "https://files/x"
    assert "proof" in c


def test_credential_wrapper_rejects_bad_input():
    with pytest.raises(TypeError):
        Credential(12345)  # not a dict or JSON string


# ---------------------------------------------------------------------------
# Item 6: require_signed / guard_mcp / guard_tools
# ---------------------------------------------------------------------------


@pytest.fixture
def did_key_agent():
    """A did:key agent whose credentials verify offline (no network)."""
    return Agent(persist=False)


def test_require_signed_allows_trusted(did_key_agent):
    signed = did_key_agent.sign(intent=INTENT)

    @require_signed(trusted_dids=[did_key_agent.did])
    def write_file(path):
        return f"wrote {path}"

    assert write_file("/x", vouch_credential=signed) == "wrote /x"


def test_require_signed_rejects_unsigned(did_key_agent):
    @require_signed(trusted_dids=[did_key_agent.did])
    def write_file(path):
        return "ran"

    with pytest.raises(PermissionError):
        write_file("/x")


def test_require_signed_rejects_untrusted_issuer(did_key_agent):
    other = Agent(persist=False)
    signed = other.sign(intent=INTENT)

    @require_signed(trusted_dids=[did_key_agent.did])
    def write_file(path):
        return "ran"

    with pytest.raises(PermissionError):
        write_file("/x", vouch_credential=signed)


def test_require_signed_keeps_credential_when_declared(did_key_agent):
    signed = did_key_agent.sign(intent=INTENT)

    @require_signed(trusted_dids=[did_key_agent.did])
    def needs_cred(path, *, vouch_credential):
        return vouch_credential["issuer"]

    assert needs_cred("/x", vouch_credential=signed) == did_key_agent.did


def test_require_signed_injects_passport(did_key_agent):
    signed = did_key_agent.sign(intent=INTENT)

    @require_signed(trusted_dids=[did_key_agent.did], inject_passport=True)
    def handler(path, *, vouch_passport):
        return vouch_passport.action

    assert handler("/x", vouch_credential=signed) == "read"


def test_require_signed_intent_policy(did_key_agent):
    @require_signed(trusted_dids=[did_key_agent.did], require_action="read")
    def handler(path):
        return "ok"

    good = did_key_agent.sign(intent=INTENT)
    assert handler("/x", vouch_credential=good) == "ok"

    bad = did_key_agent.sign(action="delete", target="t", resource="r")
    with pytest.raises(PermissionError):
        handler("/x", vouch_credential=bad)


def test_require_signed_on_reject_none(did_key_agent):
    @require_signed(trusted_dids=[did_key_agent.did], on_reject="none")
    def handler(path):
        return "ran"

    assert handler("/x") is None


def test_require_signed_bare_decorator(did_key_agent):
    signed = did_key_agent.sign(intent=INTENT)

    @require_signed
    def handler(path):
        return "ok"

    assert handler("/x", vouch_credential=signed) == "ok"
    with pytest.raises(PermissionError):
        handler("/x")


def test_require_signed_with_trusted_keys_offline():
    kp = generate_identity("w.example")
    signed = sign(kp, intent=INTENT)

    @require_signed(trusted_dids=[kp.did], trusted_keys={kp.did: kp.public_key_jwk})
    def handler(path):
        return "ok"

    assert handler("/x", vouch_credential=signed) == "ok"


def test_guard_tools(did_key_agent):
    signed = did_key_agent.sign(intent=INTENT)

    def t1(x):
        return x

    guarded = guard_tools([t1], trusted_dids=[did_key_agent.did])
    assert guarded[0]("hi", vouch_credential=signed) == "hi"
    with pytest.raises(PermissionError):
        guarded[0]("hi")


def test_guard_tools_idempotent(did_key_agent):
    def t1(x):
        return x

    once = guard_tools([t1], trusted_dids=[did_key_agent.did])
    twice = guard_tools(once, trusted_dids=[did_key_agent.did])
    assert twice[0] is once[0]


def test_guard_mcp_decorator_server(did_key_agent):
    signed = did_key_agent.sign(intent=INTENT)

    class FakeServer:
        def __init__(self):
            self.registered = {}

        def tool(self, *a, **k):
            def deco(fn):
                self.registered[fn.__name__] = fn
                return fn

            return deco

    server = guard_mcp(FakeServer(), trusted_dids=[did_key_agent.did])

    @server.tool()
    def do_thing(x):
        return f"did {x}"

    assert server.registered["do_thing"]("y", vouch_credential=signed) == "did y"
    with pytest.raises(PermissionError):
        server.registered["do_thing"]("y")


def test_guard_mcp_add_tool_server(did_key_agent):
    signed = did_key_agent.sign(intent=INTENT)

    class FakeServer:
        def __init__(self):
            self.tools = []

        def add_tool(self, fn, name=None):
            self.tools.append(fn)
            return fn

    server = guard_mcp(FakeServer(), trusted_dids=[did_key_agent.did])

    def do_thing(x):
        return f"did {x}"

    server.add_tool(do_thing)
    assert server.tools[0]("y", vouch_credential=signed) == "did y"
    with pytest.raises(PermissionError):
        server.tools[0]("y")


def test_guard_mcp_raises_without_hook():
    class Bare:
        pass

    with pytest.raises(TypeError):
        guard_mcp(Bare(), trusted_dids=["did:web:x"])


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


def test_new_symbols_exported():
    for name in (
        "Agent",
        "Credential",
        "sign",
        "verify",
        "require_signed",
        "guard_mcp",
        "guard_tools",
        "CredentialGate",
    ):
        assert hasattr(vouch, name), name
        assert name in vouch.__all__, name
