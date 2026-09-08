"""AAT <-> Vouch interop tests.

Each test is named for what it proves. The invariant under test throughout is
that authority can only narrow, and that every decision happens *before* a tool
runs.

Chains are built in-process rather than read from ``test-vectors/aat/`` for the
behavioural tests, because a warrant carries a wall-clock expiry and committed
fixtures would eventually expire and turn these into false failures. The
committed fixtures are exercised separately at the bottom of this file.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

tenuo = pytest.importorskip("tenuo", reason="AAT reference implementation not installed")

from tenuo import Pattern, SigningKey, Warrant  # noqa: E402

from vouch.keys import generate_identity  # noqa: E402
from vouch.signer import Signer  # noqa: E402

from integrations.aat import (  # noqa: E402
    AatBadSignature,
    AatBrokenChain,
    AatError,
    AatExpired,
    AatGate,
    ChainDocument,
    extract_aat_link,
    leaf_to_shield_rules,
    sign_with_aat_link,
    verify_chain,
    verify_chain_file,
)

VECTORS = Path(__file__).resolve().parents[3] / "test-vectors" / "aat"

DID = "did:web:agent.example.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def keys():
    return SigningKey.generate(), SigningKey.generate()


def make_root(root_key, holder_key, ttl=3600):
    """Root authority: read_file + write_file over reports/*."""
    return (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("reports/*"))
        .capability("write_file", path=Pattern("reports/*"))
        .ttl(ttl)
        .holder(holder_key.public_key)
        .mint(root_key)
    )


def narrow_to_read_only(root, holder_key):
    """Offline derivation. No authorization-server round trip."""
    return root.attenuate(
        capabilities={"read_file": {"path": Pattern("reports/*")}},
        signing_key=holder_key,
    )


def document(root_key, warrants):
    return ChainDocument(
        root_public_key_pem=root_key.public_key.to_pem(),
        warrants_b64=[w.to_base64() for w in warrants],
    )


@pytest.fixture
def verified_chain(keys):
    root_key, holder_key = keys
    root = make_root(root_key, holder_key)
    leaf = narrow_to_read_only(root, holder_key)
    return verify_chain(document(root_key, [root, leaf])), holder_key


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------


def test_valid_chain_leaf_rules_extracted(keys):
    """Root -> one derivation. Shield rules match the leaf, not the root."""
    root_key, holder_key = keys
    root = make_root(root_key, holder_key)
    leaf = narrow_to_read_only(root, holder_key)

    chain = verify_chain(document(root_key, [root, leaf]))

    assert chain.depth == 1
    assert chain.tools == ["read_file"]
    assert chain.leaf_jti == str(leaf.id)
    assert chain.root_jti == str(root.id)

    rules = leaf_to_shield_rules(chain, did=DID)

    # The leaf's authority, not the root's: write_file was narrowed away.
    assert rules.allowed_tools == frozenset({"read_file"})
    assert not rules.permits_tool("write_file")

    # The leaf's path constraint became a real Shield resource glob, so the
    # rule is as fine-grained as the token it came from.
    assert [r.action for r in rules.rules] == ["read_file"]
    assert rules.rules[0].resource == "reports/*/**"
    assert rules.mapped_tools == ("read_file",)
    assert rules.unmapped_tools == ()


def test_widened_scope_rejected(keys):
    """A token that widens authority fails. Shield gets no rules."""
    root_key, holder_key = keys
    root = make_root(root_key, holder_key)

    # The reference implementation refuses to derive a widened token at all:
    # adding a tool, loosening a pattern, and dropping a constraint are each
    # refused at derivation rather than at verification.
    for _label, capabilities in [
        ("adds a tool", {"read_file": {"path": Pattern("reports/*")}, "delete_file": {}}),
        ("loosens the pattern", {"read_file": {"path": Pattern("*")}}),
        ("drops the constraint", {"read_file": {}}),
    ]:
        with pytest.raises(tenuo.exceptions.MonotonicityError):
            root.attenuate(capabilities=capabilities, signing_key=holder_key)

    # What an attacker can actually build is a token of their own claiming wider
    # authority, spliced in behind a genuine root. That must fail verification,
    # and no rules may be produced from it.
    attacker_key = SigningKey.generate()
    forged = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("reports/*"))
        .capability("delete_file", path=Pattern("*"))
        .ttl(3600)
        .holder(holder_key.public_key)
        .mint(attacker_key)
    )

    with pytest.raises(AatError) as caught:
        verify_chain(document(root_key, [root, forged]))

    # Fail closed: the failure is typed, and nothing usable came back.
    assert isinstance(caught.value, AatError)
    assert "delete_file" not in str(caught.value)


def test_broken_signature_rejected(keys):
    """Tamper one byte. Fail closed."""
    root_key, holder_key = keys
    root = make_root(root_key, holder_key)
    leaf = narrow_to_read_only(root, holder_key)

    raw = bytearray(leaf.to_bytes())
    raw[len(raw) // 2] ^= 0x01
    import base64

    tampered_b64 = base64.b64encode(bytes(raw)).decode()

    doc = ChainDocument(
        root_public_key_pem=root_key.public_key.to_pem(),
        warrants_b64=[root.to_base64(), tampered_b64],
    )

    with pytest.raises(AatError) as caught:
        verify_chain(doc)
    assert isinstance(caught.value, (AatBadSignature, AatBrokenChain))


def test_untrusted_root_rejected(keys):
    """A chain anchored to a different root is not accepted."""
    root_key, holder_key = keys
    root = make_root(root_key, holder_key)
    leaf = narrow_to_read_only(root, holder_key)

    stranger = SigningKey.generate()
    doc = ChainDocument(
        root_public_key_pem=stranger.public_key.to_pem(),
        warrants_b64=[root.to_base64(), leaf.to_base64()],
    )

    with pytest.raises(AatError):
        verify_chain(doc)


def test_expired_leaf_rejected(keys):
    """An expired leaf fails closed.

    This is the case the reference implementation's ``verify_chain()`` lets
    through on its own -- expiry is enforced only on the authorization call --
    so the adapter checks it explicitly. See INTEROP-NOTES.md.
    """
    root_key, holder_key = keys
    root = make_root(root_key, holder_key, ttl=1)
    time.sleep(2)

    # Precondition: the underlying verifier does not catch this by itself.
    from tenuo import Authorizer

    authorizer = Authorizer()
    authorizer.add_trusted_root(root_key.public_key)
    authorizer.verify_chain([root])  # does not raise

    with pytest.raises(AatExpired):
        verify_chain(document(root_key, [root]))


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------


def test_in_scope_call_allowed_and_credential_links_jti(verified_chain):
    """An in-scope call is allowed and its credential carries the AAT jti."""
    chain, holder_key = verified_chain
    gate = AatGate(chain, holder_key=holder_key)

    decision = gate.check("read_file", {"path": "reports/q3.txt"})
    assert decision.allowed, decision.reason

    identity = generate_identity(domain="test-agent.example.com")
    signer = Signer(private_key=identity.private_key_jwk, did=identity.did)

    credential = sign_with_aat_link(
        signer,
        chain,
        action="read",
        target="reports/q3.txt",
        resource="file://reports/q3.txt",
    )

    link = extract_aat_link(credential)
    assert link is not None
    assert link["scheme"] == "aat"
    assert link["jti"] == chain.leaf_jti
    assert link["chainRoot"] == chain.root_jti
    assert link["depth"] == 1

    # The link rides inside the existing intent object, so the credential is an
    # ordinary Vouch credential: same format, same cryptosuite, still verifies.
    assert credential["credentialSubject"]["intent"]["action"] == "read"
    assert credential["proof"]["cryptosuite"] == "eddsa-jcs-2022"

    from vouch.verifier import Verifier

    is_valid, _ = Verifier.verify(credential, signer.get_public_key_multikey())
    assert is_valid


def test_out_of_scope_call_blocked_before_execution(verified_chain):
    """delete_file never reaches the tool."""
    chain, holder_key = verified_chain
    gate = AatGate(chain, holder_key=holder_key)

    invoked = []

    def delete_file(path):  # the tool that must never run
        invoked.append(path)
        return "deleted"

    decision = gate.check("delete_file", {"path": "reports/q3.txt"})
    if decision.allowed:  # pragma: no cover - would be the bug this guards
        delete_file("reports/q3.txt")

    assert not decision.allowed
    assert decision.failure == "ToolNotAuthorized"
    assert invoked == [], "the tool was executed despite being out of scope"


def test_narrowed_out_tool_blocked_before_execution(verified_chain):
    """write_file was in the root but narrowed out of the leaf. It is blocked."""
    chain, holder_key = verified_chain
    gate = AatGate(chain, holder_key=holder_key)

    invoked = []

    def write_file(path, content):  # pragma: no cover - must never run
        invoked.append(path)

    decision = gate.check("write_file", {"path": "reports/q3.txt"})
    if decision.allowed:  # pragma: no cover
        write_file("reports/q3.txt", "x")

    assert not decision.allowed
    assert decision.failure == "ToolNotAuthorized"
    assert invoked == []


def test_argument_constraint_enforced(verified_chain):
    """Allowed tool, disallowed argument value -> blocked."""
    chain, holder_key = verified_chain
    gate = AatGate(chain, holder_key=holder_key)

    invoked = []

    def read_file(path):
        invoked.append(path)
        return "contents"

    allowed = gate.check("read_file", {"path": "reports/q3.txt"})
    assert allowed.allowed

    blocked = gate.check("read_file", {"path": "/etc/passwd"})
    if blocked.allowed:  # pragma: no cover
        read_file("/etc/passwd")

    assert not blocked.allowed
    # Shield now expresses the leaf's path constraint itself, so it refuses
    # first. Tenuo would also refuse; it simply never gets asked.
    assert blocked.refused_by == "shield"
    assert invoked == [], "a constraint-violating call reached the tool"


def test_missing_proof_of_possession_is_denied(verified_chain):
    """Without a PoP signature, an otherwise in-scope call does not proceed."""
    chain, _ = verified_chain
    gate = AatGate(chain)  # no holder key, so no PoP can be minted

    decision = gate.check("read_file", {"path": "reports/q3.txt"})
    assert not decision.allowed
    assert decision.failure in {"MissingSignature", "SignatureMismatch"}


def test_external_shield_and_aat_must_both_allow(verified_chain):
    """An external Shield's verdict is combined with the AAT verdict."""
    from vouch.shield import Shield, ShieldConfig

    chain, holder_key = verified_chain
    did = "did:vouch:test-agent"

    shield = Shield(ShieldConfig(require_signature=False, strict_mode=True))
    shield.trust_did(did)
    # The external Shield grants nothing, so it must veto even though both the
    # AAT and the AAT-derived rules permit the call.
    gate = AatGate(chain, holder_key=holder_key, shield=shield, did=did)
    decision = gate.check("read_file", {"path": "reports/q3.txt"})

    assert not decision.allowed
    assert decision.failure == "ShieldDenied"


# ---------------------------------------------------------------------------
# Committed fixtures
# ---------------------------------------------------------------------------


def _fixture_expired(path):
    from integrations.aat import AatExpired as _Expired

    try:
        verify_chain_file(path)
        return False
    except _Expired:
        return True
    except AatError:
        return False


def test_valid_fixture_verifies():
    """The committed narrowing fixture verifies and yields read_file only."""
    path = VECTORS / "valid-narrowing-chain.json"
    if _fixture_expired(path):
        pytest.skip(
            "test-vectors/aat/valid-narrowing-chain.json has expired; "
            "regenerate with: python3 test-vectors/aat/generate.py"
        )

    chain = verify_chain_file(path)
    assert chain.tools == ["read_file"]
    assert leaf_to_shield_rules(chain, did=DID).allowed_tools == frozenset({"read_file"})


def test_widening_fixture_is_rejected():
    """The committed widening fixture must never verify.

    Chain structure is checked before expiry, so this holds whether or not the
    fixture has aged out.
    """
    with pytest.raises(AatError):
        verify_chain_file(VECTORS / "widening-chain.json")


def test_fixture_files_carry_no_private_material():
    """Chain fixtures are public material only."""
    for name in ("valid-narrowing-chain.json", "widening-chain.json"):
        raw = json.loads((VECTORS / name).read_text())
        assert "PRIVATE KEY" not in json.dumps(raw)
        assert set(raw) >= {"aat_chain_version", "root_public_key_pem", "warrants"}


# ---------------------------------------------------------------------------
# vouch-mcp wiring
# ---------------------------------------------------------------------------


def _mcp_server():
    return pytest.importorskip("vouch.integrations.mcp.server", reason="MCP SDK not installed")


def test_mcp_denies_when_no_aat_chain_configured(monkeypatch):
    """With no chain configured the AAT tool denies. There is no lax fallback."""
    server = _mcp_server()
    monkeypatch.setattr(server, "_AAT_CHAIN", None)
    server._aat_gate_cache.clear()

    out = server.check_action_aat("read_file", '{"path": "reports/q3.txt"}')
    assert out.startswith("DENY")
    server._aat_gate_cache.clear()


def test_mcp_sources_rules_from_aat_leaf(tmp_path, monkeypatch, keys):
    """--aat-chain makes the MCP gate enforce the leaf's authority."""
    server = _mcp_server()
    root_key, holder_key = keys

    root = make_root(root_key, holder_key)
    leaf = narrow_to_read_only(root, holder_key)

    chain_path = tmp_path / "leaf.json"
    document(root_key, [root, leaf]).write(chain_path)
    key_path = tmp_path / "holder.pem"
    key_path.write_text(holder_key.to_pem())

    monkeypatch.setattr(server, "_AAT_CHAIN", str(chain_path))
    monkeypatch.setattr(server, "_AAT_HOLDER_KEY", str(key_path))
    server._aat_gate_cache.clear()

    allowed = server.check_action_aat("read_file", '{"path": "reports/q3.txt"}')
    assert allowed.startswith("ALLOW"), allowed
    assert str(leaf.id) in allowed

    # Narrowed out of the leaf, even though the root granted it.
    assert server.check_action_aat("write_file", '{"path": "reports/q3.txt"}').startswith("DENY")
    # Allowed tool, disallowed argument.
    assert server.check_action_aat("read_file", '{"path": "/etc/passwd"}').startswith("DENY")

    server._aat_gate_cache.clear()


def test_mcp_denies_when_chain_does_not_verify(tmp_path, monkeypatch):
    """A chain that fails verification yields no authority at all."""
    server = _mcp_server()
    monkeypatch.setattr(server, "_AAT_CHAIN", str(VECTORS / "widening-chain.json"))
    monkeypatch.setattr(server, "_AAT_HOLDER_KEY", None)
    server._aat_gate_cache.clear()

    out = server.check_action_aat("read_file", '{"path": "reports/q3.txt"}')
    assert out.startswith("DENY")
    server._aat_gate_cache.clear()


# ---------------------------------------------------------------------------
# Shield v2 mapping (Step 2 follow-through)
# ---------------------------------------------------------------------------


def test_aat_path_constraint_enforced_by_shield(verified_chain):
    """`read_file /etc/passwd` is denied by Shield, not only by Tenuo.

    The leaf constrains `path` to `reports/*`. Shield v2 can express that as a
    resource glob, so it refuses on its own. This asserts against Shield's
    verdict directly, with Tenuo's evaluator out of the picture entirely.
    """
    chain, _ = verified_chain
    gate = AatGate(chain, did=DID)

    assert gate.shield_check("read_file", {"path": "reports/q3.txt"}).allow

    denied = gate.shield_check("read_file", {"path": "/etc/passwd"})
    assert not denied.allow
    assert denied.reason == "resource outside scope"

    # Narrowed out of the leaf entirely: not a resource question.
    assert gate.shield_check("write_file", {"path": "reports/q3.txt"}).reason == (
        "no matching rule"
    )

    # And traversal cannot sneak back in.
    assert not gate.shield_check("read_file", {"path": "reports/../etc/passwd"}).allow


def test_shield_glob_is_never_wider_than_the_tenuo_constraint(verified_chain):
    """Differential check: Shield must not allow what Tenuo would refuse.

    Tenuo's `*` crosses `/`; Shield's does not. The translation has to account
    for that. Narrower is safe here because both gates must allow; wider would
    silently widen authority.
    """
    from tenuo import Pattern

    from integrations.aat.aat_to_shield import tenuo_glob_to_shield
    from vouch.shield.rules import normalize_pattern, normalize_resource, resource_matches

    resources = [
        "reports",
        "reports/q3.txt",
        "reports/2026/q3.txt",
        "reports/a/b/c",
        "secrets/keys.txt",
        "reportsX/a",
        "etc/passwd",
    ]

    for tenuo_pattern in ["reports/*", "reports/**", "reports/q3.txt"]:
        shield_glob = tenuo_glob_to_shield(tenuo_pattern)
        assert shield_glob is not None, tenuo_pattern
        matcher = Pattern(tenuo_pattern)
        for resource in resources:
            normalised = normalize_resource(resource)
            shield_allows = normalised is not None and resource_matches(
                normalize_pattern(shield_glob), normalised
            )
            if shield_allows:
                assert matcher.matches(resource), (
                    f"Shield glob {shield_glob!r} allows {resource!r} but "
                    f"Tenuo pattern {tenuo_pattern!r} does not - that is a widening"
                )


def test_untranslatable_constraints_fall_back_and_stay_with_tenuo(keys):
    """A constraint Shield cannot express yields '**' and is reported."""
    from tenuo import Range

    from integrations.aat.aat_to_shield import tenuo_glob_to_shield

    # Mid-string '*' has no faithful Shield equivalent: Tenuo matches across
    # '/' through it, and Shield has no way to say that.
    assert tenuo_glob_to_shield("rep*ts") is None
    assert tenuo_glob_to_shield("a/*/b") is None

    root_key, holder_key = keys
    root = (
        Warrant.mint_builder()
        .capability("charge", amount=Range.max_value(100))
        .ttl(3600)
        .holder(holder_key.public_key)
        .mint(root_key)
    )
    chain = verify_chain(document(root_key, [root]))
    rules = leaf_to_shield_rules(chain, did=DID, target="payments")

    assert rules.unmapped_tools == ("charge",)
    assert rules.mapped_tools == ()
    assert [r.resource for r in rules.rules] == ["**"]


def test_numeric_constraint_still_enforced_by_tenuo(keys):
    """Shield's fallback must not become a hole: Tenuo still refuses."""
    from tenuo import Range

    root_key, holder_key = keys
    root = (
        Warrant.mint_builder()
        .capability("charge", amount=Range.max_value(100))
        .ttl(3600)
        .holder(holder_key.public_key)
        .mint(root_key)
    )
    chain = verify_chain(document(root_key, [root]))
    gate = AatGate(chain, holder_key=holder_key, did=DID, target="payments")

    # Shield allows it (its rule is '**'), so the refusal must come from Tenuo.
    assert gate.shield_check("charge", {"amount": 500}).allow

    decision = gate.check("charge", {"amount": 500})
    assert not decision.allowed
    assert decision.refused_by == "tenuo"

    assert gate.check("charge", {"amount": 50}).allowed


def test_rules_render_as_a_v2_document(verified_chain):
    """The derived rules load back through Shield's own loader."""
    from vouch.shield.rules import load_rules

    chain, _ = verified_chain
    rules = leaf_to_shield_rules(chain, did=DID)

    rule_set = load_rules(rules.as_document(), source="<aat>")
    assert rule_set.ok
    assert rule_set.check(DID, "read_file", "filesystem", "reports/q3.txt").allow
    assert not rule_set.check(DID, "read_file", "filesystem", "/etc/passwd").allow
