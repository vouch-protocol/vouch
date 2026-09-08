"""vouch.mcp: every tool protected by default, checked before it runs.

The property under test is that the tool body is not entered unless a verified
credential authorises exactly that call and Shield permits it. Several tests
therefore assert on a spy list rather than only on the returned value: a refusal
that still ran the tool would be worthless.
"""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("mcp", reason="MCP SDK not installed")

from vouch import multikey  # noqa: E402
from vouch.keys import generate_identity  # noqa: E402
from vouch.mcp import FastMCP, VouchMcpConfigError  # noqa: E402
from vouch.signer import Signer  # noqa: E402

TARGET = "files"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_identity():
    """A did:key identity, which resolves offline with no network or hosting."""
    keypair = generate_identity()
    raw = base64.urlsafe_b64decode(json.loads(keypair.public_key_jwk)["x"] + "==")
    did = "did:key:" + multikey.encode_ed25519_public(raw)
    return did, Signer(private_key=keypair.private_key_jwk, did=did)


def write_rules(tmp_path, did, allow=None):
    allow = (
        allow
        if allow is not None
        else [{"action": "read_file", "target": TARGET, "resource": "reports/**"}]
    )
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps({"version": 2, "rules": [{"did": did, "allow": allow}], "deny_default": True})
    )
    return str(path)


def call(server, tool, **kwargs):
    """Invoke a tool, returning ('ok', result) or ('refused', payload)."""
    try:
        result = asyncio.run(server.call_tool(tool, kwargs))
        return "ok", result[1]
    except Exception as exc:
        text = str(exc)
        start = text.find('{"error"')
        payload = json.loads(text[start:]) if start >= 0 else {"reason": text}
        return "refused", payload


@pytest.fixture
def env(tmp_path, monkeypatch):
    did, signer = make_identity()
    rules = write_rules(tmp_path, did)
    monkeypatch.setenv("VOUCH_RULES", rules)
    monkeypatch.setenv("VOUCH_TRUSTED_ISSUERS", did)
    monkeypatch.setenv("VOUCH_TARGET", TARGET)
    monkeypatch.setenv("VOUCH_CHECK_REVOCATION", "0")
    return {"did": did, "signer": signer, "rules": rules, "tmp_path": tmp_path}


@pytest.fixture
def server(env):
    """A protected server with one read_file tool and a spy on its body."""
    mcp = FastMCP("files")
    invoked: list = []

    @mcp.tool(resource=lambda args: args["path"])
    def read_file(path: str) -> str:
        invoked.append(path)
        return f"contents of {path}"

    mcp.invoked = invoked  # type: ignore[attr-defined]
    return mcp


def credential(signer, path, *, action="read_file", target=TARGET, **kw):
    return json.dumps(signer.sign(action=action, target=target, resource=path, **kw))


# ---------------------------------------------------------------------------
# The default is protected
# ---------------------------------------------------------------------------


def test_a_tool_is_protected_without_asking(server, env):
    """No `unprotected=True`, so a call omitting the credential is refused.

    Omitting it entirely is caught by the SDK's own schema validation, because
    the wrapper declares `credential` as required. That is a second, earlier
    refusal than the guard's own: the call never becomes well-formed.
    """
    status, payload = call(server, "read_file", path="reports/q3.txt")
    assert status == "refused"
    assert "credential" in json.dumps(payload)
    assert server.invoked == []


def test_an_empty_credential_is_refused_by_the_guard(server, env):
    """A well-formed call carrying nothing useful reaches the guard, and stops."""
    status, payload = call(server, "read_file", path="reports/q3.txt", credential="")
    assert status == "refused"
    assert payload["reason"] == "no credential"
    assert server.invoked == []


def test_credential_is_a_required_argument_in_the_schema(server):
    tools = asyncio.run(server.list_tools())
    schema = tools[0].inputSchema
    assert "credential" in schema["properties"]
    assert "credential" in schema["required"]


def test_unprotected_opt_out_is_callable_and_warns(env, caplog):
    mcp = FastMCP("files")

    with caplog.at_level("WARNING"):

        @mcp.tool(unprotected=True)
        def health() -> str:
            return "ok"

    assert any("UNPROTECTED" in r.getMessage() for r in caplog.records)

    caplog.clear()
    with caplog.at_level("WARNING"):
        status, result = call(mcp, "health")
    assert status == "ok"
    assert any("UNPROTECTED call" in r.getMessage() for r in caplog.records)


def test_resource_callable_is_rejected_on_an_unprotected_tool(env):
    mcp = FastMCP("files")
    with pytest.raises(ValueError):
        mcp.tool(unprotected=True, resource=lambda a: a["path"])


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def test_valid_in_scope_call_executes(server, env):
    cred = credential(env["signer"], "reports/q3.txt")
    status, result = call(server, "read_file", path="reports/q3.txt", credential=cred)

    assert status == "ok"
    assert server.invoked == ["reports/q3.txt"]


def test_forged_signature_is_refused(server, env):
    cred = json.loads(credential(env["signer"], "reports/q3.txt"))
    proof = cred["proof"]["proofValue"]
    # Flip one character of the signature.
    flipped = "A" if proof[-1] != "A" else "B"
    cred["proof"]["proofValue"] = proof[:-1] + flipped

    status, payload = call(server, "read_file", path="reports/q3.txt", credential=json.dumps(cred))
    assert status == "refused"
    assert payload["reason"] == "credential did not verify"
    assert server.invoked == []


def test_credential_from_an_untrusted_issuer_is_refused(server, env):
    _, stranger = make_identity()
    cred = credential(stranger, "reports/q3.txt")

    status, payload = call(server, "read_file", path="reports/q3.txt", credential=cred)
    assert status == "refused"
    assert payload["reason"] == "untrusted issuer"
    assert server.invoked == []


def test_expired_credential_is_refused(server, env):
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    cred = json.dumps(
        env["signer"].sign(
            action="read_file",
            target=TARGET,
            resource="reports/q3.txt",
            valid_from=past,
            valid_seconds=60,
        )
    )

    status, payload = call(server, "read_file", path="reports/q3.txt", credential=cred)
    assert status == "refused"
    assert payload["reason"] == "credential did not verify"
    assert server.invoked == []


def test_unparseable_credential_is_refused(server, env):
    status, payload = call(server, "read_file", path="reports/q3.txt", credential="not json")
    assert status == "refused"
    assert payload["reason"] == "no credential"
    assert server.invoked == []


# ---------------------------------------------------------------------------
# The credential must be for *this* call
# ---------------------------------------------------------------------------


def test_credential_for_a_different_file_is_refused(server, env):
    """A credential for reports/q3.txt must not authorise reports/q4.txt."""
    cred = credential(env["signer"], "reports/q3.txt")

    status, payload = call(server, "read_file", path="reports/q4.txt", credential=cred)
    assert status == "refused"
    assert payload["reason"] == "credential does not match request"
    assert server.invoked == []


def test_credential_for_a_different_action_is_refused(server, env):
    cred = credential(env["signer"], "reports/q3.txt", action="write_file")

    status, payload = call(server, "read_file", path="reports/q3.txt", credential=cred)
    assert status == "refused"
    assert payload["reason"] == "credential does not match request"
    assert server.invoked == []


def test_credential_for_a_different_target_is_refused(server, env):
    cred = credential(env["signer"], "reports/q3.txt", target="some-other-server")

    status, payload = call(server, "read_file", path="reports/q3.txt", credential=cred)
    assert status == "refused"
    assert payload["reason"] == "credential does not match request"
    assert server.invoked == []


# ---------------------------------------------------------------------------
# Shield
# ---------------------------------------------------------------------------


def test_shield_denied_call_never_reaches_the_tool(server, env):
    """Valid credential, out of scope. The spy proves the body did not run."""
    cred = credential(env["signer"], "secrets/keys.txt")

    status, payload = call(server, "read_file", path="secrets/keys.txt", credential=cred)
    assert status == "refused"
    assert payload["reason"] == "resource outside scope"
    assert server.invoked == [], "the tool ran despite being refused"


def test_traversal_is_refused_by_shield(server, env):
    cred = credential(env["signer"], "reports/../secrets/keys.txt")

    status, payload = call(server, "read_file", path="reports/../secrets/keys.txt", credential=cred)
    assert status == "refused"
    assert payload["reason"] == "resource outside scope"
    assert server.invoked == []


def test_malformed_rules_refuse_everything(tmp_path, monkeypatch):
    did, signer = make_identity()
    rules = tmp_path / "rules.json"
    rules.write_text('{"version": 1, "rules": []}')
    monkeypatch.setenv("VOUCH_RULES", str(rules))
    monkeypatch.setenv("VOUCH_TRUSTED_ISSUERS", did)
    monkeypatch.setenv("VOUCH_TARGET", TARGET)
    monkeypatch.setenv("VOUCH_CHECK_REVOCATION", "0")

    mcp = FastMCP("files")
    invoked: list = []

    @mcp.tool(resource=lambda args: args["path"])
    def read_file(path: str) -> str:  # pragma: no cover - must not run
        invoked.append(path)
        return "x"

    status, payload = call(
        mcp,
        "read_file",
        path="reports/q3.txt",
        credential=credential(signer, "reports/q3.txt"),
    )
    assert status == "refused"
    assert payload["reason"] == "malformed rules"
    assert invoked == []


# ---------------------------------------------------------------------------
# Resource binding
# ---------------------------------------------------------------------------


def test_strict_binding_ties_a_credential_to_exact_arguments(tmp_path, monkeypatch):
    """Default resource is the JCS of all arguments, so 'where' is bound too."""
    from vouch import jcs

    did, signer = make_identity()
    resource_a = jcs.canonicalize_str({"table": "a", "where": "x"})
    rules = write_rules(
        tmp_path, did, allow=[{"action": "run_query", "target": TARGET, "resource": "**"}]
    )
    monkeypatch.setenv("VOUCH_RULES", rules)
    monkeypatch.setenv("VOUCH_TRUSTED_ISSUERS", did)
    monkeypatch.setenv("VOUCH_TARGET", TARGET)
    monkeypatch.setenv("VOUCH_CHECK_REVOCATION", "0")

    mcp = FastMCP("files")
    invoked: list = []

    @mcp.tool()
    def run_query(table: str, where: str) -> str:
        invoked.append((table, where))
        return "rows"

    cred = json.dumps(signer.sign(action="run_query", target=TARGET, resource=resource_a))

    status, _ = call(mcp, "run_query", table="a", where="x", credential=cred)
    assert status == "ok"

    # Same credential, one argument changed.
    status, payload = call(mcp, "run_query", table="a", where="y", credential=cred)
    assert status == "refused"
    assert payload["reason"] == "credential does not match request"
    assert invoked == [("a", "x")]


def test_resource_opt_in_allows_a_glob_over_the_chosen_value(tmp_path, monkeypatch):
    """`resource=` makes the table name the policy unit, so `public.*` works."""
    did, signer = make_identity()
    rules = write_rules(
        tmp_path,
        did,
        allow=[{"action": "run_query", "target": TARGET, "resource": "public.*"}],
    )
    monkeypatch.setenv("VOUCH_RULES", rules)
    monkeypatch.setenv("VOUCH_TRUSTED_ISSUERS", did)
    monkeypatch.setenv("VOUCH_TARGET", TARGET)
    monkeypatch.setenv("VOUCH_CHECK_REVOCATION", "0")

    mcp = FastMCP("files")
    invoked: list = []

    @mcp.tool(resource=lambda args: args["table"])
    def run_query(table: str, where: str = "1=1") -> str:
        invoked.append(table)
        return "rows"

    ok_cred = json.dumps(
        signer.sign(action="run_query", target=TARGET, resource="public.customers")
    )
    status, _ = call(mcp, "run_query", table="public.customers", credential=ok_cred)
    assert status == "ok"

    denied_cred = json.dumps(
        signer.sign(action="run_query", target=TARGET, resource="internal.salaries")
    )
    status, payload = call(mcp, "run_query", table="internal.salaries", credential=denied_cred)
    assert status == "refused"
    assert payload["reason"] == "resource outside scope"
    assert invoked == ["public.customers"]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_server_refuses_to_start_without_rules(monkeypatch, tmp_path):
    monkeypatch.delenv("VOUCH_RULES", raising=False)
    monkeypatch.setenv("VOUCH_TRUSTED_ISSUERS", "did:key:z6Mk")

    with pytest.raises(VouchMcpConfigError) as caught:
        FastMCP("files")
    assert "VOUCH_RULES" in str(caught.value)
    assert "unprotected" in str(caught.value)


def test_server_refuses_to_start_without_trusted_issuers(monkeypatch, tmp_path):
    rules = write_rules(tmp_path, "did:key:z6Mk")
    monkeypatch.setenv("VOUCH_RULES", rules)
    monkeypatch.delenv("VOUCH_TRUSTED_ISSUERS", raising=False)

    with pytest.raises(VouchMcpConfigError) as caught:
        FastMCP("files")
    assert "VOUCH_TRUSTED_ISSUERS" in str(caught.value)


def test_target_defaults_to_the_server_name(tmp_path, monkeypatch):
    did, _ = make_identity()
    monkeypatch.setenv("VOUCH_RULES", write_rules(tmp_path, did))
    monkeypatch.setenv("VOUCH_TRUSTED_ISSUERS", did)
    monkeypatch.delenv("VOUCH_TARGET", raising=False)

    mcp = FastMCP("crm-tools")
    assert mcp.vouch_guard.config.target == "crm-tools"


def test_constructor_arguments_override_the_environment(tmp_path, monkeypatch):
    did, _ = make_identity()
    monkeypatch.delenv("VOUCH_RULES", raising=False)
    monkeypatch.delenv("VOUCH_TRUSTED_ISSUERS", raising=False)

    mcp = FastMCP(
        "files",
        rules_path=write_rules(tmp_path, did),
        trusted_issuers=[did],
        target="files",
    )
    assert mcp.vouch_guard.config.trusted_issuers == frozenset({did})


# ---------------------------------------------------------------------------
# One decision line per call
# ---------------------------------------------------------------------------


def test_every_decision_is_logged_once(server, env, caplog):
    cred = credential(env["signer"], "reports/q3.txt")

    with caplog.at_level("INFO", logger="vouch.mcp._guard"):
        call(server, "read_file", path="reports/q3.txt", credential=cred)
    allow_lines = [r for r in caplog.records if r.getMessage().startswith("ALLOW")]
    assert len(allow_lines) == 1
    assert env["did"] in allow_lines[0].getMessage()
    assert "reports/q3.txt" in allow_lines[0].getMessage()

    caplog.clear()
    with caplog.at_level("INFO", logger="vouch.mcp._guard"):
        call(server, "read_file", path="secrets/keys.txt", credential=cred)
    deny_lines = [r for r in caplog.records if r.getMessage().startswith("DENY")]
    assert len(deny_lines) == 1
    assert "credential does not match request" in deny_lines[0].getMessage()


# ---------------------------------------------------------------------------
# SDK compatibility
# ---------------------------------------------------------------------------


def test_works_against_whichever_mcp_sdk_is_installed():
    """The SDK renamed its server class; both names reach the same subclass.

    mcp 1.x ships `FastMCP`, mcp 2.x renamed it to `MCPServer`. Importing only
    one of them made this module fail outright on the other line, so the base
    class is chosen at import time and both names are exported.
    """
    import vouch.mcp as module

    assert module.MCPServer is module.FastMCP
    assert isinstance(module._MCP_SDK_V2, bool)

    # Whichever line is installed, the subclass really extends that SDK's class.
    base = type(module.FastMCP).__mro__[0]
    assert base is type
    parents = [c.__name__ for c in module.FastMCP.__mro__]
    assert parents[0] == "FastMCP"
    assert any(name in parents for name in ("FastMCP", "MCPServer"))
