"""vouch-mcp consults Shield before it signs.

A credential is a statement that this agent authorised an action. If policy says
it may not, there is nothing to attest, so no credential is issued. That makes
the signer the first of two refusal points, the second being the tool server
that receives the credential.
"""

from __future__ import annotations

import base64
import json

import pytest

pytest.importorskip("mcp", reason="MCP SDK not installed")

from vouch import multikey  # noqa: E402
from vouch.integrations.mcp import server as notary  # noqa: E402
from vouch.autosign import reset_default_signer  # noqa: E402
from vouch.keys import generate_identity  # noqa: E402

TARGET = "files"


@pytest.fixture
def notary_env(tmp_path, monkeypatch):
    keypair = generate_identity()
    raw = base64.urlsafe_b64decode(json.loads(keypair.public_key_jwk)["x"] + "==")
    did = "did:key:" + multikey.encode_ed25519_public(raw)

    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            {
                "version": 2,
                "rules": [
                    {
                        "did": did,
                        "allow": [
                            {
                                "id": "read-reports",
                                "action": "read_file",
                                "target": TARGET,
                                "resource": "reports/**",
                            }
                        ],
                    }
                ],
                "deny_default": True,
            }
        )
    )

    monkeypatch.setenv("VOUCH_DID", did)
    monkeypatch.setenv("VOUCH_PRIVATE_KEY", keypair.private_key_jwk)
    monkeypatch.setattr(notary, "_RULES_PATH", str(rules))
    notary._shield_cache.clear()
    # resolve_signer() memoises the process-wide default signer, so a stale one
    # from an earlier test would sign under the wrong DID.
    reset_default_signer()
    yield {"did": did}
    notary._shield_cache.clear()
    reset_default_signer()


def test_sign_issues_a_credential_for_a_permitted_intent(notary_env):
    out = json.loads(notary.sign(action="read_file", target=TARGET, resource="reports/q3.txt"))

    assert out.get("error") is None
    assert out["credentialSubject"]["intent"]["resource"] == "reports/q3.txt"
    assert out["proof"]["cryptosuite"] == "eddsa-jcs-2022"


def _window_seconds(credential):
    from datetime import datetime

    fmt = "%Y-%m-%dT%H:%M:%SZ"
    start = datetime.strptime(credential["validFrom"], fmt)
    end = datetime.strptime(credential["validUntil"], fmt)
    return int((end - start).total_seconds())


def test_sign_lets_the_caller_choose_how_long_the_credential_lasts(notary_env):
    intent = {"action": "read_file", "target": TARGET, "resource": "reports/q3.txt"}

    default = json.loads(notary.sign(**intent))
    chosen = json.loads(notary.sign(**intent, valid_seconds=120))
    post_quantum = json.loads(notary.sign(**intent, post_quantum=True, valid_seconds=45))

    assert _window_seconds(default) == 300
    assert _window_seconds(chosen) == 120
    assert _window_seconds(post_quantum) == 45
    assert isinstance(post_quantum["proof"], list) and len(post_quantum["proof"]) == 2


@pytest.mark.parametrize("valid_seconds", [0, -5, 1.5, "120", True])
def test_sign_rejects_a_validity_that_is_not_a_positive_whole_number(notary_env, valid_seconds):
    out = notary.sign(
        action="read_file", target=TARGET, resource="reports/q3.txt", valid_seconds=valid_seconds
    )
    assert out.startswith("Error: valid_seconds")


def test_a_chosen_validity_does_not_get_past_the_policy_check(notary_env):
    out = json.loads(
        notary.sign(
            action="delete_file", target=TARGET, resource="reports/q3.txt", valid_seconds=120
        )
    )
    assert out["error"] == "refused" and "proof" not in out


def test_sign_refuses_a_denied_action_with_a_structured_refusal(notary_env):
    """Nothing to present: the notary will not stamp it."""
    out = json.loads(notary.sign(action="delete_file", target=TARGET, resource="reports/q3.txt"))

    assert out["error"] == "refused"
    assert out["reason"] == "no matching rule"
    assert out["action"] == "delete_file"
    assert "proof" not in out


def test_sign_refuses_a_resource_outside_scope(notary_env):
    out = json.loads(notary.sign(action="read_file", target=TARGET, resource="secrets/keys.txt"))

    assert out["error"] == "refused"
    assert out["reason"] == "resource outside scope"


def test_sign_refuses_traversal(notary_env):
    out = json.loads(
        notary.sign(action="read_file", target=TARGET, resource="reports/../secrets/keys.txt")
    )
    assert out["error"] == "refused"
    assert out["reason"] == "resource outside scope"


def test_sign_refuses_everything_without_a_rules_file(monkeypatch, tmp_path):
    keypair = generate_identity()
    raw = base64.urlsafe_b64decode(json.loads(keypair.public_key_jwk)["x"] + "==")
    did = "did:key:" + multikey.encode_ed25519_public(raw)
    monkeypatch.setenv("VOUCH_DID", did)
    monkeypatch.setenv("VOUCH_PRIVATE_KEY", keypair.private_key_jwk)
    monkeypatch.setattr(notary, "_RULES_PATH", None)
    notary._shield_cache.clear()
    reset_default_signer()

    out = json.loads(notary.sign(action="read_file", target=TARGET, resource="reports/q3.txt"))
    assert out["error"] == "refused"
    assert out["reason"] == "unknown did"
    notary._shield_cache.clear()
    reset_default_signer()


def test_check_action_reports_the_decision_and_its_reason(notary_env):
    did = notary_env["did"]

    allowed = notary.check_action(
        action="read_file", target=TARGET, resource="reports/q3.txt", did=did
    )
    assert allowed.startswith("ALLOW")
    assert "read-reports" in allowed

    outside = notary.check_action(
        action="read_file", target=TARGET, resource="secrets/keys.txt", did=did
    )
    assert outside == "DENY: resource outside scope"

    wrong_action = notary.check_action(
        action="delete_file", target=TARGET, resource="reports/q3.txt", did=did
    )
    assert wrong_action == "DENY: no matching rule"

    stranger = notary.check_action(
        action="read_file", target=TARGET, resource="reports/q3.txt", did="did:key:z6MkStranger"
    )
    assert stranger == "DENY: unknown did"
