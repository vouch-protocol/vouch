"""The A2A endpoint, the signed agent card, and the assistant's DID.

Real keys and real signatures, with the sidecar in-process and the model
replaced by a fixed reply.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from fastapi.testclient import TestClient

from vouch import Verifier
from vouch.did_web import DIDDocument, did_web_to_url
from vouch.integrations.a2a import verify_agent_card

from tests.conftest import DID
from tests.test_signing_flow import _fake_llm
from vouch_agent import a2a, card, main, sidecar, signer


def _send(client: TestClient, text: str, **extra: Any) -> dict[str, Any]:
    body = {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "message/send",
        "params": {
            "message": {
                "kind": "message",
                "role": "user",
                "messageId": "m-1",
                "parts": [{"kind": "text", "text": text}],
            }
        },
    }
    body.update(extra)
    resp = client.post("/a2a", json=body)
    assert resp.status_code == 200
    return resp.json()


def _resolve(client: TestClient) -> DIDDocument:
    """Resolve the assistant's DID from the app, as a verifier would."""
    assert did_web_to_url(DID) == "https://agent.vouch-protocol.com/.well-known/did.json"
    resp = client.get("/.well-known/did.json")
    assert resp.status_code == 200
    return DIDDocument.from_json(resp.json())


def test_default_did_is_served_by_the_app() -> None:
    assert DID == "did:web:agent.vouch-protocol.com"
    from vouch_agent.config import Config

    assert Config().agent_did == DID or "VOUCH_AGENT_DID" in __import__("os").environ


def test_message_send_answers_with_a_reply_signed_by_the_resolved_did(
    wired: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_llm(monkeypatch, "A did:web resolves over HTTPS.\n---FOLLOWUPS---\n- How?\n- Why?")
    out = _send(wired, "what is did:web")
    assert out["id"] == "req-1" and "error" not in out
    message = out["result"]
    assert message["kind"] == "message" and message["role"] == "agent"
    text = message["parts"][0]["text"]
    assert text == "A did:web resolves over HTTPS."
    credential = message["metadata"]["vouchCredential"]
    assert credential["issuer"] == DID
    key = _resolve(wired).get_ed25519_public_key()
    ok, _ = Verifier.verify(credential, public_key=key)
    assert ok
    intent = credential["credentialSubject"]["intent"]
    assert intent["action"] == "answer_question"
    assert intent["outputDigest"] == signer.digest(text)


def test_tampered_reply_credential_fails(
    wired: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_llm(monkeypatch, "Signed answer.")
    credential = _send(wired, "q")["result"]["metadata"]["vouchCredential"]
    forged = copy.deepcopy(credential)
    forged["credentialSubject"]["intent"]["outputDigest"] = signer.digest("something else")
    ok, _ = Verifier.verify(forged, public_key=_resolve(wired).get_ed25519_public_key())
    assert not ok


def test_unknown_method_is_method_not_found(wired: TestClient) -> None:
    for method in ("tasks/get", "message/stream", "act", "generate_starter"):
        out = wired.post("/a2a", json={"jsonrpc": "2.0", "id": 7, "method": method}).json()
        assert out["error"]["code"] == a2a.METHOD_NOT_FOUND
        assert out["id"] == 7


def test_malformed_requests_are_json_rpc_errors(wired: TestClient) -> None:
    parse = wired.post("/a2a", content=b"{not json", headers={"content-type": "application/json"})
    assert parse.json()["error"]["code"] == a2a.PARSE_ERROR
    for body in (
        [],
        {"jsonrpc": "1.0", "id": 1, "method": "message/send"},
        {"jsonrpc": "2.0", "method": "message/send"},
        {"jsonrpc": "2.0", "id": True, "method": "message/send"},
    ):
        assert wired.post("/a2a", json=body).json()["error"]["code"] == a2a.INVALID_REQUEST


@pytest.mark.parametrize(
    "parts",
    [
        [],
        [{"kind": "file", "file": {"uri": "https://example.com/x"}}],
        [{"kind": "data", "data": {"action": "generate_starter"}}],
        [{"kind": "text", "text": "ok"}, {"kind": "data", "data": {}}],
        [{"kind": "text", "text": "   "}],
        [{"kind": "text", "text": 5}],
    ],
)
def test_only_text_parts_are_accepted(wired: TestClient, parts: list[Any]) -> None:
    body = {
        "jsonrpc": "2.0",
        "id": "p",
        "method": "message/send",
        "params": {"message": {"role": "user", "parts": parts}},
    }
    assert wired.post("/a2a", json=body).json()["error"]["code"] == a2a.INVALID_PARAMS


def test_oversize_input_is_refused(wired: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_llm(monkeypatch, "never sent")
    out = _send(wired, "x" * (a2a.MAX_TEXT_CHARS + 1))
    assert out["error"]["code"] == a2a.INVALID_PARAMS
    big = (
        b'{"jsonrpc":"2.0","id":1,"method":"message/send","pad":"'
        + b"x" * a2a.MAX_BODY_BYTES
        + b'"}'
    )
    resp = wired.post("/a2a", content=big, headers={"content-type": "application/json"})
    assert resp.status_code == 413


def test_no_tool_action_is_reachable_through_a2a(
    wired: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed: list[dict[str, Any]] = []
    real = signer.sign_and_verify

    async def spy(intent: dict[str, Any], **kw: Any) -> dict[str, Any]:
        signed.append(intent)
        return await real(intent, **kw)

    monkeypatch.setattr(signer, "sign_and_verify", spy)
    _fake_llm(monkeypatch, "Here you go.\n---ACTION--- generate_starter python")
    out = _send(wired, "make me a starter project")
    assert out["result"]["parts"] == [{"kind": "text", "text": "Here you go."}]
    assert "action" not in out["result"].get("metadata", {})
    assert [i["action"] for i in signed] == ["answer_question"]


def test_agent_card_is_signed_by_the_did_and_bound_to_the_endpoint(wired: TestClient) -> None:
    resp = wired.get("/.well-known/agent-card.json")
    assert resp.status_code == 200
    signed = resp.json()
    assert signed["url"] == card.DEFAULT_A2A_URL
    assert signed["capabilities"]["streaming"] is False
    assert signed["defaultInputModes"] == ["text/plain"] == signed["defaultOutputModes"]
    assert [s["id"] for s in signed["skills"]] == ["vouch-protocol-qa"]
    credential = signed["vouchCredential"]
    assert credential["issuer"] == DID
    assert credential["credentialSubject"]["intent"]["target"] == signed["url"]
    ok, _ = verify_agent_card(signed, public_key=_resolve(wired).get_ed25519_public_key())
    assert ok


def test_agent_card_validity_is_ninety_days(sidecar_key: str) -> None:
    from datetime import datetime

    cred = sidecar._state["card"]["vouchCredential"]
    start = datetime.fromisoformat(cred["validFrom"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(cred["validUntil"].replace("Z", "+00:00"))
    assert (end - start).total_seconds() == card.CARD_VALID_SECONDS


def test_edited_agent_card_fails(wired: TestClient) -> None:
    signed = wired.get("/.well-known/agent-card.json").json()
    key = _resolve(wired).get_ed25519_public_key()
    forged = copy.deepcopy(signed)
    forged["vouchCredential"]["credentialSubject"]["intent"]["target"] = "https://evil.example/a2a"
    ok, _ = verify_agent_card(forged, public_key=key)
    assert not ok


def test_agent_card_is_404_when_no_sidecar(
    wired: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def down() -> dict[str, Any]:
        raise signer.SignerError("sidecar unreachable")

    monkeypatch.setattr(signer, "agent_card", down)
    assert wired.get("/.well-known/agent-card.json").status_code == 404


def test_root_reports_the_did_and_the_new_endpoints(wired: TestClient) -> None:
    root = wired.get("/").json()
    assert root["agent_did"] == main.CONFIG.agent_did
    assert "/a2a" in root["endpoints"] and "/.well-known/agent-card.json" in root["endpoints"]
