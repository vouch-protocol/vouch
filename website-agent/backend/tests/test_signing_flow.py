"""End-to-end tests for the signed action flow, sidecar policy, and proposals.

The sidecar app runs in-process behind an ASGI transport, so these tests use
real keys and real signatures with no network.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from vouch import Verifier, generate_identity

from vouch_agent import actions, sidecar, signer

DID = "did:web:vouch-protocol.com:assistant"


@pytest.fixture()
def sidecar_key() -> str:
    key = generate_identity().private_key_jwk
    sidecar.configure(DID, key, sidecar.DEFAULT_RESOURCE_PREFIX, "test")
    return key


@pytest.fixture()
def wired(monkeypatch: pytest.MonkeyPatch, sidecar_key: str, tmp_path: Path) -> TestClient:
    """The chat app with its sidecar client routed to the in-process sidecar."""
    real_client = httpx.AsyncClient

    def client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("timeout", None)
        return real_client(
            transport=httpx.ASGITransport(app=sidecar.app), base_url="http://sidecar"
        )

    from dataclasses import replace

    from vouch_agent import audit, main

    config = replace(
        signer.CONFIG, sidecar_url="http://sidecar", audit_log_path=tmp_path / "audit.jsonl"
    )
    monkeypatch.setattr(signer.httpx, "AsyncClient", client)
    monkeypatch.setattr(signer, "CONFIG", config)
    monkeypatch.setattr(audit, "CONFIG", config)
    return TestClient(main.app)


def _did_key(document: dict[str, Any]) -> Any:
    return signer._public_key_from_document(document, None)


# ---------------------------------------------------------------- sidecar policy


@pytest.mark.parametrize(
    "intent",
    [
        {"action": "send_email", "target": "x", "resource": "https://vouch-protocol.com/ask"},
        {"action": "transfer_funds", "target": "x", "resource": "https://vouch-protocol.com/ask"},
        {"action": "sign_sample", "target": "x", "resource": "https://evil.example/ask"},
        {
            "action": "sign_sample",
            "target": "x",
            "resource": "https://vouch-protocol.com.evil.example/",
        },
        {"action": "sign_sample", "target": "", "resource": "https://vouch-protocol.com/ask"},
        {"action": "sign_sample", "target": 7, "resource": "https://vouch-protocol.com/ask"},
        {
            "action": "sign_sample",
            "target": "x",
            "resource": "https://vouch-protocol.com/ask",
            "pad": "a" * 5000,
        },
    ],
)
def test_sidecar_refuses_intents_outside_policy(sidecar_key: str, intent: dict[str, Any]) -> None:
    client = TestClient(sidecar.app)
    resp = client.post("/sign", json={"intent": intent})
    assert resp.status_code == 403


@pytest.mark.parametrize("seconds", [0, 5, 3601, 86400])
def test_sidecar_refuses_out_of_range_validity(sidecar_key: str, seconds: int) -> None:
    client = TestClient(sidecar.app)
    intent = {"action": "sign_sample", "target": "x", "resource": "https://vouch-protocol.com/ask"}
    resp = client.post("/sign", json={"intent": intent, "valid_seconds": seconds})
    assert resp.status_code == 422


def test_sidecar_document_matches_signing_key(sidecar_key: str) -> None:
    client = TestClient(sidecar.app)
    document = client.get("/did-document").json()
    assert document["id"] == DID
    assert document["verificationMethod"][0]["type"] == "Multikey"
    intent = {"action": "sign_sample", "target": "x", "resource": "https://vouch-protocol.com/ask"}
    credential = client.post("/sign", json={"intent": intent}).json()
    ok, _ = Verifier.verify(credential, public_key=_did_key(document))
    assert ok


def test_sidecar_refuses_to_start_without_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(sidecar.SIGNING_KEY_ENV, raising=False)
    with pytest.raises(SystemExit):
        sidecar.main([])


def test_sidecar_rejects_a_public_only_key() -> None:
    public_only = json.loads(generate_identity().public_key_jwk)
    with pytest.raises(ValueError):
        sidecar.configure(DID, json.dumps(public_only), sidecar.DEFAULT_RESOURCE_PREFIX, "test")


def test_sidecar_takes_the_key_out_of_its_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    monkeypatch.setenv(sidecar.SIGNING_KEY_ENV, generate_identity().private_key_jwk)
    monkeypatch.setattr(sidecar.uvicorn, "run", lambda *a, **k: None)
    sidecar.main([])
    assert sidecar.SIGNING_KEY_ENV not in os.environ


# ---------------------------------------------------------------- /act


def test_act_generate_starter_returns_verified_credential_bound_to_files(wired: TestClient) -> None:
    resp = wired.post("/act", json={"action": "generate_starter", "params": {"language": "python"}})
    assert resp.status_code == 200
    body = resp.json()
    credential, files = body["credential"], body["result"]["files"]
    assert body["verified"] is True
    assert credential["issuer"] == DID

    intent = credential["credentialSubject"]["intent"]
    assert intent["action"] == "generate_starter"
    expected = "sha256:" + hashlib.sha256(actions.bundle_for_digest(files).encode()).hexdigest()
    assert intent["outputDigest"] == expected

    document = wired.get("/.well-known/did.json").json()
    ok, _ = Verifier.verify(credential, public_key=_did_key(document))
    assert ok


def test_starter_files_changed_after_signing_no_longer_match(wired: TestClient) -> None:
    body = wired.post(
        "/act", json={"action": "generate_starter", "params": {"language": "typescript"}}
    ).json()
    files = dict(body["result"]["files"])
    files["main.ts"] += "\nconsole.log('injected');\n"
    tampered = "sha256:" + hashlib.sha256(actions.bundle_for_digest(files).encode()).hexdigest()
    assert tampered != body["credential"]["credentialSubject"]["intent"]["outputDigest"]


def test_act_tampered_credential_fails_verification(wired: TestClient) -> None:
    body = wired.post("/act", json={"action": "sign_sample"}).json()
    document = wired.get("/.well-known/did.json").json()
    forged = copy.deepcopy(body["credential"])
    forged["credentialSubject"]["intent"]["action"] = "generate_starter"
    ok, _ = Verifier.verify(forged, public_key=_did_key(document))
    assert not ok


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "send_email"},
        {"action": "open_github_issue"},
        {"action": "generate_starter", "params": {"language": "rust"}},
        {"action": "generate_starter"},
    ],
)
def test_act_rejects_unknown_actions_and_params(wired: TestClient, payload: dict[str, Any]) -> None:
    assert wired.post("/act", json=payload).status_code == 400


def test_act_cannot_choose_the_resource(wired: TestClient) -> None:
    body = wired.post(
        "/act",
        json={"action": "sign_sample", "params": {"resource": "https://evil.example/"}},
    ).json()
    assert (
        body["credential"]["credentialSubject"]["intent"]["resource"] == f"{actions.ASK_URL}#sample"
    )


def test_public_sign_endpoint_is_gone(wired: TestClient) -> None:
    intent = {"action": "sign_sample", "target": "x", "resource": "https://vouch-protocol.com/ask"}
    assert wired.post("/sign", json={"intent": intent}).status_code in (404, 405)


def test_act_withholds_output_when_signing_is_down(
    wired: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def down(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise signer.SignerError("sidecar unreachable")

    monkeypatch.setattr(signer, "sign_intent", down)
    resp = wired.post("/act", json={"action": "generate_starter", "params": {"language": "python"}})
    assert resp.status_code == 503
    assert "result" not in resp.json()


def test_act_withholds_output_when_sidecar_signs_a_different_intent(
    wired: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = signer.sign_intent

    async def swapped(intent: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        other = dict(intent, target="starter:other")
        return await real(other, **kwargs)

    monkeypatch.setattr(signer, "sign_intent", swapped)
    resp = wired.post("/act", json={"action": "sign_sample"})
    assert resp.status_code == 503


def test_act_withholds_output_when_issuer_is_not_the_agent(
    wired: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vouch import Signer

    stranger = generate_identity()

    async def foreign(intent: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return Signer(private_key=stranger.private_key_jwk, did="did:web:evil.example").sign(
            intent=intent
        )

    monkeypatch.setattr(signer, "sign_intent", foreign)
    assert wired.post("/act", json={"action": "sign_sample"}).status_code == 503


def test_act_withholds_output_when_key_differs_from_did_document(
    wired: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vouch import Signer

    impostor = generate_identity()

    async def wrong_key(intent: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return Signer(private_key=impostor.private_key_jwk, did=DID).sign(intent=intent)

    monkeypatch.setattr(signer, "sign_intent", wrong_key)
    assert wired.post("/act", json={"action": "sign_sample"}).status_code == 503


# ---------------------------------------------------------------- /chat


def _events(body: str) -> list[tuple[str, dict[str, Any]]]:
    out = []
    for block in body.strip().split("\n\n"):
        lines = block.split("\n")
        name = lines[0].removeprefix("event: ")
        out.append((name, json.loads(lines[1].removeprefix("data: "))))
    return out


def _fake_llm(monkeypatch: pytest.MonkeyPatch, reply: str) -> None:
    from vouch_agent import main

    async def stream(message: str, retrieved: Any) -> Any:
        for piece in (reply[: len(reply) // 2], reply[len(reply) // 2 :]):
            yield piece

    monkeypatch.setattr(main, "stream_answer", stream)


def test_chat_reply_is_signed_over_its_exact_text(
    wired: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    reply = "A did:web resolves over HTTPS.\n---ACTION--- generate_starter typescript\n---FOLLOWUPS---\n- How?\n- Why?\n- When?"
    _fake_llm(monkeypatch, reply)
    events = dict(_events(wired.post("/chat", json={"message": "what is did:web"}).text))

    assert events["action"] == {
        "action": "generate_starter",
        "params": {"language": "typescript"},
        "label": "Sign and generate a TypeScript starter",
    }
    signed = events["credential"]
    assert "---ACTION---" not in signed["signed_text"]
    assert "---FOLLOWUPS---" not in signed["signed_text"]
    intent = signed["credential"]["credentialSubject"]["intent"]
    assert intent["action"] == "answer_question"
    assert intent["outputDigest"] == signer.digest(signed["signed_text"])
    assert intent["outputDigest"] != signer.digest(signed["signed_text"] + " (edited)")


def test_chat_still_answers_when_signing_is_down(
    wired: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_llm(monkeypatch, "Plain answer.")

    async def down(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise signer.SignerError("sidecar unreachable")

    monkeypatch.setattr(signer, "sign_intent", down)
    names = [name for name, _ in _events(wired.post("/chat", json={"message": "hi"}).text)]
    assert "token" in names and "done" in names
    assert "credential" not in names


# ---------------------------------------------------------------- proposals


def test_extract_proposal_strips_marker_line() -> None:
    text = "Sure, I can make one.\n---ACTION--- generate_starter python\n---FOLLOWUPS---\n- a"
    proposal, cleaned = actions.extract_proposal(text)
    assert proposal is not None
    assert proposal.action == "generate_starter"
    assert proposal.params == {"language": "python"}
    assert "---ACTION---" not in cleaned
    assert "---FOLLOWUPS---" in cleaned


@pytest.mark.parametrize(
    "text",
    [
        "---ACTION--- send_email me@example.com",
        "---ACTION--- generate_starter rust",
        "no marker here",
        "---ACTION--- generate_starter",
    ],
)
def test_extract_proposal_ignores_anything_off_the_list(text: str) -> None:
    proposal, _ = actions.extract_proposal(text)
    assert proposal is None


def test_starter_verify_helper_matches_server_digest(tmp_path: Path) -> None:
    files = actions.starter_files("python")
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    names = sorted(files)
    bundle = "".join(f"{n}\n{(tmp_path / n).read_text(encoding='utf-8')}\n" for n in names)
    assert bundle == actions.bundle_for_digest(files)
    assert repr(names) in files["verify_assistant.py"]


def test_did_document_flag_prints_public_document_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key = generate_identity().private_key_jwk
    monkeypatch.setenv(sidecar.SIGNING_KEY_ENV, key)
    sidecar.main(["--did-document"])
    out = capsys.readouterr().out
    document = json.loads(out)
    assert document["id"] == DID
    assert json.loads(key)["d"] not in out
    assert '"d"' not in out


def test_app_did_json_is_404_when_no_sidecar(
    wired: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def down() -> dict[str, Any]:
        raise signer.SignerError("sidecar unreachable")

    monkeypatch.setattr(signer, "did_document", down)
    assert wired.get("/.well-known/did.json").status_code == 404
