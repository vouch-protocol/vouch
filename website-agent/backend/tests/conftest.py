"""Shared fixtures: the chat app wired to an in-process signing sidecar."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from vouch import generate_identity

from vouch_agent import sidecar, signer

DID = "did:web:agent.vouch-protocol.com"


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
