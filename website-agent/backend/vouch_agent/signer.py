"""Thin client for the Vouch sidecar.

The sidecar holds the agent's signing key. The LLM process never sees
it. This module just shapes intents and proxies signing requests.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import CONFIG

ALLOWED_ACTIONS = {
    "answer_question",
    "generate_starter",
    "open_github_issue",
    "send_email",
    "share_quickstart",
}


class SignerError(RuntimeError):
    pass


def validate_intent(intent: dict[str, Any]) -> None:
    for key in ("action", "target", "resource"):
        if not intent.get(key):
            raise SignerError(f"intent.{key} is required")
    if intent["action"] not in ALLOWED_ACTIONS:
        raise SignerError(f"action {intent['action']!r} not in allow-list")


async def sign_intent(intent: dict[str, Any], *, scope: list[str] | None = None) -> dict[str, Any]:
    validate_intent(intent)
    payload: dict[str, Any] = {"intent": intent}
    if scope is not None:
        payload["scope"] = scope
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{CONFIG.sidecar_url}/sign", json=payload)
        if resp.status_code >= 400:
            raise SignerError(f"sidecar returned {resp.status_code}: {resp.text}")
        return resp.json()


async def sidecar_did() -> str:
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(f"{CONFIG.sidecar_url}/did")
        resp.raise_for_status()
        return resp.json().get("did", CONFIG.agent_did)


async def sidecar_healthy() -> bool:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{CONFIG.sidecar_url}/health")
            return resp.status_code == 200
    except httpx.HTTPError:
        return False
