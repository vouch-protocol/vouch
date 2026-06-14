"""
Vouch Protocol MCP Server.

A Model Context Protocol server, built on the official MCP Python SDK
(FastMCP), that lets MCP-compatible clients (Claude Desktop, Cursor, ...)
issue v1.0 Vouch Credentials to authorize sensitive actions.

Replaces the earlier hand-rolled JSON-RPC loop and the legacy JWS signing
path. Credentials now carry an eddsa-jcs-2022 Data Integrity proof.

Run:
    VOUCH_PRIVATE_KEY=... VOUCH_DID=... vouch-mcp
"""

from __future__ import annotations

import os
from typing import Optional

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The Vouch MCP server requires the MCP SDK. Install it with:\n"
        "    pip install 'vouch-protocol[mcp]'\n"
        "or\n"
        "    pip install mcp\n"
        f"(import error: {exc})"
    )

from vouch.integrations._common import load_signer, sign_tool_call_json


mcp = FastMCP("vouch")


def _did() -> str:
    return os.getenv("VOUCH_DID", "(not configured)")


@mcp.tool()
def sign_action(action: str, target: str, resource: Optional[str] = None) -> str:
    """Issue a Vouch Credential authorizing a single sensitive action.

    Call this before any authenticated request to an external service.

    Args:
        action: The verb, e.g. 'read', 'write', 'execute', 'send'.
        target: The service or URL being called.
        resource: The specific object, e.g. 'customer:123'. Defaults to target.

    Returns:
        A compact JSON Vouch Credential to attach as a 'Vouch-Credential' header.
    """
    try:
        signer = load_signer()
        return sign_tool_call_json(signer, action, target, resource)
    except Exception as e:
        return f"Error issuing Vouch Credential: {e}"


@mcp.tool()
def create_session(purpose: str, valid_seconds: int = 3600) -> str:
    """Issue a longer-lived session credential covering multiple actions.

    Args:
        purpose: What the session is for, e.g. 'calendar_access'.
        valid_seconds: Session lifetime in seconds (default 3600).

    Returns:
        A compact JSON session credential.
    """
    try:
        signer = load_signer()
        return sign_tool_call_json(
            signer, "session", purpose, f"session:{purpose}", valid_seconds=valid_seconds
        )
    except Exception as e:
        return f"Error creating session: {e}"


@mcp.tool()
def get_identity() -> str:
    """Return the agent's DID (Decentralized Identifier)."""
    return f"Agent DID: {_did()}"


def main() -> None:
    """Entry point: run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
