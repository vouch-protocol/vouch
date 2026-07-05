"""The Vouch part: a thin MCP client to the signing sidecar.

This is the *entire* integration surface an agent needs. The agent process
never imports a private key, never touches signing code, and never links the
Vouch SDK. It holds one handle to this sidecar and calls ``sign`` / ``verify``
over the Model Context Protocol.

The sidecar itself is the published ``vouch-mcp`` server, run as a separate
child process. The private key is placed in that child's environment and stays
there. A prompt-injected model in the agent process cannot exfiltrate a key it
never holds.

Everything below is protocol plumbing you write once. Compare its size to
``agent.py`` to see the real integration cost.
"""

from __future__ import annotations

import os
import sys
from contextlib import AsyncExitStack
from typing import Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class VouchSidecar:
    """An async handle to a Vouch signing sidecar spoken to over MCP (stdio).

    Use as an async context manager. On enter it launches the ``vouch-mcp``
    server as a child process with the private key in *that* process's
    environment, then opens an MCP session to it.
    """

    def __init__(self, private_key_jwk: str, did: str) -> None:
        # These are handed to the child process only. The agent code that
        # imports this class receives a VouchSidecar instance, never these.
        self._private_key_jwk = private_key_jwk
        self._did = did
        self._stack: Optional[AsyncExitStack] = None
        self._session: Optional[ClientSession] = None

    async def __aenter__(self) -> "VouchSidecar":
        # The key lives only in the child's env. We inherit the parent env so
        # the child can find Python and the vouch package, then add the secret.
        child_env = {
            **os.environ,
            "VOUCH_PRIVATE_KEY": self._private_key_jwk,
            "VOUCH_DID": self._did,
        }
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "vouch.integrations.mcp.server"],
            env=child_env,
        )
        self._stack = AsyncExitStack()
        # Send the child's server logs to nowhere so the demo output stays clean.
        errlog = open(os.devnull, "w")
        self._stack.callback(errlog.close)
        read, write = await self._stack.enter_async_context(
            stdio_client(params, errlog=errlog)
        )
        self._session = await self._stack.enter_async_context(
            ClientSession(read, write)
        )
        await self._session.initialize()
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None
            self._session = None

    async def _call(self, tool: str, **args: object) -> str:
        assert self._session is not None, "sidecar not started"
        result = await self._session.call_tool(tool, args)
        parts = getattr(result, "content", None) or []
        for part in parts:
            text = getattr(part, "text", None)
            if text is not None:
                return text
        return str(result)

    # ---- the four calls an agent actually makes ------------------------------

    async def get_identity(self) -> str:
        """This agent's DID, per the sidecar."""
        return await self._call("get_identity")

    async def sign(
        self,
        action: str,
        target: str,
        resource: Optional[str] = None,
        post_quantum: bool = False,
    ) -> str:
        """Sign one intent. Returns a Vouch Credential as compact JSON."""
        args: dict = {"action": action, "target": target}
        if resource is not None:
            args["resource"] = resource
        if post_quantum:
            args["post_quantum"] = True
        return await self._call("sign", **args)

    async def verify(self, credential_json: str, public_key: Optional[str] = None) -> str:
        """Verify a credential someone presented. Returns a readable verdict."""
        args: dict = {"credential_json": credential_json}
        if public_key is not None:
            args["public_key"] = public_key
        return await self._call("verify", **args)

    async def create_session(self, purpose: str, valid_seconds: int = 3600) -> str:
        """Issue a trust-decaying session voucher (Heartbeat Protocol)."""
        return await self._call(
            "create_session", purpose=purpose, valid_seconds=valid_seconds
        )
