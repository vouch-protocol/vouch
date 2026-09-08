"""Vouch-protected MCP servers: change one import, every tool checks first.

``vouch.mcp.FastMCP`` is a drop-in replacement for the MCP SDK's ``FastMCP`` in
which **every registered tool is protected by default**::

    from vouch.mcp import FastMCP          # was: from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("crm-tools")

    @mcp.tool()
    def run_query(table: str, where: str) -> list[dict]:   # protected
        ...

    @mcp.tool(unprotected=True)                            # explicit opt-out
    def health() -> str:
        ...

A protected tool gains a required ``credential`` argument. Before its body runs,
the credential is verified, checked against the trusted issuer list, confirmed to
authorise *this exact call*, and put to Shield. Any failure returns a structured
refusal and the body never runs.

This is the receiving side. Note that ``vouch.protect`` (in ``vouch.autosign``)
is the *sending* side: it sign-wraps outbound tool calls. Same word, opposite
direction.

Configuration comes from the environment and is required:

===========================  ==========================================
``VOUCH_RULES``              Path to the Shield v2 rules file
``VOUCH_TRUSTED_ISSUERS``    Comma-separated DIDs whose credentials count
``VOUCH_TARGET``             ``intent.target`` to require (default: server name)
``VOUCH_CHECK_REVOCATION``   ``0`` to skip status-list lookups (default on)
===========================  ==========================================

A server missing required configuration **refuses to start**. It never starts
unprotected.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from ._guard import (
    CREDENTIAL_ARG,
    GuardConfig,
    Refusal,
    ToolGuard,
    VouchMcpConfigError,
    compute_resource,
)

logger = logging.getLogger(__name__)

try:
    from mcp.server.fastmcp import FastMCP as _BaseFastMCP
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "vouch.mcp needs the MCP SDK. Install it with:\n"
        "    pip install 'vouch-protocol[mcp]'\n"
        "or\n"
        "    pip install mcp\n"
        f"(import error: {exc})"
    ) from exc


__all__ = [
    "FastMCP",
    "protect",
    "GuardConfig",
    "Refusal",
    "ToolGuard",
    "VouchMcpConfigError",
    "compute_resource",
    "CREDENTIAL_ARG",
]


class FastMCP(_BaseFastMCP):
    """An MCP server whose tools are protected by default.

    A thin subclass. The constructor takes everything the SDK's ``FastMCP``
    takes; ``tool()`` takes everything the SDK's ``tool()`` takes plus
    ``unprotected`` and ``resource``. Registration, schema generation, and
    dispatch all stay with the SDK.

    Args:
        *args, **kwargs: passed straight to the SDK's ``FastMCP``.
        rules_path: overrides ``VOUCH_RULES``.
        trusted_issuers: overrides ``VOUCH_TRUSTED_ISSUERS``.
        target: overrides ``VOUCH_TARGET``.
        guard: a preconfigured :class:`ToolGuard`, mainly for tests.
    """

    def __init__(
        self,
        *args: Any,
        rules_path: Optional[str] = None,
        trusted_issuers: Optional[Any] = None,
        target: Optional[str] = None,
        guard: Optional[ToolGuard] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        if guard is not None:
            self._vouch_guard = guard
        else:
            env_overrides: Dict[str, str] = {}
            if rules_path:
                env_overrides["VOUCH_RULES"] = rules_path
            if trusted_issuers:
                issuers = (
                    trusted_issuers
                    if isinstance(trusted_issuers, str)
                    else ",".join(trusted_issuers)
                )
                env_overrides["VOUCH_TRUSTED_ISSUERS"] = issuers
            if target:
                env_overrides["VOUCH_TARGET"] = target

            import os

            merged = dict(os.environ)
            merged.update(env_overrides)
            config = GuardConfig.from_env(server_name=self.name, env=merged)
            self._vouch_guard = ToolGuard(config)

        logger.info(
            "Vouch: protecting '%s' (target=%s, rules=%s, issuers=%d)",
            self.name,
            self._vouch_guard.config.target,
            self._vouch_guard.config.rules_path,
            len(self._vouch_guard.config.trusted_issuers),
        )

    @property
    def vouch_guard(self) -> ToolGuard:
        """The guard deciding this server's calls."""
        return self._vouch_guard

    def tool(  # type: ignore[override]
        self,
        *args: Any,
        unprotected: bool = False,
        resource: Optional[Callable[[Dict[str, Any]], str]] = None,
        **kwargs: Any,
    ) -> Callable[[Any], Any]:
        """Register a tool. Protected unless ``unprotected=True``.

        Args:
            unprotected: skip protection entirely. Logs a WARNING when the tool
                is registered and on every call, because an unprotected tool on
                a protected server is a decision someone should be able to see
                in the logs.
            resource: a callable mapping the argument dict to the resource
                string. Without it the resource is the JCS canonicalisation of
                all arguments, so a credential authorises exactly one call with
                exactly those arguments. Supplying it is a deliberate loosening
                of that binding, and a policy decision the tool author is
                making.
            *args, **kwargs: passed to the SDK's ``tool()``.
        """
        if unprotected and resource is not None:
            raise ValueError("resource= has no meaning on an unprotected tool")

        base_decorator = super().tool(*args, **kwargs)
        guard = self._vouch_guard

        def decorator(fn: Any) -> Any:
            tool_name = kwargs.get("name") or (args[0] if args else None) or fn.__name__

            if unprotected:
                logger.warning(
                    "Vouch: tool '%s' is registered UNPROTECTED; calls to it are not checked",
                    tool_name,
                )
                return base_decorator(_warn_on_call(fn, tool_name))

            wrapped = guard.wrap(fn, tool_name=tool_name, resource_fn=resource)
            return base_decorator(wrapped)

        return decorator


def _warn_on_call(fn: Any, tool_name: str) -> Any:
    """Wrap an unprotected tool so every call says so in the log."""
    import functools
    import inspect

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            logger.warning("Vouch: UNPROTECTED call to '%s'", tool_name)
            return await fn(*args, **kwargs)

    else:

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            logger.warning("Vouch: UNPROTECTED call to '%s'", tool_name)
            return fn(*args, **kwargs)

    wrapper.__vouch_protected__ = False
    return wrapper


def protect(server: Any, *, guard: Optional[ToolGuard] = None, **config: Any) -> Any:
    """Protect an already-built server's tool dispatch.

    The secondary API, for people not using ``FastMCP``. Same five steps and the
    same refusals; the difference is that this cannot add a ``credential``
    parameter to a schema it does not own, so the credential is read from the
    call's arguments if the tool already accepts one.

    Prefer :class:`FastMCP` where you can: a wrapper someone has to remember to
    apply is a wrapper someone will forget.
    """
    if guard is None:
        import os

        merged = dict(os.environ)
        for key, value in config.items():
            if value is not None:
                merged[f"VOUCH_{key.upper()}"] = (
                    value if isinstance(value, str) else ",".join(value)
                )
        name = getattr(server, "name", "mcp")
        guard = ToolGuard(GuardConfig.from_env(server_name=name, env=merged))

    original = getattr(server, "call_tool", None)
    if original is None:
        raise TypeError(
            f"{type(server).__name__} has no call_tool to wrap; use vouch.mcp.FastMCP instead"
        )

    async def guarded_call_tool(name: str, arguments: Dict[str, Any], *rest: Any, **kw: Any):
        refusal = guard.check(name, dict(arguments or {}))
        if refusal is not None:
            return refusal.to_dict()
        stripped = {k: v for k, v in (arguments or {}).items() if k != CREDENTIAL_ARG}
        result = original(name, stripped, *rest, **kw)
        if hasattr(result, "__await__"):
            return await result
        return result

    server.call_tool = guarded_call_tool  # type: ignore[assignment]
    server.vouch_guard = guard  # type: ignore[attr-defined]
    return server
