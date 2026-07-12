"""
One-line verification guards for tool servers (MCP and other frameworks).

On the sending side, ``vouch.protect`` / ``@vouch.signed`` make an agent sign
every tool call. On the receiving side, a tool server has to verify those
credentials before it runs anything. ``CredentialGate`` / ``VouchGate`` cover
HTTP endpoints; this module covers in-process tool functions:

    @vouch.require_signed(trusted_dids=["did:web:agent.example"])
    def write_file(path, content, *, vouch_credential): ...

    server = vouch.guard_mcp(server, trusted_dids=["did:web:agent.example"])

Both verify the credential's Data Integrity proof, enforce an issuer allowlist
(``trusted_dids``), and optionally match the intent (``require_action`` /
``require_target`` / ``require_resource``) before the tool body runs. A call
that is unsigned, forged, from an untrusted issuer, or intent-mismatched is
rejected with ``PermissionError`` (configurable).

Security boundary: the guard authenticates the *caller* (a valid signature from
a trusted issuer) and, when configured, that the declared intent matches the
route. It does NOT by itself bind the credential to the specific argument values
of this call, and it does NOT provide replay protection; pair it with intent
policy and the nonce tracker (``vouch.MemoryNonceTracker``) when those matter.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict, List, Optional, Sequence

from vouch.gate import CredentialGate

# Default keyword the guard reads the inbound credential from. A signed caller
# (or the transport shim) passes the credential under this name.
DEFAULT_CREDENTIAL_ARG = "vouch_credential"
PASSPORT_INJECT_ARG = "vouch_passport"


def require_signed(
    trusted_dids: Optional[Any] = None,
    *,
    public_key: Optional[Any] = None,
    trusted_keys: Optional[Dict[str, str]] = None,
    allow_did_resolution: bool = True,
    require_action: Optional[str] = None,
    require_target: Optional[str] = None,
    require_resource: Optional[str] = None,
    credential_arg: str = DEFAULT_CREDENTIAL_ARG,
    pass_credential: bool = False,
    inject_passport: bool = False,
    on_reject: str = "raise",
):
    """Decorator: require a valid Vouch credential before a tool runs.

    Usable as a factory (the normal form)::

        @require_signed(trusted_dids=["did:web:agent.example"])
        def write_file(path, content, *, vouch_credential): ...

    or bare (no issuer allowlist, signature still required)::

        @require_signed
        def read_file(path, *, vouch_credential): ...

    The credential is read from the ``credential_arg`` keyword (default
    ``vouch_credential``). On success the keyword is removed before the tool is
    called, unless ``pass_credential=True``; with ``inject_passport=True`` the
    verified passport is passed as ``vouch_passport``.

    Args:
      trusted_dids: allowed issuer DIDs. None allows any issuer whose key
        verifies (signature still required).
      public_key / trusted_keys / allow_did_resolution: key-resolution options,
        forwarded to :class:`~vouch.gate.CredentialGate`.
      require_action / require_target / require_resource: exact intent policy.
      credential_arg: keyword the credential arrives under.
      pass_credential: keep the credential keyword when calling the tool.
      inject_passport: pass the verified passport as ``vouch_passport``.
      on_reject: ``"raise"`` (default) raises ``PermissionError``; ``"none"``
        returns None without running the tool.
    """
    gate = CredentialGate(
        public_key=public_key,
        trusted_keys=trusted_keys,
        allow_did_resolution=allow_did_resolution,
        require_action=require_action,
        require_target=require_target,
        require_resource=require_resource,
    )

    # Bare-decorator support: @require_signed with no parentheses passes the
    # decorated function in as `trusted_dids`.
    bare_func: Optional[Callable] = None
    allow: Optional[set] = None
    if callable(trusted_dids):
        bare_func = trusted_dids
    elif trusted_dids is not None:
        allow = set(trusted_dids)

    def decorate(func: Callable) -> Callable:
        # Keep the credential keyword only if the tool actually wants it; strip
        # it otherwise so a plain tool signature is not broken by the extra arg.
        keep_credential = pass_credential or _accepts_kwarg(func, credential_arg)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            credential = kwargs.get(credential_arg)
            result = gate.check(credential)

            reason: Optional[str] = None
            if not result.ok or result.passport is None:
                reason = result.reason or "unsigned or invalid credential"
            elif allow is not None and result.passport.issuer not in allow:
                reason = f"issuer {result.passport.issuer!r} is not in trusted_dids"

            if reason is not None:
                if on_reject == "none":
                    return None
                raise PermissionError(f"Vouch guard rejected call to {_name(func)}: {reason}")

            if not keep_credential:
                kwargs.pop(credential_arg, None)
            if inject_passport:
                kwargs[PASSPORT_INJECT_ARG] = result.passport
            return func(*args, **kwargs)

        wrapper.__vouch_guarded__ = True  # type: ignore[attr-defined]
        return wrapper

    if bare_func is not None:
        return decorate(bare_func)
    return decorate


def guard_mcp(server: Any, trusted_dids: Optional[Any] = None, **guard_kwargs: Any) -> Any:
    """Wrap an MCP-style tool server so every registered tool is verified.

    Patches the server's tool-registration entry point so each tool it registers
    is wrapped with :func:`require_signed`. Returns the same server for
    chaining::

        server = vouch.guard_mcp(server, trusted_dids=["did:web:agent.example"])

    Recognized registration hooks, in order: a ``tool`` decorator (FastMCP
    style), ``add_tool``, or ``register_tool`` (each taking the tool function as
    its first positional argument). Tools registered after this call are
    guarded; the credential must reach each tool under the ``vouch_credential``
    argument (see :func:`require_signed`).

    Raises:
      TypeError: if the server exposes none of the recognized hooks. Use the
        per-tool :func:`require_signed` decorator in that case.
    """
    if trusted_dids is not None:
        guard_kwargs.setdefault("trusted_dids", trusted_dids)

    for attr, kind in (
        ("tool", "decorator"),
        ("add_tool", "callable"),
        ("register_tool", "callable"),
    ):
        hook = getattr(server, attr, None)
        if callable(hook):
            if kind == "decorator":
                _patch_decorator_hook(server, attr, guard_kwargs)
            else:
                _patch_callable_hook(server, attr, guard_kwargs)
            return server

    raise TypeError(
        "guard_mcp could not find a tool-registration hook (tool/add_tool/"
        "register_tool) on the server. Use the @vouch.require_signed decorator "
        "on each tool instead."
    )


def guard_tools(
    tools: Sequence[Callable], trusted_dids: Optional[Any] = None, **guard_kwargs: Any
) -> List[Callable]:
    """Wrap a list of plain tool callables with :func:`require_signed`.

    The framework-agnostic counterpart to :func:`guard_mcp` for servers whose
    tools are just a list of functions::

        guarded = vouch.guard_tools([read_file, write_file],
                                    trusted_dids=["did:web:agent.example"])
    """
    decorator = require_signed(trusted_dids, **guard_kwargs)
    out: List[Callable] = []
    for tool in tools:
        if getattr(tool, "__vouch_guarded__", False):
            out.append(tool)
        else:
            out.append(decorator(tool))
    return out


def _patch_decorator_hook(server: Any, attr: str, guard_kwargs: Dict[str, Any]) -> None:
    original = getattr(server, attr)
    if getattr(original, "__vouch_guard_patched__", False):
        return

    @functools.wraps(original)
    def patched(*args: Any, **kwargs: Any) -> Any:
        # Bare use: decorator applied straight to the tool function.
        if len(args) == 1 and not kwargs and callable(args[0]):
            return original(_apply_guard(args[0], guard_kwargs))

        # Factory use: original(...) returns the real decorator; wrap its target.
        decorator = original(*args, **kwargs)

        def wrapping(func: Callable) -> Any:
            return decorator(_apply_guard(func, guard_kwargs))

        return wrapping

    patched.__vouch_guard_patched__ = True  # type: ignore[attr-defined]
    setattr(server, attr, patched)


def _patch_callable_hook(server: Any, attr: str, guard_kwargs: Dict[str, Any]) -> None:
    original = getattr(server, attr)
    if getattr(original, "__vouch_guard_patched__", False):
        return

    @functools.wraps(original)
    def patched(*args: Any, **kwargs: Any) -> Any:
        args_list = list(args)
        if args_list and callable(args_list[0]):
            args_list[0] = _apply_guard(args_list[0], guard_kwargs)
        return original(*args_list, **kwargs)

    patched.__vouch_guard_patched__ = True  # type: ignore[attr-defined]
    setattr(server, attr, patched)


def _apply_guard(func: Callable, guard_kwargs: Dict[str, Any]) -> Callable:
    if getattr(func, "__vouch_guarded__", False):
        return func
    trusted_dids = guard_kwargs.get("trusted_dids")
    kwargs = {k: v for k, v in guard_kwargs.items() if k != "trusted_dids"}
    return require_signed(trusted_dids, **kwargs)(func)


def _accepts_kwarg(func: Callable, name: str) -> bool:
    """True if `func` declares `name` as a parameter or accepts ``**kwargs``."""
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return False
    for p in sig.parameters.values():
        if p.kind == inspect.Parameter.VAR_KEYWORD:
            return True
        if p.name == name:
            return True
    return False


def _name(func: Callable) -> str:
    return getattr(func, "__name__", repr(func))


__all__ = ["require_signed", "guard_mcp", "guard_tools"]
