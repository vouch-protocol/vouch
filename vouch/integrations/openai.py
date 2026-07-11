"""
Vouch Protocol OpenAI Integration.

Sign the tool (function) calls an OpenAI agent makes with Vouch Credentials, so
every action an OpenAI-driven agent takes carries a verifiable identity. This
works with the OpenAI Python SDK function calling (Chat Completions and the
Responses API) and with the OpenAI Agents SDK, because all of them dispatch to
Python tool callables and expose a tool call as a name plus JSON arguments.

Two entry points:

- :func:`sign_tool_call` signs the model's requested tool call (a name plus its
  JSON arguments) before you dispatch it, giving you a credential to attach to
  the result or to log.
- :func:`signed_tool` and :func:`protect` wrap the Python tool callables you
  dispatch to, so each execution issues its own Vouch Credential.

Neither imports the OpenAI SDK, so the core package carries no extra dependency;
the standalone ``vouch-openai`` package declares ``openai`` for you.
"""

from __future__ import annotations

import functools
import json
from typing import Any, Callable, List, Optional, Sequence, Tuple

from vouch import Signer
from vouch.autosign import sign_intent
from vouch.verifier import verify as _verify_credential

__all__ = ["protect", "signed_tool", "sign_tool_call", "verify_tool_call"]

_TARGET = "openai:tool"


def signed_tool(
    fn: Optional[Callable[..., Any]] = None,
    *,
    signer: Optional[Signer] = None,
    action: Optional[str] = None,
    resource: Optional[str] = None,
) -> Callable[..., Any]:
    """Wrap an OpenAI tool (a Python callable) so each execution is signed.

    Use as a decorator on a function tool. The credential records the tool
    running, under the function name unless ``action`` is given, and binds the
    call arguments. The tool runs whether or not an identity is resolved; when
    none is, signing is skipped and the call proceeds unsigned.

    Example::

        from vouch.integrations.openai import signed_tool

        @signed_tool
        def get_weather(city: str) -> str: ...

        @signed_tool(action="charge_card")
        def bill(amount: int) -> str: ...
    """

    def decorate(func: Callable[..., Any]) -> Callable[..., Any]:
        tool_action = action or getattr(func, "__name__", "tool")
        res = resource or f"{_TARGET}:{tool_action}"

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            sign_intent(
                tool_action,
                target=_TARGET,
                resource=res,
                signer=signer,
                extra={"arguments": _json_safe(kwargs)},
            )
            return func(*args, **kwargs)

        wrapper.__vouch_signed__ = True
        return wrapper

    if fn is not None:
        return decorate(fn)
    return decorate


def protect(
    tools: Sequence[Any],
    *,
    signer: Optional[Signer] = None,
    **signed_kwargs: Any,
) -> List[Any]:
    """Sign-wrap a list of OpenAI function-tool callables.

    Each plain callable is wrapped so every invocation is signed. Anything that
    is already signed, or is not callable, is returned unchanged.

    Example::

        from vouch.integrations.openai import protect

        tools = protect([get_weather, send_email])
    """
    out: List[Any] = []
    for t in tools:
        if callable(t) and not getattr(t, "__vouch_signed__", False):
            out.append(signed_tool(t, signer=signer, **signed_kwargs))
        else:
            out.append(t)
    return out


def sign_tool_call(
    tool_call: Any,
    *,
    signer: Optional[Signer] = None,
    resource: Optional[str] = None,
    publish: bool = True,
) -> Optional[dict]:
    """Sign the model's requested tool call and return a Vouch Credential.

    Accepts the OpenAI SDK tool-call object (``tool_call.function.name`` and
    ``tool_call.function.arguments``) or the equivalent dict shape. The
    credential binds the action to the tool name and to the arguments the model
    asked to run with.

    Example::

        for call in message.tool_calls:
            credential = sign_tool_call(call)
            result = dispatch(call)
    """
    name, arguments = _extract(tool_call)
    res = resource or f"{_TARGET}:{name}"
    return sign_intent(
        name,
        target=_TARGET,
        resource=res,
        signer=signer,
        extra={"arguments": arguments},
        publish=publish,
    )


def verify_tool_call(credential: Any, *, public_key: Any = None):
    """Verify a signed tool-call credential. Returns ``(is_valid, passport)``.

    With no ``public_key`` the issuer key is resolved from the credential's DID.
    """
    return _verify_credential(credential, public_key=public_key)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract(tool_call: Any) -> Tuple[str, Any]:
    """Pull (name, arguments) from an OpenAI tool call object or dict."""
    fn = getattr(tool_call, "function", None)
    if fn is None and isinstance(tool_call, dict):
        fn = tool_call.get("function", tool_call)
    if fn is None:
        raise ValueError("tool_call has no function payload")

    if isinstance(fn, dict):
        name = fn.get("name")
        raw_args = fn.get("arguments")
    else:
        name = getattr(fn, "name", None)
        raw_args = getattr(fn, "arguments", None)

    if not name:
        raise ValueError("tool_call is missing a function name")
    return name, _parse_args(raw_args)


def _parse_args(raw: Any) -> Any:
    """OpenAI passes tool arguments as a JSON string; normalize to a value."""
    if raw is None:
        return {}
    if isinstance(raw, (dict, list)):
        return _json_safe(raw)
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return {"_raw": raw}
    return {"_raw": str(raw)}


def _json_safe(value: Any) -> Any:
    """Return value unchanged if JSON-serializable, else a stringified form."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        if isinstance(value, dict):
            return {k: str(v) for k, v in value.items()}
        return str(value)
