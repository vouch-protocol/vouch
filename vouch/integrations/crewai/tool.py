"""
Vouch Protocol CrewAI Integration.

Two ways to use it, newest first:

  * ``protect([...])`` / ``@signed`` / ``autosign()`` — deterministic signing.
    Every tool call is signed in Python before it runs, with no prompt and no
    dependence on the model choosing to call a signing tool. This is the
    recommended path. See :mod:`vouch.autosign`.

  * ``sign_request`` — the legacy "ask the LLM to mint a token" tool, kept for
    backward compatibility. Prefer the deterministic path above.
"""

import functools
import os
from typing import Any, List, Optional, Sequence

from vouch import Signer

# Re-export the framework-agnostic primitives so users can write
# `from vouch.integrations.crewai import signed, protect`.
from vouch.autosign import current_credential, sign_intent, signed  # noqa: F401
from vouch.autosign import protect as _protect_callables

try:
    from crewai.tools import tool
except ImportError:
    # Fallback if crewai not installed
    def tool(name):
        def decorator(func):
            return func

        return decorator


def _inner_attr(obj: Any) -> Optional[str]:
    """Name of the attribute holding a CrewAI tool's underlying function.

    Returns ``None`` for a plain function (which the core wrapper handles
    directly).
    """
    if inspect_isfunction_or_method(obj):
        return None
    for attr in ("func", "_run", "run"):
        if callable(getattr(obj, attr, None)):
            return attr
    return None


def inspect_isfunction_or_method(obj: Any) -> bool:
    import inspect

    return inspect.isfunction(obj) or inspect.ismethod(obj)


def protect(
    tools: Sequence[Any],
    *,
    signer: Optional[Signer] = None,
    **signed_kwargs: Any,
) -> List[Any]:
    """Sign-wrap a list of CrewAI tools (or plain functions).

    Accepts either plain callables or CrewAI tool objects produced by the
    ``@tool`` decorator. Plain callables are wrapped and returned; CrewAI tool
    objects have their underlying function wrapped in place so every invocation
    the agent makes is signed, then the same object is returned (so the agent's
    ``tools=[...]`` list keeps its shape).

    Example::

        from vouch.integrations.crewai import protect

        agent = Agent(role=..., goal=..., tools=protect([charge_invoice]))
    """
    out: List[Any] = []
    for t in tools:
        attr = _inner_attr(t)
        if attr is None:
            # Plain function — let the core wrapper handle it.
            out.append(_protect_callables([t], signer=signer, **signed_kwargs)[0])
            continue

        original = getattr(t, attr)
        if getattr(original, "__vouch_signed__", False):
            out.append(t)  # idempotent
            continue
        setattr(t, attr, signed(original, signer=signer, **signed_kwargs))
        out.append(t)
    return out


def autosign(*, signer: Optional[Signer] = None) -> None:
    """Near-zero setup: sign **every** CrewAI tool defined after this call.

    Monkeypatches ``crewai.tools.tool`` so that any tool created with the
    ``@tool`` decorator is automatically sign-wrapped. One line, no per-tool
    changes::

        import vouch.integrations.crewai as vc
        vc.autosign()

        @tool("Charge Invoice")          # signed transparently
        def charge_invoice(...): ...
    """
    try:
        import crewai.tools as crewai_tools
    except ImportError as e:  # pragma: no cover - depends on optional dep
        raise RuntimeError("crewai is not installed; cannot autosign") from e

    if getattr(crewai_tools.tool, "__vouch_autosign__", False):
        return  # already patched

    original_tool = crewai_tools.tool

    @functools.wraps(original_tool)
    def patched_tool(*args, **kwargs):
        decorator = original_tool(*args, **kwargs)

        def wrapping_decorator(func):
            return decorator(signed(func, signer=signer))

        return wrapping_decorator

    patched_tool.__vouch_autosign__ = True  # type: ignore[attr-defined]
    crewai_tools.tool = patched_tool


# ---------------------------------------------------------------------------
# Legacy tool: ask the LLM to mint a token. Prefer protect()/@signed/autosign().
# ---------------------------------------------------------------------------
@tool("Sign Request with Vouch")
def sign_request(intent: str, target: Optional[str] = None) -> str:
    """
    Generates a cryptographic Vouch-Token to prove identity.

    DEPRECATED in favor of deterministic signing (``protect``/``@signed``/
    ``autosign``), which does not depend on the model remembering to call a
    tool. Retained for backward compatibility.

    Args:
        intent: What action you are taking (e.g., 'read_database', 'send_email')
        target: Optional target service or domain

    Returns:
        A Vouch-Token string to use in your request headers.
    """
    private_key = os.getenv("VOUCH_PRIVATE_KEY")
    did = os.getenv("VOUCH_DID")

    if not private_key:
        return "Error: VOUCH_PRIVATE_KEY environment variable not set"
    if not did:
        return "Error: VOUCH_DID environment variable not set"

    try:
        signer = Signer(private_key=private_key, did=did)

        payload = {"intent": intent}
        if target:
            payload["target"] = target

        token = signer.sign(payload)
        return f"Vouch-Token: {token}"

    except Exception as e:
        return f"Error generating token: {e}"


class VouchCrewTools:
    """Collection of Vouch tools for CrewAI agents."""

    sign_request = sign_request


# For backward compatibility
VouchSignerTool = sign_request
