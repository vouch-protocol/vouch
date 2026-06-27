"""
Vouch Protocol CrewAI Integration — deterministic signing.

Every tool call is signed in Python before it runs. There is nothing for the
model to remember and no prompt to write. Three tiers of effort:

  * ``protect([...])``  — wrap a list of tools (one line)
  * ``@signed``         — annotate a single tool (one decorator)
  * ``autosign()``      — sign every ``@tool`` framework-wide (near-zero)

See :mod:`vouch.autosign` for the framework-agnostic core.
"""

import inspect
from typing import Any, List, Optional, Sequence

from vouch import Signer

# Framework-agnostic primitives, re-exported for convenience.
from vouch.autosign import (  # noqa: F401
    current_credential,
    install_decorator_autosign,
    sign_intent,
    signed,
)
from vouch.autosign import protect as _protect_callables


def _inner_attr(obj: Any) -> Optional[str]:
    """Attribute holding a CrewAI tool's underlying callable, or ``None`` for a
    plain function (which the core wrapper handles directly)."""
    if inspect.isfunction(obj) or inspect.ismethod(obj):
        return None
    for attr in ("func", "_run", "run"):
        if callable(getattr(obj, attr, None)):
            return attr
    return None


def protect(
    tools: Sequence[Any],
    *,
    signer: Optional[Signer] = None,
    **signed_kwargs: Any,
) -> List[Any]:
    """Sign-wrap a list of CrewAI tools (or plain functions).

    Plain callables are wrapped and returned. CrewAI tool objects produced by
    the ``@tool`` decorator have their underlying function wrapped in place, so
    every invocation the agent makes is signed and the ``tools=[...]`` list
    keeps its shape.

    Example::

        from vouch.integrations.crewai import protect

        agent = Agent(role=..., goal=..., tools=protect([charge_invoice]))
    """
    out: List[Any] = []
    for t in tools:
        attr = _inner_attr(t)
        if attr is None:
            out.append(_protect_callables([t], signer=signer, **signed_kwargs)[0])
            continue
        original = getattr(t, attr)
        if getattr(original, "__vouch_signed__", False):
            out.append(t)  # idempotent
            continue
        setattr(t, attr, signed(original, signer=signer, **signed_kwargs))
        out.append(t)
    return out


def autosign(*, signer: Optional[Signer] = None) -> bool:
    """Near-zero setup: sign **every** CrewAI tool defined after this call.

    Monkeypatches ``crewai.tools.tool`` so any tool created with ``@tool`` is
    automatically sign-wrapped::

        import vouch.integrations.crewai as vc
        vc.autosign()

        @tool("Charge Invoice")          # signed transparently
        def charge_invoice(...): ...
    """
    try:
        import crewai.tools as crewai_tools
    except ImportError as e:  # pragma: no cover - optional dep
        raise RuntimeError("crewai is not installed; cannot autosign") from e
    return install_decorator_autosign(crewai_tools, "tool", signer=signer)
