"""
Vouch Protocol LangChain Integration — deterministic signing.

Every tool call is signed in Python before it runs. Three tiers of effort:

  * ``protect([...])``  — wrap a list of tools (one line)
  * ``@signed``         — annotate a single tool (one decorator)
  * ``autosign()``      — sign every ``@tool`` framework-wide (near-zero)

See :mod:`vouch.autosign` for the framework-agnostic core.
"""

import inspect
from typing import Any, List, Optional, Sequence

from vouch import Signer
from vouch.autosign import (  # noqa: F401
    current_credential,
    install_decorator_autosign,
    sign_intent,
    signed,
)
from vouch.autosign import protect as _protect_callables


def _inner_attr(obj: Any) -> Optional[str]:
    """Attribute holding a LangChain tool's underlying callable, or ``None``."""
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
    """Sign-wrap a list of LangChain tools (or plain functions).

    Plain callables are wrapped via the core signer. LangChain tool objects
    (``BaseTool`` / ``StructuredTool``) have their underlying callable wrapped
    in place so every invocation is signed, then the same object is returned.

    Example::

        from vouch.integrations.langchain import protect

        agent = create_react_agent(llm, tools=protect([search, send_email]))
    """
    out: List[Any] = []
    for t in tools:
        attr = _inner_attr(t)
        if attr is None:
            out.append(_protect_callables([t], signer=signer, **signed_kwargs)[0])
            continue
        original = getattr(t, attr)
        if getattr(original, "__vouch_signed__", False):
            out.append(t)
            continue
        wrapped = signed(original, signer=signer, **signed_kwargs)
        try:
            object.__setattr__(t, attr, wrapped)  # pydantic models block plain setattr
        except Exception:
            setattr(t, attr, wrapped)
        out.append(t)
    return out


def autosign(*, signer: Optional[Signer] = None) -> bool:
    """Near-zero setup: sign **every** LangChain tool defined after this call.

    Monkeypatches ``langchain_core.tools.tool`` (falling back to
    ``langchain.tools.tool``) so any tool created with ``@tool`` — bare or with
    arguments — is automatically sign-wrapped::

        import vouch.integrations.langchain as vl
        vl.autosign()

        @tool                            # signed transparently
        def search(query: str) -> str: ...
    """
    module = None
    attr = "tool"
    try:
        import langchain_core.tools as module  # type: ignore
    except ImportError:
        try:
            import langchain.tools as module  # type: ignore
        except ImportError as e:  # pragma: no cover - optional dep
            raise RuntimeError("langchain is not installed; cannot autosign") from e
    return install_decorator_autosign(module, attr, signer=signer)
