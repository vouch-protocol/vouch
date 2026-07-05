"""
Vouch Protocol LangGraph Integration.

LangGraph builds agent workflows as graphs. The tool calls inside a graph run
through the same LangChain tool objects, so tool-level signing is shared with
the LangChain integration: wrap the tools you hand to a ToolNode or to
``create_react_agent`` and every tool call is signed before it runs.

On top of that, :func:`sign_node` wraps a graph node (a ``state -> state``
callable) so each node step issues its own Vouch Credential, giving a signed
trail across the whole graph rather than only at the leaf tools.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, List, Optional, Sequence

from vouch import Signer
from vouch.autosign import sign_intent
from vouch.integrations.langchain import protect as _protect_tools

__all__ = ["protect", "sign_node"]


def protect(
    tools: Sequence[Any],
    *,
    signer: Optional[Signer] = None,
    **signed_kwargs: Any,
) -> List[Any]:
    """Sign-wrap the tools handed to a ToolNode or ``create_react_agent``.

    LangGraph tools are LangChain tools (or plain callables), so this delegates
    to the LangChain integration. Every tool call is signed before it runs.

    Example::

        from langgraph.prebuilt import create_react_agent
        from vouch.integrations.langgraph import protect

        agent = create_react_agent(llm, tools=protect([search, send_email]))
    """
    return _protect_tools(tools, signer=signer, **signed_kwargs)


def sign_node(
    fn: Optional[Callable[..., Any]] = None,
    *,
    signer: Optional[Signer] = None,
    action: Optional[str] = None,
) -> Callable[..., Any]:
    """Wrap a LangGraph node so each execution issues a Vouch Credential.

    Use as a decorator on a node callable (``state -> state``). The credential
    records the node running, under the node's function name unless ``action``
    is given. The node runs whether or not an identity is resolved; when none
    is, signing is skipped and the step proceeds unsigned.

    Example::

        @sign_node
        def plan(state): ...

        @sign_node(action="charge_card")
        def bill(state): ...
    """

    def decorate(func: Callable[..., Any]) -> Callable[..., Any]:
        node_action = action or getattr(func, "__name__", "node")

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            sign_intent(
                node_action,
                target="langgraph:node",
                resource="langgraph:node",
                signer=signer,
            )
            return func(*args, **kwargs)

        wrapper.__vouch_signed__ = True
        return wrapper

    if fn is not None:
        return decorate(fn)
    return decorate
