"""vouch-langgraph: sign LangGraph tool calls and graph nodes with Vouch.

Thin distribution wrapping ``vouch.integrations.langgraph``. It exists so the
integration can be installed and listed on its own while the implementation
stays single-sourced in the vouch-protocol package.
"""

from vouch.integrations.langgraph import protect, sign_node

__all__ = ["protect", "sign_node"]
__version__ = "0.1.0"
