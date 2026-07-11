"""Sign OpenAI agent tool calls with Vouch Credentials.

Thin re-export of :mod:`vouch.integrations.openai` so the integration installs
as a standalone package that pulls in both ``vouch-protocol`` and ``openai``.
"""

from vouch.integrations.openai import (
    protect,
    sign_tool_call,
    signed_tool,
    verify_tool_call,
)

__all__ = ["protect", "signed_tool", "sign_tool_call", "verify_tool_call"]
__version__ = "0.1.0"
