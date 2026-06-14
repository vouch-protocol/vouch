"""vouch-langchain: a LangChain tool that issues Vouch Credentials.

Thin distribution wrapping vouch.integrations.langchain. It exists so the tool
can be installed and listed on its own while the implementation stays
single-sourced in the vouch-protocol package.
"""

from vouch.integrations.langchain.tool import VouchSignerInput, VouchSignerTool

__all__ = ["VouchSignerTool", "VouchSignerInput"]
__version__ = "0.1.0"
