"""vouch-mcp: an MCP server that issues Vouch Credentials for agent tool calls.

This is a thin distribution that wraps ``vouch.integrations.mcp.server``
(built on the official MCP SDK / FastMCP). It exists so the server can be
installed and listed on its own (PyPI, the MCP server registry) while the
implementation stays single-sourced in the vouch-protocol package.

Run:
    pip install vouch-mcp
    VOUCH_PRIVATE_KEY=... VOUCH_DID=... vouch-mcp
"""

from vouch.integrations.mcp.server import main, mcp

__all__ = ["main", "mcp"]
__version__ = "2.0.0"
