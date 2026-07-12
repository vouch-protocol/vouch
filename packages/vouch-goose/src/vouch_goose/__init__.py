"""vouch-goose: make Block's Goose agent Vouch-aware.

Thin distribution wrapping ``vouch.integrations.goose``. It registers the
vouch-mcp server as a Goose extension so Goose can create identities, sign, and
verify through the same MCP tools every other client uses. The implementation
stays single-sourced in the vouch-protocol package.
"""

from vouch.integrations.goose import (
    EXTENSION_NAME,
    extension_config,
    goose_config_path,
    install,
)

__all__ = ["install", "extension_config", "goose_config_path", "EXTENSION_NAME"]
__version__ = "0.1.0"
