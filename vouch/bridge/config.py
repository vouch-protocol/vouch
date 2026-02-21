# vouch/bridge/config.py
"""
Bridge server configuration.

All settings are read from VOUCH_BRIDGE_* environment variables.
"""

import os
from typing import Optional

from pydantic import BaseModel, Field


class BridgeSettings(BaseModel):
    """Configuration for the Vouch bridge server."""

    # Auth secret — required for /sign and /verify endpoints
    bridge_secret: str = Field(
        default_factory=lambda: os.getenv("VOUCH_BRIDGE_SECRET", ""),
    )

    # Server
    bridge_port: int = Field(
        default_factory=lambda: int(os.getenv("VOUCH_BRIDGE_PORT", "21000")),
    )
    bridge_host: str = Field(
        default_factory=lambda: os.getenv("VOUCH_BRIDGE_HOST", "0.0.0.0"),
    )

    # Identity defaults (used when caller doesn't supply a DID)
    default_did: str = Field(
        default_factory=lambda: os.getenv("VOUCH_BRIDGE_DEFAULT_DID", ""),
    )
    default_display_name: str = Field(
        default_factory=lambda: os.getenv("VOUCH_BRIDGE_DEFAULT_DISPLAY_NAME", "Vouch Signer"),
    )

    # Shortlink domain override
    shortlink_domain: str = Field(
        default_factory=lambda: os.getenv("VOUCH_SHORTLINK_DOMAIN", "https://vch.sh"),
    )

    @property
    def auth_enabled(self) -> bool:
        """Whether bearer-token auth is enforced."""
        return bool(self.bridge_secret)


def load_settings() -> BridgeSettings:
    """Load settings from environment."""
    return BridgeSettings()
