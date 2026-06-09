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
    # Default to loopback. An unauthenticated signer must never be exposed on a
    # routable interface (see validate_security).
    bridge_host: str = Field(
        default_factory=lambda: os.getenv("VOUCH_BRIDGE_HOST", "127.0.0.1"),
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

    @property
    def is_loopback_host(self) -> bool:
        """Whether the bind host is a loopback address."""
        return self.bridge_host in ("127.0.0.1", "::1", "localhost")

    def validate_security(self) -> None:
        """
        Fail closed on an unsafe configuration. Refuse to expose an
        unauthenticated signing service on a routable interface: if no
        bridge_secret is set, the host must be loopback.

        Raises:
          RuntimeError: if auth is disabled while binding a non-loopback host.
        """
        if not self.auth_enabled and not self.is_loopback_host:
            raise RuntimeError(
                f"refusing to bind {self.bridge_host} without VOUCH_BRIDGE_SECRET; "
                "an unauthenticated signing endpoint must stay on loopback"
            )


def load_settings() -> BridgeSettings:
    """Load settings from environment and validate it is safe to serve."""
    settings = BridgeSettings()
    settings.validate_security()
    return settings
