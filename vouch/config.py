# vouch/config.py
"""
Centralized configuration for Vouch Protocol.

All configurable values are read from environment variables with sensible defaults.
This allows different environments (dev, staging, production) to use different
settings without code changes.

Usage:
    from vouch.config import SHORTLINK_DOMAIN, VERIFY_DOMAIN
    
    url = f"{SHORTLINK_DOMAIN}/{signature_id}"
    
Environment Variables:
    VOUCH_SHORTLINK_DOMAIN: Short URL domain for sharing (default: https://vch.sh)
    VOUCH_VERIFY_DOMAIN: Full verification page domain (default: https://vouch-protocol.com)
    VOUCH_API_DOMAIN: API endpoint domain (default: https://api.vouch-protocol.com)
"""

import os
from typing import Final

# =============================================================================
# Shortlink Configuration
# =============================================================================

# Short domain for shareable links (vch.sh/{id})
# This domain 301-redirects to VERIFY_DOMAIN for SEO benefits
SHORTLINK_DOMAIN: Final[str] = os.getenv(
    "VOUCH_SHORTLINK_DOMAIN", 
    "https://vch.sh"
)

# Full verification domain where content is actually served
# All SEO value flows here
VERIFY_DOMAIN: Final[str] = os.getenv(
    "VOUCH_VERIFY_DOMAIN", 
    "https://vouch-protocol.com"
)

# Verification path prefix on the main domain
VERIFY_PATH: Final[str] = os.getenv(
    "VOUCH_VERIFY_PATH",
    "/v"
)

# =============================================================================
# API Configuration
# =============================================================================

# API endpoint for Vouch services
API_DOMAIN: Final[str] = os.getenv(
    "VOUCH_API_DOMAIN",
    "https://api.vouch-protocol.com"
)

# Bridge daemon default port
BRIDGE_PORT: Final[int] = int(os.getenv("VOUCH_BRIDGE_PORT", "21000"))

# =============================================================================
# Helper Functions
# =============================================================================

def get_shortlink(signature_id: str) -> str:
    """
    Generate a shareable shortlink for a signature.
    
    Args:
        signature_id: The unique identifier for the signature (e.g., 8-char hash)
        
    Returns:
        Full shortlink URL (e.g., "https://vch.sh/abc12345")
    """
    domain = SHORTLINK_DOMAIN.rstrip("/")
    return f"{domain}/{signature_id}"


def get_verify_url(signature_id: str) -> str:
    """
    Generate the canonical verification URL on the main domain.
    
    This is where the shortlink redirects to. All verification content
    is served from this URL for SEO benefits.
    
    Args:
        signature_id: The unique identifier for the signature
        
    Returns:
        Full verification URL (e.g., "https://vouch-protocol.com/v/abc12345")
    """
    domain = VERIFY_DOMAIN.rstrip("/")
    path = VERIFY_PATH.rstrip("/")
    return f"{domain}{path}/{signature_id}"


def get_redirect_url(signature_id: str) -> str:
    """
    Alias for get_verify_url - the URL that shortlinks redirect to.
    """
    return get_verify_url(signature_id)


# =============================================================================
# Configuration Summary (for debugging)
# =============================================================================

def print_config() -> None:
    """Print current configuration (useful for debugging)."""
    print("Vouch Protocol Configuration:")
    print(f"  SHORTLINK_DOMAIN: {SHORTLINK_DOMAIN}")
    print(f"  VERIFY_DOMAIN:    {VERIFY_DOMAIN}")
    print(f"  VERIFY_PATH:      {VERIFY_PATH}")
    print(f"  API_DOMAIN:       {API_DOMAIN}")
    print(f"  BRIDGE_PORT:      {BRIDGE_PORT}")


if __name__ == "__main__":
    print_config()
