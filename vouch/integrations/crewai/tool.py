"""
Vouch Protocol CrewAI Integration.

Provides CrewAI-compatible tools for generating Vouch-Tokens.
"""

import os
from typing import Optional

try:
    from crewai.tools import tool
except ImportError:
    # Fallback if crewai not installed
    def tool(name):
        def decorator(func):
            return func

        return decorator


from vouch import Signer


@tool("Sign Request with Vouch")
def sign_request(intent: str, target: Optional[str] = None) -> str:
    """
    Generates a cryptographic Vouch-Token to prove identity.

    Use this tool before making authenticated API calls to external services.
    The generated token should be included as a 'Vouch-Token' header.

    Args:
        intent: What action you are taking (e.g., 'read_database', 'send_email')
        target: Optional target service or domain

    Returns:
        A Vouch-Token string to use in your request headers.
    """
    private_key = os.getenv("VOUCH_PRIVATE_KEY")
    did = os.getenv("VOUCH_DID")

    if not private_key:
        return "Error: VOUCH_PRIVATE_KEY environment variable not set"
    if not did:
        return "Error: VOUCH_DID environment variable not set"

    try:
        signer = Signer(private_key=private_key, did=did)

        payload = {"intent": intent}
        if target:
            payload["target"] = target

        token = signer.sign(payload)
        return f"Vouch-Token: {token}"

    except Exception as e:
        return f"Error generating token: {e}"


class VouchCrewTools:
    """Collection of Vouch tools for CrewAI agents."""

    sign_request = sign_request


# For backward compatibility
VouchSignerTool = sign_request
