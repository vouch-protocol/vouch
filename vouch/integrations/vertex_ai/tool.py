"""
Vouch Protocol Vertex AI Integration.

Provides integration for Google Vertex AI services.
"""

import os
from typing import Dict, Any, Optional

from vouch import Signer


def sign_request_with_vouch(intent: str, target: Optional[str] = None) -> str:
    """
    Sign a request for Vertex AI function calling.

    Args:
        intent: Description of the action being taken.
        target: Optional target service.

    Returns:
        Vouch-Token or error message.
    """
    private_key = os.getenv("VOUCH_PRIVATE_KEY")
    did = os.getenv("VOUCH_DID")

    if not private_key:
        return "Error: VOUCH_PRIVATE_KEY not set"
    if not did:
        return "Error: VOUCH_DID not set"

    try:
        signer = Signer(private_key=private_key, did=did)

        payload = {"intent": intent}
        if target:
            payload["target"] = target

        return f"Vouch-Token: {signer.sign(payload)}"

    except Exception as e:
        return f"Error: {e}"
