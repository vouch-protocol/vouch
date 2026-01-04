"""
Vouch Protocol AutoGen Integration.

Provides AutoGen-compatible tools for generating Vouch-Tokens.
"""

import os
from typing import Annotated, Optional

from vouch import Signer


def sign_action(
    intent: Annotated[str, "The action you are about to take"],
    target: Annotated[Optional[str], "Optional target service"] = None,
) -> str:
    """
    Generates a Vouch-Token to sign a sensitive action for AutoGen agents.

    Use this function before making authenticated API calls to external services.
    The generated token should be included as a 'Vouch-Token' header.

    Args:
        intent: Description of the action being taken.
        target: Optional target service or domain.

    Returns:
        A Vouch-Token string or an error message.
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


# Function registry for AutoGen
VOUCH_FUNCTIONS = [
    {
        "name": "sign_action",
        "description": "Generate a cryptographic Vouch-Token for authenticated API calls",
        "function": sign_action,
    }
]
