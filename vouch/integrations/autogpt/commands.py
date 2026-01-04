"""
Vouch Protocol AutoGPT Integration.

Provides AutoGPT-compatible commands for generating Vouch-Tokens.
"""

import os
from typing import Optional

try:
    from autogpt.command_decorator import command
except ImportError:
    # Fallback decorator when AutoGPT is not installed
    def command(name, description, args):
        def decorator(func):
            return func

        return decorator


from vouch import Signer


@command(
    "sign_with_vouch",
    "Generates a cryptographic Vouch-Token to prove your identity to external services",
    {
        "intent": {
            "type": "string",
            "description": "What action you are taking (e.g., 'read_email', 'query_database')",
            "required": True,
        },
        "target_service": {
            "type": "string",
            "description": "The target service domain",
            "required": False,
        },
    },
)
def sign_with_vouch(intent: str, target_service: Optional[str] = None) -> str:
    """
    Generate a Vouch-Token for authentication with external services.

    Args:
        intent: Description of the action being taken.
        target_service: Optional target domain.

    Returns:
        Instructions with the generated Vouch-Token.
    """
    private_key = os.getenv("VOUCH_PRIVATE_KEY")
    did = os.getenv("VOUCH_DID", "did:web:anonymous")

    if not private_key:
        return "Error: VOUCH_PRIVATE_KEY environment variable not set"

    try:
        signer = Signer(private_key=private_key, did=did)

        payload = {"intent": intent}
        if target_service:
            payload["target"] = target_service

        token = signer.sign(payload)

        return (
            f"Vouch-Token generated successfully.\n"
            f"Add this header to your request:\n"
            f"Vouch-Token: {token}"
        )

    except Exception as e:
        return f"Error generating Vouch-Token: {e}"


def register_commands():
    """Register Vouch commands with AutoGPT."""
    return [sign_with_vouch]
