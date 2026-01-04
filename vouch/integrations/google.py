"""
Vouch Protocol Google/Vertex AI Integration.

Provides integration for Google Vertex AI Agent Builder and other Google Cloud AI services.
"""

import os
from typing import Dict, Any, Optional

from vouch import Signer


class VertexAISigner:
    """
    Integration for Google Vertex AI Agent Builder.

    Signs tool calls and function invocations with Vouch-Tokens
    for authenticated external API access.

    Example:
        >>> signer = VertexAISigner()
        >>> token = signer.sign_tool_call('search_database', {'query': 'test'})
    """

    def __init__(self, private_key: Optional[str] = None, did: Optional[str] = None):
        """
        Initialize the Vertex AI signer.

        Args:
            private_key: JWK JSON string. Falls back to VOUCH_PRIVATE_KEY env var.
            did: Agent DID. Falls back to VOUCH_DID env var.
        """
        self._private_key = private_key or os.getenv("VOUCH_PRIVATE_KEY")
        self._did = did or os.getenv("VOUCH_DID")
        self._signer: Optional[Signer] = None

        if self._private_key and self._did:
            try:
                self._signer = Signer(private_key=self._private_key, did=self._did)
            except Exception:
                pass

    def sign_tool_call(
        self, tool_name: str, args: Dict[str, Any], target: Optional[str] = None
    ) -> str:
        """
        Generates a Vouch-Token for a Vertex AI Function Call.

        Args:
            tool_name: Name of the tool/function being called.
            args: Arguments to the tool call.
            target: Optional target service.

        Returns:
            A Vouch-Token string or error message.
        """
        if not self._signer:
            if not self._private_key:
                return "Error: VOUCH_PRIVATE_KEY not set"
            if not self._did:
                return "Error: VOUCH_DID not set"

            try:
                self._signer = Signer(private_key=self._private_key, did=self._did)
            except Exception as e:
                return f"Error initializing signer: {e}"

        try:
            payload = {"tool": tool_name, "args": args}
            if target:
                payload["target"] = target

            return self._signer.sign(payload)

        except Exception as e:
            return f"Error signing: {e}"


def sign_request_with_vouch(intent: str, target: Optional[str] = None) -> str:
    """
    Standalone function to sign a request.

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
