"""The Vouch Protocol Assistant's A2A agent card.

The signing sidecar builds this card for the assistant's A2A endpoint and
signs it with ``vouch.integrations.a2a.sign_agent_card``, so the card's
vouchCredential binds the card's ``url`` to the assistant's DID.
"""

from __future__ import annotations

from typing import Any

DEFAULT_A2A_URL = "https://agent.vouch-protocol.com/a2a"
A2A_PROTOCOL_VERSION = "0.3.0"
CARD_VERSION = "0.3.0"
CARD_VALID_SECONDS = 90 * 24 * 3600


def build_card(url: str = DEFAULT_A2A_URL) -> dict[str, Any]:
    """The unsigned agent card for an A2A endpoint at ``url``."""
    return {
        "protocolVersion": A2A_PROTOCOL_VERSION,
        "name": "Vouch Protocol Assistant",
        "description": (
            "Answers questions about Vouch Protocol from its published documentation. "
            "Every reply carries a Vouch Credential signed by the assistant's DID."
        ),
        "url": url,
        "preferredTransport": "JSONRPC",
        "version": CARD_VERSION,
        "provider": {"organization": "Vouch Protocol", "url": "https://vouch-protocol.com"},
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            {
                "id": "vouch-protocol-qa",
                "name": "Vouch Protocol Q&A",
                "description": (
                    "Answers questions about Vouch Protocol, its specification, and its SDKs."
                ),
                "tags": ["vouch-protocol", "documentation", "q&a"],
                "examples": ["How does delegation work in Vouch Protocol?"],
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain"],
            }
        ],
    }
