"""vouch-a2a: bind A2A Agent Cards to a Vouch identity.

Thin distribution wrapping vouch.integrations.a2a. It exists so the A2A binding
can be installed and listed on its own while the implementation stays
single-sourced in the vouch-protocol package.
"""

from vouch.integrations.a2a import VOUCH_CARD_FIELD, sign_agent_card, verify_agent_card

__all__ = ["sign_agent_card", "verify_agent_card", "VOUCH_CARD_FIELD"]
__version__ = "0.1.0"
