"""Vouch CrewAI integration - deterministic signing."""

from .tool import (
    autosign,
    current_credential,
    protect,
    sign_intent,
    signed,
)

__all__ = [
    "protect",
    "signed",
    "autosign",
    "sign_intent",
    "current_credential",
]
