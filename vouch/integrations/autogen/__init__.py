"""Vouch AutoGen integration.

AutoGen tools are plain functions, so the framework-agnostic deterministic
signers apply directly: wrap your real tools with ``protect([...])`` or annotate
them with ``@signed`` and every call is signed before it runs — no prompt, no
reliance on the model calling ``sign_action``.
"""

from vouch.autosign import current_credential, protect, sign_intent, signed

from .tool import VOUCH_FUNCTIONS, sign_action

__all__ = [
    "protect",
    "signed",
    "sign_intent",
    "current_credential",
    "sign_action",
    "VOUCH_FUNCTIONS",
]
