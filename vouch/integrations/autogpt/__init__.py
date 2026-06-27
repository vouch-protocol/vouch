"""Vouch AutoGPT integration.

AutoGPT commands are plain functions, so the framework-agnostic deterministic
signers apply directly: wrap the real commands with ``protect([...])`` or
annotate them with ``@signed`` so every invocation is signed before it runs —
no reliance on the model calling ``sign_with_vouch``.
"""

from vouch.autosign import current_credential, protect, sign_intent, signed

from .commands import register_commands, sign_with_vouch

__all__ = [
    "protect",
    "signed",
    "sign_intent",
    "current_credential",
    "sign_with_vouch",
    "register_commands",
]
