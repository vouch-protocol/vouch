"""Vouch Vertex AI integration.

Vertex AI function-calling tools are plain functions, so the framework-agnostic
deterministic signers apply directly: wrap your real tools with ``protect([...])``
or annotate them with ``@signed`` and every call is signed before it runs — no
reliance on the model calling ``sign_request_with_vouch``.
"""

from vouch.autosign import current_credential, protect, sign_intent, signed

from .tool import sign_request_with_vouch

__all__ = [
    "protect",
    "signed",
    "sign_intent",
    "current_credential",
    "sign_request_with_vouch",
]
