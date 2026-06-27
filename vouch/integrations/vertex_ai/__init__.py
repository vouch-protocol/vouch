"""Vouch Vertex AI integration — deterministic signing.

Vertex AI function-calling tools are plain functions; there is no global tool
decorator to patch, so there is no ``autosign()`` here. ``protect([...])`` is the
one-line equivalent — wrap your real tools once and every call is signed before
it runs::

    from vouch.integrations.vertex_ai import protect

    tools = protect([search_db, send_email])

Or annotate individual tools with ``@signed``.
"""

from vouch.autosign import current_credential, protect, sign_intent, signed

__all__ = [
    "protect",
    "signed",
    "sign_intent",
    "current_credential",
]
