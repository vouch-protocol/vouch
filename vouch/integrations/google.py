"""
Vouch Protocol Google / Vertex AI Agent Builder Integration — deterministic
signing.

Google Cloud AI tools (Vertex AI Agent Builder, function calling) are plain
functions; there is no global tool decorator to patch, so there is no
``autosign()`` here. ``protect([...])`` is the one-line equivalent — wrap your
real tools once and every call is signed before it runs::

    from vouch.integrations.google import protect

    tools = protect([search_db, send_email])

Or annotate individual tools with ``@signed``. See :mod:`vouch.autosign`.
"""

from vouch.autosign import current_credential, protect, sign_intent, signed

__all__ = [
    "protect",
    "signed",
    "sign_intent",
    "current_credential",
]
