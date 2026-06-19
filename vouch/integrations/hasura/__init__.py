"""
Vouch Protocol Hasura Integration.

Provides an Auth Webhook for Hasura GraphQL Engine to verify AI agent identity.
"""

from .webhook import HasuraAuthWebhook, create_webhook_handler

__all__ = ["HasuraAuthWebhook", "create_webhook_handler"]
