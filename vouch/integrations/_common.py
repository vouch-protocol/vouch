"""
Shared utilities for Vouch integrations.

Provides a single `load_signer()` entry-point so every integration
presents the same helpful error when credentials are missing.
"""

import os
from typing import Optional

from vouch import Signer

_MISSING_ENV_HELP = """\
Vouch identity not configured.

Set the following environment variables:

  export VOUCH_DID='did:web:your-agent.example.com'
  export VOUCH_PRIVATE_KEY='{"kty":"OKP","crv":"Ed25519",...}'

To generate a new identity from Python:

  from vouch.keys import generate_identity

  identity = generate_identity(domain="your-agent.example.com")
  print(f"export VOUCH_DID='{identity.did}'")
  print(f"export VOUCH_PRIVATE_KEY='{identity.private_key_jwk}'")

Or use the CLI:

  vouch init --domain your-agent.example.com --env

See https://vouch-protocol.com/ for more details.
"""


def load_signer(
    private_key: Optional[str] = None,
    did: Optional[str] = None,
) -> Signer:
    """Return a Signer, resolving credentials from args or environment.

    Args:
        private_key: JWK JSON string. If ``None``, reads ``VOUCH_PRIVATE_KEY``.
        did: Agent DID. If ``None``, reads ``VOUCH_DID``.

    Returns:
        A configured :class:`vouch.Signer`.

    Raises:
        OSError: When ``VOUCH_PRIVATE_KEY`` or ``VOUCH_DID`` is unset and
            not provided as an argument. The error message includes
            step-by-step setup instructions.
    """
    resolved_key = private_key or os.getenv("VOUCH_PRIVATE_KEY")
    resolved_did = did or os.getenv("VOUCH_DID")

    if not resolved_key or not resolved_did:
        raise OSError(_MISSING_ENV_HELP)

    return Signer(private_key=resolved_key, did=resolved_did)
