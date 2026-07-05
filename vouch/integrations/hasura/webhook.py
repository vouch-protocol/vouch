"""
Vouch Protocol Hasura Auth Webhook.

Provides authentication for Hasura GraphQL Engine by verifying AI agent
identity via Vouch-Tokens. Implements Hasura's Auth Webhook specification.

Usage:
    # As standalone server
    from vouch.integrations.hasura import create_webhook_handler
    app = create_webhook_handler()
    app.run(host="0.0.0.0", port=3000)

    # Or integrate with existing Flask/FastAPI app
    from vouch.integrations.hasura import HasuraAuthWebhook
    webhook = HasuraAuthWebhook()
    result = webhook.authenticate(request.headers)
"""

import os
import time
import json
import base64
import logging
import hashlib
from datetime import datetime
from typing import Dict, Optional, Any, Tuple
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vouch import Verifier

logger = logging.getLogger(__name__)


def _jwk_to_ed25519_public(public_key_jwk: str) -> Ed25519PublicKey:
    """Ed25519PublicKey from a public JWK JSON string."""
    x = json.loads(public_key_jwk)["x"]
    raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    return Ed25519PublicKey.from_public_bytes(raw)


def _credential_expiry_ts(passport) -> int:
    """Unix timestamp of the credential's validUntil, or 0 if absent."""
    if not getattr(passport, "valid_until", None):
        return 0
    try:
        return int(datetime.fromisoformat(passport.valid_until.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


@dataclass
class RoleMappingConfig:
    """Configuration for mapping DIDs and reputation to Hasura roles."""

    # Explicit DID → role mapping
    did_roles: Dict[str, str] = field(default_factory=dict)

    # Organization prefix → role mapping (e.g., "acme.com" → "acme_agent")
    org_roles: Dict[str, str] = field(default_factory=dict)

    # Reputation thresholds → roles
    admin_threshold: int = 80
    writer_threshold: int = 50
    reader_threshold: int = 30

    # Default roles
    default_role: str = "agent_minimal"
    delegated_role: str = "agent_delegated"


class HasuraAuthWebhook:
    """
    Hasura Auth Webhook handler for Vouch Protocol.

    Verifies Vouch-Tokens and returns Hasura session variables.

    Example:
        >>> webhook = HasuraAuthWebhook()
        >>> headers = {"Vouch-Token": "eyJ..."}
        >>> result = webhook.authenticate(headers)
        >>> print(result)
        {"X-Hasura-Role": "agent_writer", "X-Hasura-User-Id": "did:web:agent.com"}
    """

    def __init__(
        self,
        trusted_dids: Optional[Dict[str, str]] = None,
        role_config: Optional[RoleMappingConfig] = None,
        allow_did_resolution: bool = True,
        clock_skew_seconds: int = 30,
        nonce_store: Optional[Any] = None,  # Redis client for replay prevention
        revocation_store: Optional[Any] = None,  # Redis client for revocation
    ):
        """
        Initialize the Hasura Auth Webhook.

        Args:
            trusted_dids: Dict of DID → public key JWK for trusted agents.
            role_config: Configuration for role mapping.
            allow_did_resolution: If True, resolve unknown DIDs via did:web.
            clock_skew_seconds: Allowed clock drift for timestamp validation.
            nonce_store: Optional Redis client for replay attack prevention.
            revocation_store: Optional Redis client for key revocation checks.
        """
        self._trusted_keys: Dict[str, Ed25519PublicKey] = {}
        for did, key in (trusted_dids or {}).items():
            self._trusted_keys[did] = _jwk_to_ed25519_public(key)
        self._allow_resolution = allow_did_resolution
        self._clock_skew = clock_skew_seconds
        self.role_config = role_config or RoleMappingConfig()
        self.nonce_store = nonce_store
        self.revocation_store = revocation_store

        # Load trusted DIDs from environment
        env_trusted = os.getenv("VOUCH_TRUSTED_DIDS")
        if env_trusted:
            try:
                for did, key in json.loads(env_trusted).items():
                    self._trusted_keys[did] = _jwk_to_ed25519_public(key)
            except (json.JSONDecodeError, ValueError):
                logger.warning("Invalid VOUCH_TRUSTED_DIDS JSON")

    def authenticate(self, headers: Dict[str, str]) -> Tuple[bool, Dict[str, Any]]:
        """
        Authenticate a request using Vouch-Token header.

        Args:
            headers: HTTP headers from the request.

        Returns:
            Tuple of (success, session_vars or error).
            On success: (True, {"X-Hasura-Role": ..., "X-Hasura-User-Id": ...})
            On failure: (False, {"error": "..."})
        """
        # Extract the credential from headers.
        raw = headers.get("Vouch-Credential") or headers.get("vouch-credential")
        if not raw:
            raw = headers.get("Vouch-Token") or headers.get("vouch-token")
        if not raw:
            auth = headers.get("Authorization") or headers.get("authorization")
            if auth and auth.startswith("Vouch "):
                raw = auth[6:]

        if not raw:
            return False, {"error": "Missing Vouch-Credential header"}

        try:
            credential = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            return False, {"error": "Credential is not valid JSON"}

        # Resolve the verification key: a trusted root for the issuer, else fall
        # back to did:web resolution when allowed.
        issuer = credential.get("issuer") or credential.get("credentialSubject", {}).get("id", "")
        public_key = self._trusted_keys.get(issuer)
        if public_key is None and not self._allow_resolution:
            return False, {"error": "Issuer is not a trusted DID"}

        try:
            valid, passport = Verifier.verify(
                credential, public_key=public_key, clock_skew_seconds=self._clock_skew
            )
        except Exception as e:
            logger.warning(f"Credential verification error: {e}")
            return False, {"error": "Credential verification failed"}

        if not valid or not passport:
            return False, {"error": "Invalid credential signature"}

        # Check revocation (if configured)
        if self.revocation_store:
            try:
                revoked = self.revocation_store.get(f"vouch:revoked:{passport.iss}")
                if revoked:
                    logger.warning(f"Revoked DID attempted access: {passport.iss}")
                    return False, {"error": "Agent key has been revoked"}
            except Exception as e:
                logger.warning(f"Revocation check failed: {e}")

        # Check replay (if configured)
        if self.nonce_store:
            try:
                nonce_key = f"vouch:nonce:{passport.credential_id}"
                if self.nonce_store.exists(nonce_key):
                    logger.warning(f"Replay attack detected: {passport.credential_id}")
                    return False, {"error": "Token replay detected"}
                # Mark as used with TTL
                ttl = max(_credential_expiry_ts(passport) - int(time.time()) + 60, 60)
                self.nonce_store.setex(nonce_key, ttl, "1")
            except Exception as e:
                logger.warning(f"Nonce tracking failed: {e}")

        # Build session variables
        session_vars = self._build_session_vars(passport)

        logger.info(f"Authenticated agent: {passport.sub} as {session_vars.get('X-Hasura-Role')}")
        return True, session_vars

    def _build_session_vars(self, passport) -> Dict[str, str]:
        """Build Hasura session variables from passport."""
        role = self._compute_role(passport)

        session_vars = {
            "X-Hasura-Role": role,
            "X-Hasura-User-Id": passport.sub,
        }

        # Add reputation if available
        if passport.reputation_score is not None:
            session_vars["X-Hasura-Vouch-Reputation"] = str(passport.reputation_score)

        # Add delegation info if present
        if passport.delegation_chain:
            session_vars["X-Hasura-Vouch-Delegation-Depth"] = str(len(passport.delegation_chain))
            # Root issuer is first in chain
            root_issuer = passport.delegation_chain[0].issuer
            session_vars["X-Hasura-Vouch-Root-Issuer"] = root_issuer

        # Add intent hash for audit
        if passport.intent:
            intent_hash = hashlib.sha256(
                json.dumps(passport.intent, sort_keys=True).encode()
            ).hexdigest()[:16]
            session_vars["X-Hasura-Vouch-Intent"] = intent_hash

        return session_vars

    def _compute_role(self, passport) -> str:
        """Compute Hasura role based on DID and reputation."""
        config = self.role_config

        # 1. Check explicit DID mapping
        if passport.sub in config.did_roles:
            return config.did_roles[passport.sub]

        # 2. Check organization mapping (extract domain from did:web:)
        if passport.sub.startswith("did:web:"):
            domain = passport.sub[8:].split(":")[0]
            for org, role in config.org_roles.items():
                if domain.endswith(org):
                    return role

        # 3. Delegated agents get reduced permissions
        if passport.delegation_chain:
            return config.delegated_role

        # 4. Reputation-based assignment
        reputation = passport.reputation_score or 50

        if reputation >= config.admin_threshold:
            return "agent_admin"
        elif reputation >= config.writer_threshold:
            return "agent_writer"
        elif reputation >= config.reader_threshold:
            return "agent_reader"

        return config.default_role


def create_webhook_handler(
    host: str = "0.0.0.0",
    port: int = 3000,
    **webhook_kwargs,
):
    """
    Create a standalone Flask server for the Hasura Auth Webhook.

    Args:
        host: Host to bind to.
        port: Port to bind to.
        **webhook_kwargs: Arguments passed to HasuraAuthWebhook.

    Returns:
        Flask app instance.

    Example:
        >>> app = create_webhook_handler()
        >>> app.run()  # Runs on http://0.0.0.0:3000
    """
    try:
        from flask import Flask, request, jsonify
    except ImportError:
        raise ImportError("Flask is required for standalone webhook server: pip install flask")

    app = Flask(__name__)
    webhook = HasuraAuthWebhook(**webhook_kwargs)

    @app.route("/auth", methods=["GET"])
    def auth():
        """Hasura Auth Webhook endpoint."""
        headers = dict(request.headers)
        success, result = webhook.authenticate(headers)

        if success:
            return jsonify(result), 200
        else:
            return jsonify(result), 401

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint."""
        return jsonify({"status": "ok", "service": "vouch-hasura-integrator"}), 200

    return app


# CLI entry point
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Vouch Hasura Auth Webhook")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=3000, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    app = create_webhook_handler()
    app.run(host=args.host, port=args.port, debug=args.debug)
