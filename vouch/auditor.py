"""
Vouch Protocol Auditor - Issues verifiable credentials with reputation scores.

The Auditor is responsible for issuing Vouch certificates that include
identity verification and reputation scores.
"""

import json
import time
import uuid
import logging
from typing import Dict, Any, Optional

from jwcrypto import jwk, jws
from jwcrypto.common import json_encode


logger = logging.getLogger(__name__)


class Auditor:
    """
    Issues Vouch certificates binding identity to reputation.

    The Auditor creates JWS tokens that include:
    - Agent DID and identity binding
    - Reputation score
    - Integrity hash (code/model fingerprint)
    - Expiration time

    Example:
        >>> auditor = Auditor(private_key_jwk='{"kty":"OKP",...}')
        >>> cert = auditor.issue_vouch({
        ...     'did': 'did:web:agent.com',
        ...     'integrity_hash': 'sha256:abc123...',
        ...     'reputation_score': 85
        ... })
        >>> print(cert['certificate'])
    """

    DEFAULT_EXPIRY_SECONDS = 86400  # 24 hours
    DEFAULT_REPUTATION = 50  # Starting reputation for new agents

    def __init__(
        self,
        private_key_json: str,
        issuer_did: str = "did:web:vouch-authority",
        default_expiry: int = DEFAULT_EXPIRY_SECONDS,
    ):
        """
        Initialize the Auditor with signing credentials.

        Args:
            private_key_json: JWK JSON string of the Ed25519 private key.
            issuer_did: The DID of this auditor/authority.
            default_expiry: Default certificate validity period in seconds.

        Raises:
            ValueError: If the private key is invalid.
        """
        if not private_key_json:
            raise ValueError("Auditor requires a private key (JWK JSON string)")

        try:
            self._signing_key = jwk.JWK.from_json(private_key_json)
            if self._signing_key["kty"] != "OKP":
                raise ValueError("Key must be an Ed25519 key (OKP)")
        except Exception as e:
            raise ValueError(f"Invalid private key: {e}")

        self._issuer_did = issuer_did
        self._default_expiry = default_expiry

    def issue_vouch(
        self, agent_data: Dict[str, Any], expiry_seconds: Optional[int] = None
    ) -> Dict[str, str]:
        """
        Issue a Vouch certificate for an agent.

        Args:
            agent_data: Dictionary containing:
                - did: The agent's DID (required)
                - integrity_hash: Hash of agent code/model (optional)
                - reputation_score: Reputation score 0-100 (optional, default: 50)
            expiry_seconds: Optional override for certificate expiry.

        Returns:
            Dictionary with 'certificate' key containing the JWS token.

        Raises:
            ValueError: If required fields are missing.
        """
        if not agent_data.get("did"):
            raise ValueError("agent_data must include 'did' field")

        now = int(time.time())
        exp = expiry_seconds if expiry_seconds is not None else self._default_expiry

        # Extract reputation score with default
        reputation_score = agent_data.get("reputation_score", self.DEFAULT_REPUTATION)

        # Clamp reputation to valid range
        reputation_score = max(0, min(100, reputation_score))

        # Build the verifiable credential payload
        payload = {
            "jti": str(uuid.uuid4()),
            "sub": agent_data.get("did"),
            "iss": self._issuer_did,
            "iat": now,
            "nbf": now,
            "exp": now + exp,
            "vc": {
                "type": ["VerifiableCredential", "VouchIdentityCredential"],
                "integrity_hash": agent_data.get("integrity_hash", ""),
                "reputation_score": reputation_score,
                "credential_type": "Identity+Reputation",
            },
        }

        # Create and sign the JWS
        token = jws.JWS(json.dumps(payload, sort_keys=True, separators=(",", ":")))

        protected_header = {
            "alg": "EdDSA",
            "typ": "vc+jwt",
            "kid": self._signing_key.get("kid") or self._issuer_did,
        }

        token.add_signature(self._signing_key, None, json_encode(protected_header), None)

        return {"certificate": token.serialize(compact=True)}

    def get_public_key_jwk(self) -> str:
        """Returns the public key in JWK format for verification."""
        return self._signing_key.export_public()

    def get_issuer_did(self) -> str:
        """Returns the issuer DID."""
        return self._issuer_did
