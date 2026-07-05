"""
Vouch Protocol Auditor - a certificate authority for audit trails.

The Auditor issues Vouch Credentials that bind an agent's identity to a
reputation score and an integrity hash (a code/model fingerprint). Together
these form an auditable trail of who attested what about whom. Certificates
are issued as W3C Verifiable Credentials with an eddsa-jcs-2022 Data Integrity
proof, verifiable with the same `Verifier.verify` as any other credential.
"""

import logging
from typing import Any, Dict, Optional

from vouch.signer import Signer


logger = logging.getLogger(__name__)


class Auditor:
    """
    Issues Vouch Credentials binding identity to reputation.

    Each certificate carries:
    - the agent DID it attests (intent.target / credentialSubject.id)
    - a reputation score (credentialSubject.reputationScore)
    - an integrity hash, the agent's code/model fingerprint (intent.integrity_hash)
    - a validity window

    Example:
        >>> auditor = Auditor(private_key_json='{"kty":"OKP",...}')
        >>> cert = auditor.issue_vouch({
        ...     'did': 'did:web:agent.com',
        ...     'integrity_hash': 'sha256:abc123...',
        ...     'reputation_score': 85,
        ... })
        >>> credential = cert['certificate']   # a Verifiable Credential dict
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
            ValueError: If the private key is missing or invalid.
        """
        if not private_key_json:
            raise ValueError("Auditor requires a private key (JWK JSON string)")

        self._signer = Signer(
            private_key=private_key_json,
            did=issuer_did,
            default_expiry_seconds=default_expiry,
        )
        self._issuer_did = issuer_did
        self._default_expiry = default_expiry

    def issue_vouch(
        self, agent_data: Dict[str, Any], expiry_seconds: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Issue a Vouch certificate for an agent.

        Args:
            agent_data: Dictionary containing:
                - did: The agent's DID (required)
                - integrity_hash: Hash of agent code/model (optional)
                - reputation_score: Reputation score 0-100 (optional, default: 50)
            expiry_seconds: Optional override for certificate expiry.

        Returns:
            Dictionary with a 'certificate' key holding a Verifiable Credential.

        Raises:
            ValueError: If required fields are missing.
        """
        agent_did = agent_data.get("did")
        if not agent_did:
            raise ValueError("agent_data must include 'did' field")

        exp = expiry_seconds if expiry_seconds is not None else self._default_expiry
        reputation_score = max(
            0, min(100, agent_data.get("reputation_score", self.DEFAULT_REPUTATION))
        )

        intent = {
            "action": "certify_identity",
            "target": agent_did,
            "resource": agent_did,
            "integrity_hash": agent_data.get("integrity_hash", ""),
            "credential_type": "Identity+Reputation",
        }

        credential = self._signer.sign(
            intent=intent,
            reputation_score=reputation_score,
            valid_seconds=exp,
        )

        return {"certificate": credential}

    def get_public_key_jwk(self) -> str:
        """Returns the public key in JWK format for verification."""
        return self._signer.get_public_key_jwk()

    def get_issuer_did(self) -> str:
        """Returns the issuer DID."""
        return self._issuer_did
