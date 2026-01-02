"""
Vouch Protocol Signer - Cryptographically signs payloads using Ed25519 (JWS/JWK).

This module provides the core signing functionality for the Vouch Protocol,
generating verifiable tokens that bind agent identity to intent.
"""

import json
import time
import uuid
from typing import Dict, Any, Optional

from jwcrypto import jwk, jws
from jwcrypto.common import json_encode


class Signer:
    """
    Signs payloads to generate Vouch-Tokens using Ed25519 keys.
    
    The Signer creates JWS (JSON Web Signature) tokens that cryptographically
    bind an agent's DID to their stated intent with a timestamp.
    
    Example:
        >>> signer = Signer(private_key_jwk='{"kty":"OKP",...}', did='did:web:example.com')
        >>> token = signer.sign({'action': 'read_email'})
        
        # With reputation score
        >>> token = signer.sign({'action': 'read_email'}, reputation_score=85)
    """
    
    def __init__(self, private_key: str, did: str, default_expiry_seconds: int = 300):
        """
        Initialize the Signer with credentials.
        
        Args:
            private_key: JWK JSON string containing the Ed25519 private key.
            did: The Decentralized Identifier (DID) of the signing agent.
            default_expiry_seconds: Token validity period (default: 5 minutes).
            
        Raises:
            ValueError: If private_key or did is missing or invalid.
        """
        if not private_key:
            raise ValueError("Vouch Signer requires 'private_key' (JWK JSON string)")
        if not did:
            raise ValueError("Vouch Signer requires 'did' (Decentralized Identifier)")
        
        self.did = did
        self.default_expiry = default_expiry_seconds
        
        try:
            self._key = jwk.JWK.from_json(private_key)
            if self._key.key_type != 'OKP' or self._key.get('crv') != 'Ed25519':
                raise ValueError("Key must be an Ed25519 key (OKP with crv=Ed25519)")
        except Exception as e:
            raise ValueError(f"Invalid JWK private key: {e}")
    
    def sign(
        self, 
        payload: Dict[str, Any], 
        expiry_seconds: Optional[int] = None,
        reputation_score: Optional[int] = None
    ) -> str:
        """
        Signs a payload and returns a Vouch-Token (JWS compact serialization).
        
        Args:
            payload: Dictionary containing the intent/action data to sign.
            expiry_seconds: Optional override for token expiry time.
            reputation_score: Optional reputation score (0-100) to include in token.
                             Allows servers to see the agent's trustworthiness.
            
        Returns:
            A JWS compact serialized token string (the Vouch-Token).
        """
        now = int(time.time())
        exp = expiry_seconds if expiry_seconds is not None else self.default_expiry
        
        # Build the vouch claim
        vouch_claim = {
            "version": "1.0",
            "payload": payload
        }
        
        # Add reputation if provided (clamp to valid range)
        if reputation_score is not None:
            vouch_claim["reputation_score"] = max(0, min(100, reputation_score))
        
        # Build the JWT claims
        claims = {
            "jti": str(uuid.uuid4()),           # Unique token ID (nonce)
            "iss": self.did,                     # Issuer (the signing agent)
            "sub": self.did,                     # Subject (same as issuer for self-signed)
            "iat": now,                          # Issued at
            "nbf": now,                          # Not before
            "exp": now + exp,                    # Expiration
            "vouch": vouch_claim
        }
        
        # Create the JWS
        token = jws.JWS(json.dumps(claims, sort_keys=True, separators=(',', ':')))
        
        # Sign with EdDSA algorithm
        protected_header = {
            "alg": "EdDSA",
            "typ": "vouch+jwt",
            "kid": self._key.key_id if self._key.key_id else self.did
        }
        
        token.add_signature(
            self._key,
            None,
            json_encode(protected_header),
            None
        )
        
        return token.serialize(compact=True)
    
    def get_public_key_jwk(self) -> str:
        """
        Returns the public key in JWK format for verification.
        
        Returns:
            JSON string of the public JWK.
        """
        return self._key.export_public()
    
    def get_did(self) -> str:
        """Returns the DID of this signer."""
        return self.did
