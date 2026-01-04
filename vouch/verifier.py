"""
Vouch Protocol Verifier - Cryptographically verifies Vouch-Tokens.

This module provides verification functionality for the Vouch Protocol,
validating signatures, timestamps, and extracting claims from tokens.
"""

import json
import time
import logging
from typing import Tuple, Optional, Dict, Any, Union, List
from dataclasses import dataclass, field

from jwcrypto import jwk, jws
from jwcrypto.common import JWException
import httpx


logger = logging.getLogger(__name__)


@dataclass
class DelegationLink:
    """
    Represents a single link in a delegation chain.

    Attributes:
        iss: Issuer - who delegated authority
        sub: Subject - who received the delegation
        intent: The intent/action that was authorized
        iat: When the delegation was made
        signature: Cryptographic signature of this delegation
    """

    iss: str
    sub: str
    intent: str
    iat: int
    signature: str


@dataclass
class Passport:
    """
    Represents a verified Vouch identity claim.

    Attributes:
        sub: Subject (the agent's DID)
        iss: Issuer (who signed the token)
        iat: Issued-at timestamp
        exp: Expiration timestamp
        jti: JWT ID (unique nonce)
        payload: The signed intent/action data
        raw_claims: Full decoded JWT claims
        reputation_score: Agent's reputation score (0-100) if included in token
        delegation_chain: List of delegation links from root to current agent
    """

    sub: str
    iss: str
    iat: int
    exp: int
    jti: str
    payload: Dict[str, Any]
    raw_claims: Dict[str, Any]
    reputation_score: Optional[int] = None
    delegation_chain: List[DelegationLink] = field(default_factory=list)


class VerificationError(Exception):
    """Raised when token verification fails."""

    pass


class Verifier:
    """
    Verifies Vouch-Tokens using Ed25519 public keys.

    The Verifier validates JWS signatures, checks timestamps/expiration,
    and can fetch public keys from DID documents.

    Example:
        # Static verification with provided public key
        >>> valid, passport = Verifier.verify(token, public_key_jwk='{"kty":"OKP",...}')

        # Instance-based verification with trusted roots
        >>> verifier = Verifier(trusted_roots={'did:web:agent.com': public_key_jwk})
        >>> valid, passport = verifier.check_vouch(token)
    """

    # Cache for resolved DID public keys
    _key_cache: Dict[str, Tuple[jwk.JWK, float]] = {}
    _cache_ttl: int = 300  # 5 minutes

    def __init__(
        self,
        trusted_roots: Optional[Dict[str, str]] = None,
        allow_did_resolution: bool = True,
        clock_skew_seconds: int = 30,
    ):
        """
        Initialize the Verifier.

        Args:
            trusted_roots: Dict mapping DIDs to their public JWK strings.
            allow_did_resolution: If True, attempt to fetch unknown DIDs.
            clock_skew_seconds: Allowed clock drift for timestamp validation.
        """
        self._trusted_roots: Dict[str, jwk.JWK] = {}
        self._allow_resolution = allow_did_resolution
        self._clock_skew = clock_skew_seconds

        if trusted_roots:
            for did, key_json in trusted_roots.items():
                try:
                    self._trusted_roots[did] = jwk.JWK.from_json(key_json)
                except Exception as e:
                    logger.warning(f"Invalid key for {did}: {e}")

    @staticmethod
    def verify(
        token: str, public_key_jwk: Optional[str] = None, clock_skew_seconds: int = 30
    ) -> Tuple[bool, Optional[Passport]]:
        """
        Statically verify a Vouch-Token.

        Args:
            token: The JWS compact serialized Vouch-Token.
            public_key_jwk: JWK JSON string of the public key. If not provided,
                           verification will only check structure, not signature.
            clock_skew_seconds: Allowed clock drift for timestamps.

        Returns:
            Tuple of (is_valid, Passport or None)
        """
        if not token:
            return False, None

        try:
            # Parse the JWS
            jws_token = jws.JWS()
            jws_token.deserialize(token)

            # Get the payload (without verification first, to extract claims)
            # This is safe because we verify the signature below
            payload_bytes = jws_token.objects.get("payload", b"")
            if isinstance(payload_bytes, str):
                payload_bytes = payload_bytes.encode("utf-8")

            claims = json.loads(payload_bytes.decode("utf-8"))

            # Verify signature if public key provided
            if public_key_jwk:
                key = jwk.JWK.from_json(public_key_jwk)
                jws_token.verify(key)

            # Validate timestamps
            now = int(time.time())

            exp = claims.get("exp", 0)
            if exp and now > exp + clock_skew_seconds:
                logger.debug(f"Token expired: exp={exp}, now={now}")
                return False, None

            nbf = claims.get("nbf", 0)
            if nbf and now < nbf - clock_skew_seconds:
                logger.debug(f"Token not yet valid: nbf={nbf}, now={now}")
                return False, None

            iat = claims.get("iat", 0)
            if iat and now < iat - clock_skew_seconds:
                logger.debug(f"Token issued in future: iat={iat}, now={now}")
                return False, None

            # Extract vouch-specific payload
            vouch_data = claims.get("vouch", {})
            intent_payload = vouch_data.get("payload", {})
            reputation_score = vouch_data.get("reputation_score")

            # Extract delegation chain if present
            delegation_chain = []
            raw_chain = vouch_data.get("delegation_chain", [])
            for link_data in raw_chain:
                try:
                    delegation_chain.append(
                        DelegationLink(
                            iss=link_data.get("iss", ""),
                            sub=link_data.get("sub", ""),
                            intent=link_data.get("intent", ""),
                            iat=link_data.get("iat", 0),
                            signature=link_data.get("sig", ""),
                        )
                    )
                except Exception as e:
                    logger.debug(f"Invalid delegation link: {e}")

            passport = Passport(
                sub=claims.get("sub", ""),
                iss=claims.get("iss", ""),
                iat=iat,
                exp=exp,
                jti=claims.get("jti", ""),
                payload=intent_payload,
                raw_claims=claims,
                reputation_score=reputation_score,
                delegation_chain=delegation_chain,
            )

            return True, passport

        except JWException as e:
            logger.debug(f"JWS verification failed: {e}")
            return False, None
        except json.JSONDecodeError as e:
            logger.debug(f"Invalid JSON in token: {e}")
            return False, None
        except Exception as e:
            logger.debug(f"Verification error: {e}")
            return False, None

    def check_vouch(self, token: str) -> Tuple[bool, Optional[Passport]]:
        """
        Verify a token using trusted roots or DID resolution.

        Args:
            token: The JWS compact serialized Vouch-Token.

        Returns:
            Tuple of (is_valid, Passport or None)
        """
        if not token:
            return False, None

        try:
            # First, decode without verification to get the issuer
            jws_token = jws.JWS()
            jws_token.deserialize(token)

            payload_bytes = jws_token.objects.get("payload", b"")
            if isinstance(payload_bytes, str):
                payload_bytes = payload_bytes.encode("utf-8")

            claims = json.loads(payload_bytes.decode("utf-8"))
            issuer_did = claims.get("iss", "")

            # Get the public key
            public_key = self._get_public_key(issuer_did)
            if not public_key:
                logger.warning(f"Could not resolve public key for: {issuer_did}")
                return False, None

            # Verify with the resolved key
            return Verifier.verify(
                token,
                public_key_jwk=public_key.export_public(),
                clock_skew_seconds=self._clock_skew,
            )

        except Exception as e:
            logger.debug(f"check_vouch error: {e}")
            return False, None

    def _get_public_key(self, did: str) -> Optional[jwk.JWK]:
        """Get public key from trusted roots or resolve from DID."""

        # Check trusted roots first
        if did in self._trusted_roots:
            return self._trusted_roots[did]

        # Check cache
        if did in self._key_cache:
            key, cached_at = self._key_cache[did]
            if time.time() - cached_at < self._cache_ttl:
                return key

        # Attempt DID resolution
        if self._allow_resolution and did.startswith("did:web:"):
            resolved_key = self._resolve_did_web(did)
            if resolved_key:
                self._key_cache[did] = (resolved_key, time.time())
                return resolved_key

        return None

    def _resolve_did_web(self, did: str) -> Optional[jwk.JWK]:
        """
        Resolve a did:web identifier to its public key.

        Args:
            did: A did:web identifier (e.g., did:web:example.com)

        Returns:
            JWK public key or None if resolution fails.
        """
        try:
            # Parse did:web format
            # did:web:example.com -> https://example.com/.well-known/did.json
            # did:web:example.com:path -> https://example.com/path/did.json
            parts = did.split(":")
            if len(parts) < 3:
                return None

            domain_and_path = ":".join(parts[2:])
            path_parts = domain_and_path.split(":")
            domain = path_parts[0]

            if len(path_parts) > 1:
                path = "/".join(path_parts[1:])
                url = f"https://{domain}/{path}/did.json"
            else:
                url = f"https://{domain}/.well-known/did.json"

            # Fetch DID document
            with httpx.Client(timeout=10.0) as client:
                response = client.get(url)
                response.raise_for_status()
                did_doc = response.json()

            # Extract verification method
            verification_methods = did_doc.get("verificationMethod", [])
            if not verification_methods:
                return None

            # Get first Ed25519 key
            for method in verification_methods:
                pub_key_jwk = method.get("publicKeyJwk", {})
                if pub_key_jwk.get("kty") == "OKP" and pub_key_jwk.get("crv") == "Ed25519":
                    return jwk.JWK(**pub_key_jwk)

            return None

        except Exception as e:
            logger.debug(f"DID resolution failed for {did}: {e}")
            return None

    def add_trusted_root(self, did: str, public_key_jwk: str) -> None:
        """Add a trusted DID and its public key."""
        try:
            self._trusted_roots[did] = jwk.JWK.from_json(public_key_jwk)
        except Exception as e:
            raise ValueError(f"Invalid JWK: {e}")

    def clear_cache(self) -> None:
        """Clear the resolved key cache."""
        self._key_cache.clear()
