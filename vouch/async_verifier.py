"""
Vouch Protocol Async Verifier - High-performance async verification.

Provides async verification with caching, nonce tracking, and batch
operations for enterprise-scale deployments.
"""

import json
import time
import logging
import asyncio
from typing import Tuple, Optional, Dict, Any, List
from dataclasses import dataclass

from jwcrypto import jwk, jws
from jwcrypto.common import JWException
import httpx

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vouch.verifier import (
    Passport,
    CredentialPassport,
    VerificationError,
    Verifier,
)
from vouch.cache import CacheInterface, MemoryCache
from vouch.nonce import NonceTrackerInterface, MemoryNonceTracker
from vouch import did_web


logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of a batch verification."""

    token_index: int
    is_valid: bool
    passport: Optional[Passport]
    error: Optional[str] = None


class AsyncVerifier:
    """
    High-performance async Vouch-Token verifier.

    Provides:
    - Async DID resolution with connection pooling
    - Pluggable caching (memory, Redis, tiered)
    - Nonce tracking for replay prevention
    - Batch verification for high throughput

    Example:
        >>> from vouch.async_verifier import AsyncVerifier
        >>> from vouch.cache import MemoryCache
        >>>
        >>> cache = MemoryCache()
        >>> verifier = AsyncVerifier(cache=cache)
        >>>
        >>> async with verifier:
        ...     valid, passport = await verifier.verify(token, public_key_jwk)
    """

    def __init__(
        self,
        trusted_roots: Optional[Dict[str, str]] = None,
        cache: Optional[CacheInterface] = None,
        nonce_tracker: Optional[NonceTrackerInterface] = None,
        allow_did_resolution: bool = True,
        clock_skew_seconds: int = 30,
        http_timeout: float = 10.0,
        max_connections: int = 100,
    ):
        """
        Initialize the async verifier.

        Args:
            trusted_roots: Dict mapping DIDs to their public JWK strings.
            cache: Cache implementation for public keys.
            nonce_tracker: Nonce tracker for replay prevention.
            allow_did_resolution: If True, attempt to fetch unknown DIDs.
            clock_skew_seconds: Allowed clock drift for timestamp validation.
            http_timeout: Timeout for DID resolution requests.
            max_connections: Max concurrent HTTP connections.
        """
        self._trusted_roots: Dict[str, jwk.JWK] = {}
        self._cache = cache or MemoryCache()
        self._nonce_tracker = nonce_tracker
        self._allow_resolution = allow_did_resolution
        self._clock_skew = clock_skew_seconds
        self._http_timeout = http_timeout
        self._max_connections = max_connections
        self._http_client: Optional[httpx.AsyncClient] = None

        # Stats
        self._stats = {
            "verifications": 0,
            "successes": 0,
            "failures": 0,
            "cache_hits": 0,
            "did_resolutions": 0,
            "replays_blocked": 0,
        }

        if trusted_roots:
            for did, key_json in trusted_roots.items():
                try:
                    self._trusted_roots[did] = jwk.JWK.from_json(key_json)
                except Exception as e:
                    logger.warning(f"Invalid key for {did}: {e}")

    async def __aenter__(self):
        """Async context manager entry."""
        self._http_client = httpx.AsyncClient(
            timeout=self._http_timeout, limits=httpx.Limits(max_connections=self._max_connections)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def verify(
        self, token: str, public_key_jwk: Optional[str] = None, check_nonce: bool = True
    ) -> Tuple[bool, Optional[Passport]]:
        """
        Verify a Vouch-Token asynchronously.

        Args:
            token: The JWS compact serialized Vouch-Token.
            public_key_jwk: JWK JSON string of the public key.
            check_nonce: Whether to check/track nonce for replay prevention.

        Returns:
            Tuple of (is_valid, Passport or None)
        """
        self._stats["verifications"] += 1

        if not token:
            self._stats["failures"] += 1
            return False, None

        try:
            # Parse the JWS
            jws_token = jws.JWS()
            jws_token.deserialize(token)

            # Extract payload
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
            if exp and now > exp + self._clock_skew:
                logger.debug(f"Token expired: exp={exp}, now={now}")
                self._stats["failures"] += 1
                return False, None

            nbf = claims.get("nbf", 0)
            if nbf and now < nbf - self._clock_skew:
                logger.debug(f"Token not yet valid: nbf={nbf}, now={now}")
                self._stats["failures"] += 1
                return False, None

            # Check nonce for replay
            jti = claims.get("jti", "")
            if check_nonce and self._nonce_tracker and jti:
                if await self._nonce_tracker.is_used(jti):
                    logger.warning(f"Replay attack blocked: jti={jti}")
                    self._stats["replays_blocked"] += 1
                    self._stats["failures"] += 1
                    return False, None

                # Mark nonce as used
                await self._nonce_tracker.mark_used(jti, exp)

            # Build passport
            vouch_data = claims.get("vouch", {})
            intent_payload = vouch_data.get("payload", {})

            passport = Passport(
                sub=claims.get("sub", ""),
                iss=claims.get("iss", ""),
                iat=claims.get("iat", 0),
                exp=exp,
                jti=jti,
                payload=intent_payload,
                raw_claims=claims,
            )

            self._stats["successes"] += 1
            return True, passport

        except JWException as e:
            logger.debug(f"JWS verification failed: {e}")
            self._stats["failures"] += 1
            return False, None
        except json.JSONDecodeError as e:
            logger.debug(f"Invalid JSON in token: {e}")
            self._stats["failures"] += 1
            return False, None
        except Exception as e:
            logger.debug(f"Verification error: {e}")
            self._stats["failures"] += 1
            return False, None

    async def check_vouch(
        self, token: str, check_nonce: bool = True
    ) -> Tuple[bool, Optional[Passport]]:
        """
        Verify a token using trusted roots, cache, or DID resolution.

        Args:
            token: The JWS compact serialized Vouch-Token.
            check_nonce: Whether to check nonce for replay prevention.

        Returns:
            Tuple of (is_valid, Passport or None)
        """
        if not token:
            return False, None

        try:
            # Parse to get issuer
            jws_token = jws.JWS()
            jws_token.deserialize(token)

            payload_bytes = jws_token.objects.get("payload", b"")
            if isinstance(payload_bytes, str):
                payload_bytes = payload_bytes.encode("utf-8")

            claims = json.loads(payload_bytes.decode("utf-8"))
            issuer_did = claims.get("iss", "")

            # Get public key
            public_key = await self._get_public_key(issuer_did)
            if not public_key:
                logger.warning(f"Could not resolve public key for: {issuer_did}")
                return False, None

            return await self.verify(token, public_key_jwk=public_key, check_nonce=check_nonce)

        except Exception as e:
            logger.debug(f"check_vouch error: {e}")
            return False, None

    async def verify_batch(
        self,
        tokens: List[str],
        public_key_jwk: Optional[str] = None,
        check_nonce: bool = True,
        max_concurrent: int = 50,
    ) -> List[VerificationResult]:
        """
        Verify multiple tokens concurrently.

        Args:
            tokens: List of tokens to verify.
            public_key_jwk: Optional public key for all tokens.
            check_nonce: Whether to check nonces.
            max_concurrent: Maximum concurrent verifications.

        Returns:
            List of VerificationResult objects.
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def verify_one(index: int, token: str) -> VerificationResult:
            async with semaphore:
                try:
                    valid, passport = await self.verify(
                        token, public_key_jwk=public_key_jwk, check_nonce=check_nonce
                    )
                    return VerificationResult(token_index=index, is_valid=valid, passport=passport)
                except Exception as e:
                    return VerificationResult(
                        token_index=index, is_valid=False, passport=None, error=str(e)
                    )

        tasks = [verify_one(i, token) for i, token in enumerate(tokens)]
        results = await asyncio.gather(*tasks)

        return list(results)

    async def _get_public_key(self, did: str) -> Optional[str]:
        """Get public key from trusted roots, cache, or DID resolution."""

        # Check trusted roots first
        if did in self._trusted_roots:
            return self._trusted_roots[did].export_public()

        # Check cache
        cached = await self._cache.get(did)
        if cached:
            self._stats["cache_hits"] += 1
            return cached

        # Attempt DID resolution
        if self._allow_resolution and did.startswith("did:web:"):
            self._stats["did_resolutions"] += 1
            resolved = await self._resolve_did_web(did)
            if resolved:
                await self._cache.set(did, resolved)
                return resolved

        return None

    async def _resolve_did_web(self, did: str) -> Optional[str]:
        """Async DID resolution with connection pooling."""
        try:
            # Parse did:web format
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

            # Use pooled client if available
            client = self._http_client or httpx.AsyncClient(timeout=self._http_timeout)

            try:
                response = await client.get(url)
                response.raise_for_status()
                did_doc = response.json()
            finally:
                if not self._http_client:
                    await client.aclose()

            # Extract verification method
            verification_methods = did_doc.get("verificationMethod", [])
            for method in verification_methods:
                pub_key_jwk = method.get("publicKeyJwk", {})
                if pub_key_jwk.get("kty") == "OKP" and pub_key_jwk.get("crv") == "Ed25519":
                    return json.dumps(pub_key_jwk)

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

    async def clear_cache(self) -> None:
        """Clear the key cache."""
        await self._cache.clear()

    @property
    def stats(self) -> Dict[str, int]:
        """Return verification statistics."""
        return self._stats.copy()

    # ------------------------------------------------------------------
    # Modern path: W3C Verifiable Credentials with Data Integrity proofs
    # ------------------------------------------------------------------

    async def verify_credential(
        self,
        credential,
        public_key=None,
    ) -> Tuple[bool, Optional[CredentialPassport]]:
        """
        Verify a W3C Vouch Credential. The cryptographic check is delegated to
        the synchronous `Verifier.verify_credential`, since Ed25519 verification
        is fast and CPU-bound (offloading to a thread adds more overhead than
        it saves). DID resolution is async.

        See `Verifier.verify_credential` for argument semantics.
        """
        return Verifier.verify_credential(
            credential,
            public_key=public_key,
            clock_skew_seconds=self._clock_skew,
        )

    async def check_vouch_credential(
        self,
        credential,
    ) -> Tuple[bool, Optional[CredentialPassport]]:
        """
        Async equivalent of `Verifier.check_vouch_credential`. Resolves the
        issuer's Multikey via async did:web resolution and the local cache.
        """
        if not credential:
            return False, None

        try:
            cred = json.loads(credential) if isinstance(credential, str) else credential
            if not isinstance(cred, dict):
                return False, None

            issuer_did = cred.get("issuer")
            if isinstance(issuer_did, list):
                issuer_did = issuer_did[0] if issuer_did else ""
            if not issuer_did:
                return False, None

            proof = cred.get("proof") or {}
            vm_id = proof.get("verificationMethod") if isinstance(proof, dict) else None

            public_key = await self._resolve_credential_public_key_async(issuer_did, vm_id)
            if public_key is None:
                logger.warning(f"Could not resolve Multikey for: {issuer_did}")
                return False, None

            return Verifier.verify_credential(
                cred,
                public_key=public_key,
                clock_skew_seconds=self._clock_skew,
            )
        except Exception as e:
            logger.debug(f"check_vouch_credential error: {e}")
            return False, None

    async def _resolve_credential_public_key_async(
        self,
        did: str,
        verification_method_id: Optional[str] = None,
    ) -> Optional[Ed25519PublicKey]:
        """Async resolve Ed25519 public key from did:web for VC verification."""
        # Trusted root override
        if did in self._trusted_roots:
            jwk_obj = self._trusted_roots[did]
            try:
                jwk_dict = json.loads(jwk_obj.export_public())
                from jwcrypto.common import base64url_decode

                if jwk_dict.get("kty") == "OKP" and jwk_dict.get("crv") == "Ed25519":
                    return Ed25519PublicKey.from_public_bytes(base64url_decode(jwk_dict["x"]))
            except Exception:  # pragma: no cover
                pass

        if not (self._allow_resolution and did.startswith("did:web:")):
            return None

        try:
            # Async DID resolution using vouch.did_web helpers
            doc = await did_web.resolve_did_web(did, timeout=self._http_timeout)
            return doc.get_ed25519_public_key(verification_method_id)
        except Exception as e:
            logger.debug(f"Async DID resolution failed for {did}: {e}")
            return None
