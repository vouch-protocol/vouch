"""
Vouch Protocol Verifier.

Verifies both legacy JWS-format Vouch-Tokens and modern W3C Verifiable
Credentials with Data Integrity proofs (eddsa-jcs-2022).

Two coexisting verification paths:

    1. Legacy JWS: `Verifier.verify(token, ...)` and `Verifier.check_vouch(token)`.
       Operates on JWS Compact Serialization strings produced by `Signer.sign()`.

    2. W3C VC: `Verifier.verify_credential(credential, ...)` and
       `Verifier.check_vouch_credential(credential)`. Operates on credential
       dicts produced by `Signer.sign_credential()` (see W3C CG Report §8).

Existing callers of the legacy methods continue to work unchanged. New callers
should prefer the credential methods.
"""

import json
import time
import logging
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any, Union, List
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from jwcrypto import jwk, jws
from jwcrypto.common import JWException
import httpx

from . import data_integrity, did_web, multikey


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


@dataclass
class CredentialDelegationLink:
    """
    A single link in a W3C VC delegation chain (W3C CG Report §9.2).

    Distinct shape from the legacy DelegationLink used in JWS-format tokens.
    """

    issuer: str
    subject: str
    intent: Dict[str, Any]
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    parent_proof_value: Optional[str] = None


@dataclass
class CredentialPassport:
    """
    Verified W3C Verifiable Credential issued under Vouch Protocol v1.0.

    Returned by `Verifier.verify_credential()` and
    `Verifier.check_vouch_credential()`. Parallel to the legacy `Passport`
    dataclass; new code should prefer this type.

    Attributes:
        sub: credentialSubject.id (the agent's DID)
        iss: issuer (DID that signed the credential)
        valid_from: ISO 8601 timestamp string
        valid_until: ISO 8601 timestamp string
        credential_id: The credential's `id` field (e.g. urn:uuid:...)
        intent: Intent payload (action, target, resource)
        reputation_score: Optional self-reported reputation in [0, 100]
        delegation_chain: Ordered list of delegation links from root to current
        raw_credential: Full verified credential dict
    """

    sub: str
    iss: str
    valid_from: str
    valid_until: str
    credential_id: str
    intent: Dict[str, Any]
    raw_credential: Dict[str, Any]
    reputation_score: Optional[int] = None
    delegation_chain: List[CredentialDelegationLink] = field(default_factory=list)


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

    # ------------------------------------------------------------------
    # Modern path: W3C Verifiable Credentials with Data Integrity proofs
    # ------------------------------------------------------------------

    @staticmethod
    def verify_credential(
        credential: Union[Dict[str, Any], str],
        public_key: Optional[Union[Ed25519PublicKey, str]] = None,
        clock_skew_seconds: int = 30,
    ) -> Tuple[bool, Optional[CredentialPassport]]:
        """
        Verify a W3C Verifiable Credential issued under Vouch Protocol v1.0.

        Performs the full verification flow per W3C CG Report §8.1:
            1. Parse the credential.
            2. Verify the Data Integrity proof (eddsa-jcs-2022).
            3. Validate temporal claims (validFrom, validUntil).
            4. Validate the required `intent.resource` binding.
            5. Build a CredentialPassport.

        Args:
            credential: A Vouch Credential dict OR a JSON-encoded string.
            public_key: An `Ed25519PublicKey` instance, or a Multikey string,
                or None. If None, only structural and temporal checks run.
            clock_skew_seconds: Allowed clock drift for timestamp validation.

        Returns:
            Tuple of (is_valid, CredentialPassport or None).
        """
        if not credential:
            return False, None

        # Parse if given as a JSON string
        try:
            if isinstance(credential, str):
                cred = json.loads(credential)
            else:
                cred = credential
        except json.JSONDecodeError as e:
            logger.debug(f"Invalid credential JSON: {e}")
            return False, None

        if not isinstance(cred, dict):
            return False, None

        # Verify the Data Integrity proof if a key was provided
        if public_key is not None:
            try:
                resolved = _coerce_ed25519_public_key(public_key)
                if resolved is None:
                    logger.debug("Could not coerce public_key to Ed25519PublicKey")
                    return False, None
                if not data_integrity.verify_proof(cred, resolved):
                    logger.debug("Data Integrity proof verification failed")
                    return False, None
            except ValueError as e:
                logger.debug(f"Proof verification raised: {e}")
                return False, None
            except InvalidSignature:
                return False, None

        # Validate temporal claims
        now = datetime.now(timezone.utc)
        valid_from = _parse_iso8601(cred.get("validFrom"))
        valid_until = _parse_iso8601(cred.get("validUntil"))

        if valid_until is None or valid_from is None:
            logger.debug("Credential missing validFrom or validUntil")
            return False, None

        skew = clock_skew_seconds
        if (now - valid_until).total_seconds() > skew:
            logger.debug("Credential expired")
            return False, None
        if (valid_from - now).total_seconds() > skew:
            logger.debug("Credential not yet valid")
            return False, None

        # Validate required intent.resource binding (§5.4.1, §8.4)
        subject = cred.get("credentialSubject") or {}
        if not isinstance(subject, dict):
            return False, None
        intent = subject.get("intent") or {}
        if not isinstance(intent, dict):
            return False, None
        resource = intent.get("resource")
        if not resource:
            logger.debug("Credential missing required intent.resource")
            return False, None

        # Build the CredentialPassport
        chain = []
        for raw_link in subject.get("delegationChain", []) or []:
            try:
                chain.append(
                    CredentialDelegationLink(
                        issuer=raw_link.get("issuer", ""),
                        subject=raw_link.get("subject", ""),
                        intent=raw_link.get("intent", {}) or {},
                        valid_from=raw_link.get("validFrom"),
                        valid_until=raw_link.get("validUntil"),
                        parent_proof_value=raw_link.get("parentProofValue"),
                    )
                )
            except Exception as e:  # pragma: no cover
                logger.debug(f"Invalid delegation link: {e}")

        rep_score = subject.get("reputationScore")
        if rep_score is not None:
            try:
                rep_score = int(rep_score)
            except (TypeError, ValueError):
                rep_score = None

        passport = CredentialPassport(
            sub=subject.get("id", ""),
            iss=cred.get("issuer", "") if isinstance(cred.get("issuer"), str)
                else (cred.get("issuer") or [""])[0],
            valid_from=cred.get("validFrom", ""),
            valid_until=cred.get("validUntil", ""),
            credential_id=cred.get("id", ""),
            intent=intent,
            raw_credential=cred,
            reputation_score=rep_score,
            delegation_chain=chain,
        )

        return True, passport

    def check_vouch_credential(
        self,
        credential: Union[Dict[str, Any], str],
    ) -> Tuple[bool, Optional[CredentialPassport]]:
        """
        Verify a W3C Vouch Credential, resolving the issuer key from trusted
        roots or via DID resolution (`did:web`).

        Mirrors `check_vouch()` for the modern credential format.
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

            # Determine which verification method the proof points at
            proof = cred.get("proof") or {}
            vm_id = proof.get("verificationMethod") if isinstance(proof, dict) else None

            public_key = self._resolve_credential_public_key(issuer_did, vm_id)
            if public_key is None:
                logger.warning(f"Could not resolve Multikey/JWK for: {issuer_did}")
                return False, None

            return Verifier.verify_credential(
                cred,
                public_key=public_key,
                clock_skew_seconds=self._clock_skew,
            )
        except Exception as e:
            logger.debug(f"check_vouch_credential error: {e}")
            return False, None

    def _resolve_credential_public_key(
        self,
        did: str,
        verification_method_id: Optional[str] = None,
    ) -> Optional[Ed25519PublicKey]:
        """Resolve an Ed25519PublicKey for the modern credential path."""
        # Trusted root override (legacy JWK form is acceptable, we coerce)
        if did in self._trusted_roots:
            jwk_obj = self._trusted_roots[did]
            try:
                jwk_dict = json.loads(jwk_obj.export_public())
                from jwcrypto.common import base64url_decode

                if jwk_dict.get("kty") == "OKP" and jwk_dict.get("crv") == "Ed25519":
                    return Ed25519PublicKey.from_public_bytes(
                        base64url_decode(jwk_dict["x"])
                    )
            except Exception:  # pragma: no cover
                pass

        if not (self._allow_resolution and did.startswith("did:web:")):
            return None

        try:
            doc = did_web.resolve_did_web_sync(did)
            return doc.get_ed25519_public_key(verification_method_id)
        except Exception as e:
            logger.debug(f"DID resolution failed for {did}: {e}")
            return None


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


def _coerce_ed25519_public_key(
    public_key: Union[Ed25519PublicKey, str, Dict[str, Any]],
) -> Optional[Ed25519PublicKey]:
    """Accept Ed25519PublicKey, Multikey string, or JWK dict/string."""
    if isinstance(public_key, Ed25519PublicKey):
        return public_key

    # Multikey string (z-prefixed base58btc)
    if isinstance(public_key, str) and public_key.startswith("z"):
        try:
            alg, raw = multikey.decode(public_key)
            if alg == "Ed25519":
                return Ed25519PublicKey.from_public_bytes(raw)
        except ValueError:
            return None
        return None

    # JWK as JSON string or dict
    jwk_dict: Optional[Dict[str, Any]] = None
    if isinstance(public_key, str):
        try:
            jwk_dict = json.loads(public_key)
        except json.JSONDecodeError:
            return None
    elif isinstance(public_key, dict):
        jwk_dict = public_key

    if jwk_dict and jwk_dict.get("kty") == "OKP" and jwk_dict.get("crv") == "Ed25519":
        from jwcrypto.common import base64url_decode

        try:
            return Ed25519PublicKey.from_public_bytes(base64url_decode(jwk_dict["x"]))
        except Exception:
            return None

    return None


def _parse_iso8601(value: Optional[str]) -> Optional[datetime]:
    """Parse W3C VC datetime strings. Returns timezone-aware UTC datetime."""
    if not value or not isinstance(value, str):
        return None
    try:
        # Accept "...Z" and "...+00:00" forms
        if value.endswith("Z"):
            dt = datetime.fromisoformat(value[:-1] + "+00:00")
        else:
            dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None
