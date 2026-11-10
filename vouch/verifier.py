"""
Vouch Protocol Verifier.

Verifies W3C Verifiable Credentials with Data Integrity proofs
(eddsa-jcs-2022) via ``Verifier.verify(credential, ...)`` and
``Verifier.check_vouch_credential(credential)`` (see Specification §8). The
issuer key is supplied directly or resolved from the issuer's did:web document.
"""

import json
import time
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union
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
    A single link in a VC delegation chain (Specification §9.2).

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
    Verified Verifiable Credential issued under Vouch Protocol v1.0.

    Returned by `Verifier.verify()` and
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

    # Convenience accessors so callers can read what was authorized without
    # reaching into `intent` or `raw_credential` by hand.

    @property
    def action(self) -> Optional[str]:
        """The intent action that was signed, if present."""
        return (self.intent or {}).get("action")

    @property
    def target(self) -> Optional[str]:
        """The intent target that was signed, if present."""
        return (self.intent or {}).get("target")

    @property
    def resource(self) -> Optional[str]:
        """The intent resource that was signed, if present."""
        return (self.intent or {}).get("resource")

    @property
    def issuer(self) -> str:
        """The issuer DID. Alias for :attr:`iss`."""
        return self.iss

    @property
    def is_expired(self) -> bool:
        """True if the credential's validity window has passed.

        Independent of the clock skew applied during verification: this is a
        plain "is it past validUntil now" check for display and policy logic.
        """
        expires = _parse_iso8601(self.valid_until)
        if expires is None:
            return False
        return datetime.now(timezone.utc) > expires


class Verifier:
    """
    Verifies Vouch Credentials using Ed25519 public keys.

    Validates the Data Integrity proof, the validity window, and the intent,
    and can resolve the issuer's public key from its did:web document.

    Example:
      >>> valid, passport = Verifier.verify(credential, public_key=issuer_key)
    """

    # Cache for resolved DID public keys
    _key_cache: Dict[str, Tuple[jwk.JWK, float]] = {}
    _cache_ttl: int = 300  # 5 minutes
    # Bound the cache so distinct attacker-supplied DIDs cannot grow it without
    # limit (memory DoS).
    _key_cache_max: int = 1024

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
                if len(self._key_cache) >= self._key_cache_max and did not in self._key_cache:
                    # Evict the oldest entry to keep the cache bounded.
                    oldest = min(self._key_cache, key=lambda d: self._key_cache[d][1])
                    del self._key_cache[oldest]
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
    # Modern path: Verifiable Credentials with Data Integrity proofs
    # ------------------------------------------------------------------

    @staticmethod
    def verify(
        credential: Union[Dict[str, Any], str],
        public_key: Optional[Union[Ed25519PublicKey, str]] = None,
        clock_skew_seconds: int = 30,
        *,
        key_resolver: Optional[Callable[[str], Any]] = None,
        trusted_roots: Optional[Any] = None,
        now: Optional[datetime] = None,
    ) -> Tuple[bool, Optional[CredentialPassport]]:
        """
        Verify a Verifiable Credential issued under Vouch Protocol v1.0.

        Performs the full verification flow per Specification §8.1:
          1. Parse the credential.
          2. Verify the Data Integrity proof (eddsa-jcs-2022).
          3. Validate temporal claims (validFrom, validUntil).
          4. Validate the required `intent.resource` binding.
          5. Verify the embedded delegation chain, if any
             (`verify_delegation_chain`, Specification §9.3).
          6. Build a CredentialPassport.

        Args:
          credential: A Vouch Credential dict OR a JSON-encoded string.
          public_key: An `Ed25519PublicKey` instance, or a Multikey string,
            or None. If None, the credential's own proof is not checked; the
            delegation chain, if present, is still verified.
          clock_skew_seconds: Allowed clock drift for timestamp validation.
          key_resolver: Optional `did -> key` callable used to resolve the keys
            of the delegation chain's grant issuers. `did:key` issuers always
            resolve offline.
          trusted_roots: Optional root anchors for the delegation chain: either
            a `{did: key}` map (keys are also used for resolution) or a list of
            DIDs. When given, the chain's root issuer must be one of them.
          now: Evaluation time for the validity windows (default: now, UTC).

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

        # A `proof` array is a post-quantum proof set (an Ed25519 proof
        # alongside an ML-DSA-44 proof). This generic verifier checks only the
        # classical eddsa-jcs-2022 proof and has no ML-DSA-44 key to check the
        # post-quantum half, so it cannot validate a proof set. Fail closed with
        # a clear reason here instead of letting data_integrity.verify_proof
        # raise an incidental "no proof object" error that reads like a bad
        # signature. Post-quantum credentials must be verified with
        # vouch.data_integrity_hybrid.verify_dual or
        # vouch.robotics.verify_robot_credential, which take the ML-DSA-44 key.
        if isinstance(cred.get("proof"), list):
            logger.debug(
                "Credential carries a proof set (post-quantum); verify it with "
                "verify_dual or verify_robot_credential, which take an "
                "ML-DSA-44 key"
            )
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

        # Bind the proof to the issuer and enforce its purpose. A signature is
        # only meaningful if the key that made it is the issuer's key, used for
        # the right purpose. Without this, a key trusted for issuer A could sign
        # a credential claiming issuer B (cross-issuer reuse), and a proof made
        # for an unrelated purpose could be replayed as an assertion.
        proof = cred.get("proof")
        if isinstance(proof, dict):
            if proof.get("proofPurpose") != "assertionMethod":
                logger.debug("Proof proofPurpose is not assertionMethod")
                return False, None
            issuer = cred.get("issuer")
            issuer_did = issuer[0] if isinstance(issuer, list) and issuer else issuer
            vm = proof.get("verificationMethod")
            if isinstance(issuer_did, str) and issuer_did:
                if not isinstance(vm, str) or not vm:
                    logger.debug("Proof missing verificationMethod")
                    return False, None
                if vm.split("#", 1)[0] != issuer_did:
                    logger.debug("verificationMethod does not belong to issuer")
                    return False, None

        # Validate temporal claims
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
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

        # Verify the delegation chain (Specification §9.3): each grant's
        # signature, the parent -> child linkage, expiry, and non-expansion.
        if subject.get("delegationChain"):
            chain_reason = verify_delegation_chain(
                cred,
                key_resolver=key_resolver,
                trusted_roots=trusted_roots,
                clock_skew_seconds=skew,
                now=now,
            )
            if chain_reason is not None:
                logger.debug(f"Delegation chain rejected: {chain_reason}")
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
            iss=cred.get("issuer", "")
            if isinstance(cred.get("issuer"), str)
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
        *,
        key_resolver: Optional[Callable[[str], Any]] = None,
        trusted_roots: Optional[Any] = None,
    ) -> Tuple[bool, Optional[CredentialPassport]]:
        """
        Verify a W3C Vouch Credential, resolving the issuer key from trusted
        roots or via DID resolution (`did:web`).

        Delegation-chain grant issuers resolve through `key_resolver` when
        given, otherwise through this verifier's own trusted roots and DID
        resolution.

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

            return Verifier.verify(
                cred,
                public_key=public_key,
                clock_skew_seconds=self._clock_skew,
                key_resolver=key_resolver or self._resolve_credential_public_key,
                trusted_roots=trusted_roots,
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
                    return Ed25519PublicKey.from_public_bytes(base64url_decode(jwk_dict["x"]))
            except Exception:  # pragma: no cover
                pass

        # did:key is self-certifying: the public key is encoded in the DID
        # itself, so it resolves offline with no network and is allowed even
        # when allow_did_resolution is False.
        if did.startswith("did:key:"):
            return _resolve_did_key(did)

        if not (self._allow_resolution and did.startswith("did:web:")):
            return None

        try:
            doc = did_web.resolve_did_web_sync(did)
            return doc.get_ed25519_public_key(verification_method_id)
        except Exception as e:
            logger.debug(f"DID resolution failed for {did}: {e}")
            return None


# ---------------------------------------------------------------------------
# One-line verification (the receiving-side counterpart to vouch.protect)
# ---------------------------------------------------------------------------

# A cached resolver-enabled Verifier so the convenience helper does not rebuild
# (and re-warm DID caches) on every call.
_DEFAULT_VERIFIER: Optional["Verifier"] = None


def verify(
    credential: Optional[Union[Dict[str, Any], str]] = None,
    public_key: Optional[Union[Ed25519PublicKey, str]] = None,
    *,
    allow_did_resolution: bool = True,
    key_resolver: Optional[Callable[[str], Any]] = None,
    trusted_roots: Optional[Any] = None,
) -> Tuple[bool, Optional[CredentialPassport]]:
    """Verify a Vouch Credential in one line.

    The receiving-side counterpart to ``vouch.protect`` / ``vouch.sign_intent``::

        ok, passport = vouch.verify(credential)

    Args:
      credential: a Vouch Credential dict or JSON string. If ``None``, verifies
        the credential most recently signed in this execution context
        (``vouch.current_credential()``) - handy right after a protected call.
      public_key: an optional Multikey/JWK/``Ed25519PublicKey`` for OFFLINE
        verification. If omitted, the issuer's key is resolved automatically
        from trusted roots or ``did:web``.
      allow_did_resolution: set ``False`` to forbid network DID resolution
        (offline-only). With a ``public_key`` it still governs how delegation
        chain grant issuers are resolved.
      key_resolver / trusted_roots: see :meth:`Verifier.verify`; used for the
        delegation chain.

    Returns:
      ``(is_valid, CredentialPassport | None)``.
    """
    if credential is None:
        # Lazy import avoids a hard dependency cycle at module load time.
        from vouch.autosign import current_credential

        credential = current_credential()
        if credential is None:
            return False, None

    global _DEFAULT_VERIFIER
    if _DEFAULT_VERIFIER is None or _DEFAULT_VERIFIER._allow_resolution != allow_did_resolution:
        _DEFAULT_VERIFIER = Verifier(allow_did_resolution=allow_did_resolution)
    resolver = key_resolver or _DEFAULT_VERIFIER._resolve_credential_public_key

    # Offline path: a key was handed to us for the credential itself.
    if public_key is not None:
        return Verifier.verify(
            credential,
            public_key=public_key,
            key_resolver=resolver,
            trusted_roots=trusted_roots,
        )

    # Auto-resolving path: reuse a cached resolver-enabled Verifier.
    return _DEFAULT_VERIFIER.check_vouch_credential(
        credential, key_resolver=resolver, trusted_roots=trusted_roots
    )


# ---------------------------------------------------------------------------
# Delegation chain verification (Specification §9.3)
# ---------------------------------------------------------------------------


def verify_delegation_chain(
    credential: Union[Dict[str, Any], str],
    *,
    key_resolver: Optional[Callable[[str], Any]] = None,
    trusted_roots: Optional[Any] = None,
    clock_skew_seconds: int = 30,
    now: Optional[datetime] = None,
) -> Optional[str]:
    """
    Verify a credential's embedded `delegationChain`. Returns None when the
    chain is valid (or absent), otherwise a stable reason code.

    Each link embeds the signed grant it was derived from (`parentCredential`).
    For every link, in order (first failure wins):

      - the link carries a signed grant              -> delegation_link_unsigned
      - the grant's issuer is the link's issuer      -> delegation_link_issuer_mismatch
      - the issuer's key resolves                    -> delegation_issuer_key_unresolved
      - the grant's eddsa-jcs-2022 proof verifies,
        made by the issuer for assertionMethod       -> delegation_signature_invalid
      - `parentProofValue`, if present, binds to it  -> delegation_link_tampered
      - the grant names a delegatee ...              -> delegation_no_delegatee
        ... who is the link's subject                -> delegation_subject_mismatch
      - the grant is inside its validity window      -> delegation_expired /
                                                        delegation_not_yet_valid

    Then across the chain:

      - each link's subject is the next link's issuer, and the last link's
        subject is the credential's issuer          -> delegation_subject_issuer_mismatch
      - the root issuer is trusted (only when
        `trusted_roots` is given)                   -> untrusted_principal
      - no step is broader than its parent on action, target, resource, time,
        rate, or policy (`vouch.attenuation.non_expansion`; the leaf credential
        is the last step)                           -> scope_exceeds_parent:<dimension>

    Keys resolve from `trusted_roots` (when it is a `{did: key}` map), then
    `key_resolver`, then `did:key` (offline). Revocation is not checked here;
    combine with a status-list or registry check.
    """
    from .attenuation import capability_view, non_expansion
    from .signer import _parent_proof_binding_value

    try:
        cred = json.loads(credential) if isinstance(credential, str) else credential
    except json.JSONDecodeError:
        return "malformed_delegation"
    if not isinstance(cred, dict):
        return "malformed_delegation"
    subject = cred.get("credentialSubject")
    chain = subject.get("delegationChain") if isinstance(subject, dict) else None
    if not chain:
        return None
    if not isinstance(chain, list):
        return "malformed_delegation"

    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    root_keys, root_dids = _normalize_trusted_roots(trusted_roots)

    grants: List[Dict[str, Any]] = []
    for link in chain:
        if (
            not isinstance(link, dict)
            or not isinstance(link.get("issuer"), str)
            or not isinstance(link.get("subject"), str)
        ):
            return "malformed_delegation"
        grant = link.get("parentCredential")
        if not isinstance(grant, dict) or not isinstance(grant.get("proof"), (dict, list)):
            return "delegation_link_unsigned"
        grant_issuer = _issuer_did(grant)
        if grant_issuer != link["issuer"]:
            return "delegation_link_issuer_mismatch"
        key = _resolve_chain_key(grant_issuer, root_keys, key_resolver)
        if key is None:
            return "delegation_issuer_key_unresolved"
        if not _verify_grant_proof(grant, grant_issuer, key):
            return "delegation_signature_invalid"
        bound = link.get("parentProofValue")
        if bound is not None and bound != _parent_proof_binding_value(grant)[:64]:
            return "delegation_link_tampered"
        grant_subject = grant.get("credentialSubject")
        grant_intent = grant_subject.get("intent") if isinstance(grant_subject, dict) else None
        delegatee = grant_intent.get("delegatee") if isinstance(grant_intent, dict) else None
        if not delegatee:
            return "delegation_no_delegatee"
        if delegatee != link["subject"]:
            return "delegation_subject_mismatch"
        valid_from = _parse_iso8601(grant.get("validFrom"))
        valid_until = _parse_iso8601(grant.get("validUntil"))
        if valid_from is None or valid_until is None:
            return "malformed_delegation"
        if (moment - valid_until).total_seconds() > clock_skew_seconds:
            return "delegation_expired"
        if (valid_from - moment).total_seconds() > clock_skew_seconds:
            return "delegation_not_yet_valid"
        grants.append(grant)

    for i in range(1, len(chain)):
        if chain[i - 1]["subject"] != chain[i]["issuer"]:
            return "delegation_subject_issuer_mismatch"
    if chain[-1]["subject"] != _issuer_did(cred):
        return "delegation_subject_issuer_mismatch"

    if root_dids is not None and chain[0]["issuer"] not in root_dids:
        return "untrusted_principal"

    views = [capability_view(g) for g in grants] + [capability_view(cred)]
    for parent_view, child_view in zip(views, views[1:]):
        dimension = non_expansion(parent_view, child_view)
        if dimension is not None:
            return f"scope_exceeds_parent:{dimension}"
    return None


def _issuer_did(credential: Dict[str, Any]) -> Optional[str]:
    issuer = credential.get("issuer")
    if isinstance(issuer, list):
        issuer = issuer[0] if issuer else None
    if isinstance(issuer, dict):
        issuer = issuer.get("id")
    return issuer if isinstance(issuer, str) else None


def _normalize_trusted_roots(
    trusted_roots: Optional[Any],
) -> Tuple[Dict[str, Any], Optional[List[str]]]:
    """`{did: key}` -> (keys, dids); `[did, ...]` / `did` -> ({}, dids); None -> ({}, None)."""
    if trusted_roots is None:
        return {}, None
    if isinstance(trusted_roots, Mapping):
        return dict(trusted_roots), list(trusted_roots.keys())
    if isinstance(trusted_roots, str):
        return {}, [trusted_roots]
    if isinstance(trusted_roots, Iterable):
        return {}, [str(d) for d in trusted_roots]
    raise TypeError("trusted_roots must be a {did: key} map or a list of DIDs")


def _resolve_chain_key(
    did: Optional[str],
    root_keys: Dict[str, Any],
    key_resolver: Optional[Callable[[str], Any]],
) -> Optional[Ed25519PublicKey]:
    if not did:
        return None
    if did in root_keys:
        return _coerce_any_public_key(root_keys[did])
    if key_resolver is not None:
        try:
            candidate = key_resolver(did)
        except Exception as e:  # noqa: BLE001 - an unresolvable key is a refusal
            logger.debug(f"key_resolver failed for {did}: {e}")
            candidate = None
        if candidate is not None:
            return _coerce_any_public_key(candidate)
    if did.startswith("did:key:"):
        return _resolve_did_key(did)
    return None


def _coerce_any_public_key(key: Any) -> Optional[Ed25519PublicKey]:
    """Like `_coerce_ed25519_public_key`, also accepting a jwcrypto JWK object."""
    if isinstance(key, jwk.JWK):
        try:
            key = json.loads(key.export_public())
        except Exception:  # noqa: BLE001
            return None
    return _coerce_ed25519_public_key(key)


def _verify_grant_proof(grant: Dict[str, Any], issuer_did: str, key: Ed25519PublicKey) -> bool:
    """Verify a grant's eddsa-jcs-2022 proof (the classical member of a proof set)."""
    raw = grant.get("proof")
    proofs = raw if isinstance(raw, list) else [raw]
    for proof in proofs:
        if not isinstance(proof, dict):
            continue
        if proof.get("cryptosuite") not in (None, data_integrity.CRYPTOSUITE_ID):
            continue
        if proof.get("proofPurpose") != "assertionMethod":
            continue
        vm = proof.get("verificationMethod")
        if not isinstance(vm, str) or vm.split("#", 1)[0] != issuer_did:
            continue
        candidate = {k: v for k, v in grant.items() if k != "proof"}
        candidate["proof"] = proof
        try:
            if data_integrity.verify_proof(candidate, key):
                return True
        except (ValueError, InvalidSignature):
            continue
    return False


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


def _resolve_did_key(did: str) -> Optional[Ed25519PublicKey]:
    """Decode the Ed25519 public key embedded in a ``did:key`` identifier.

    ``did:key:z6Mk...`` carries the multicodec-tagged public key in the DID
    string, so there is no network resolution. Returns None for non-Ed25519
    did:key values or malformed input.
    """
    try:
        mk = did.split("did:key:", 1)[1]
        alg, raw = multikey.decode(mk)
        if alg == "Ed25519":
            return Ed25519PublicKey.from_public_bytes(raw)
    except (IndexError, ValueError):
        return None
    return None


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
    """Parse VC datetime strings. Returns timezone-aware UTC datetime."""
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
