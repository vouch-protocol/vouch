"""
Vouch Protocol Signer.

Two issuance modes coexist during the migration from JWS to Data Integrity
(see Specification §3.1, "Backward Compatibility"):

  1. Legacy JWS Compact Serialization, the v0.x format. Produced by
    `Signer.sign()`. Retained for backward compatibility while integrations
    migrate. Will be removed once all callers transition.

  2. Verifiable Credentials with Data Integrity proofs (eddsa-jcs-2022),
    the v1.0 format. Produced by `Signer.sign_credential()` and
    `Signer.sign_credential_json()`. This is the standards-aligned form aligned with
    the CG Report.

Both modes share the same Ed25519 signing key. Existing callers using
`Signer.sign()` continue to work unchanged. New callers should prefer
`sign_credential()`.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode

from . import data_integrity, data_integrity_hybrid, multikey, vc


class Signer:
    """
    Issues Vouch credentials using Ed25519 keys.

    The same key pair backs both the legacy JWS path and the new VC + Data
    Integrity path. Choose the issuance mode by which method you call:

      legacy = signer.sign({"action": "x", "target": "y"})       # JWS string
      modern = signer.sign_credential(intent={              # VC dict
        "action": "x",
        "target": "y",
        "resource": "https://api.example.com/y",
      })

    Example:
      >>> signer = Signer(private_key='{"kty":"OKP",...}', did='did:web:example.com')
      >>> token = signer.sign({'action': 'read_email'})      # legacy
      >>> cred = signer.sign_credential(intent={         # modern
      ...   'action': 'read_email',
      ...   'target': 'inbox',
      ...   'resource': 'https://mail.example.com/api/inbox',
      ... })
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
            if self._key["kty"] != "OKP" or self._key.get("crv") != "Ed25519":
                raise ValueError("Key must be an Ed25519 key (OKP with crv=Ed25519)")
        except Exception as e:
            raise ValueError(f"Invalid JWK private key: {e}")

        # Derive raw Ed25519 bytes for the modern Data Integrity path.
        # The JWK 'd' parameter is the base64url-encoded 32-byte private seed.
        self._raw_priv: Optional[Ed25519PrivateKey] = None
        try:
            seed_b64 = self._key.get("d")
            if seed_b64:
                from jwcrypto.common import base64url_decode

                seed = base64url_decode(seed_b64)
                self._raw_priv = Ed25519PrivateKey.from_private_bytes(seed)
        except Exception:  # pragma: no cover - defensive
            self._raw_priv = None

    @classmethod
    def from_keypair(cls, keypair: Any, default_expiry_seconds: int = 300) -> "Signer":
        """Construct a Signer directly from a :class:`~vouch.keys.KeyPair`.

        Saves unpacking ``keypair.private_key_jwk`` and ``keypair.did`` by hand::

            keys = generate_identity("agent.example")
            signer = Signer.from_keypair(keys)

        Args:
          keypair: a KeyPair (or any object exposing ``private_key_jwk`` and
            ``did`` attributes).
          default_expiry_seconds: token validity period (default 5 minutes).

        Raises:
          ValueError: if the keypair has no DID.
        """
        did = getattr(keypair, "did", None)
        if not did:
            raise ValueError(
                "Signer.from_keypair requires a keypair with a DID; "
                "generate it with a domain, e.g. generate_identity('agent.example')"
            )
        return cls(
            private_key=keypair.private_key_jwk,
            did=did,
            default_expiry_seconds=default_expiry_seconds,
        )

    # ------------------------------------------------------------------
    # Legacy JWS path (v0.x). Preserved verbatim for backward compatibility.
    # ------------------------------------------------------------------

    def sign(
        self,
        payload: Dict[str, Any],
        expiry_seconds: Optional[int] = None,
        reputation_score: Optional[int] = None,
        parent_token: Optional[str] = None,
    ) -> str:
        """
        Legacy: sign a payload and return a JWS Compact Serialization string.

        Retained for backward compatibility. New code should prefer
        :meth:`sign_credential`. See module docstring.

        Args:
          payload: Dictionary containing the intent/action data to sign.
          expiry_seconds: Optional override for token expiry time.
          reputation_score: Optional reputation score (0-100).
          parent_token: Optional parent legacy JWS token for delegation chains.

        Returns:
          A JWS compact serialized token string.
        """
        now = int(time.time())
        exp = expiry_seconds if expiry_seconds is not None else self.default_expiry

        vouch_claim = {"version": "1.0", "payload": payload}
        if reputation_score is not None:
            vouch_claim["reputation_score"] = max(0, min(100, reputation_score))
        if parent_token:
            chain = self._build_delegation_chain(parent_token, payload)
            if chain:
                vouch_claim["delegation_chain"] = chain

        claims = {
            "jti": str(uuid.uuid4()),
            "iss": self.did,
            "sub": self.did,
            "iat": now,
            "nbf": now,
            "exp": now + exp,
            "vouch": vouch_claim,
        }

        token = jws.JWS(json.dumps(claims, sort_keys=True, separators=(",", ":")))
        protected_header = {
            "alg": "EdDSA",
            "typ": "vouch+jwt",
            "kid": self._key.get("kid") or self.did,
        }
        token.add_signature(self._key, None, json_encode(protected_header), None)
        return token.serialize(compact=True)

    def _build_delegation_chain(self, parent_token: str, current_payload: Dict[str, Any]) -> list:
        """Legacy delegation chain assembly (operates on JWS tokens)."""
        MAX_CHAIN_DEPTH = 5
        try:
            jws_token = jws.JWS()
            jws_token.deserialize(parent_token)

            payload_bytes = jws_token.objects.get("payload", b"")
            if isinstance(payload_bytes, str):
                payload_bytes = payload_bytes.encode("utf-8")

            parent_claims = json.loads(payload_bytes.decode("utf-8"))
            parent_vouch = parent_claims.get("vouch", {})
            existing_chain = parent_vouch.get("delegation_chain", [])

            if len(existing_chain) >= MAX_CHAIN_DEPTH:
                raise ValueError(f"Delegation chain exceeds max depth of {MAX_CHAIN_DEPTH}")

            new_link = {
                "iss": parent_claims.get("iss", ""),
                "sub": self.did,
                "intent": json.dumps(current_payload, sort_keys=True),
                "iat": int(time.time()),
                "sig": parent_token.split(".")[-1][:64],
            }
            return existing_chain + [new_link]
        except Exception as e:
            raise ValueError(f"Failed to build delegation chain: {e}")

    # ------------------------------------------------------------------
    # Modern path: VC + Data Integrity (eddsa-jcs-2022).
    # ------------------------------------------------------------------

    def sign_credential(
        self,
        intent: Optional[Dict[str, Any]] = None,
        *,
        action: Optional[str] = None,
        target: Optional[str] = None,
        resource: Optional[str] = None,
        valid_seconds: Optional[int] = None,
        reputation_score: Optional[int] = None,
        delegation_chain: Optional[List[Dict[str, Any]]] = None,
        parent_credential: Optional[Dict[str, Any]] = None,
        valid_from: Optional[datetime] = None,
        credential_id: Optional[str] = None,
        credential_status: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Issue a Verifiable Credential with a Data Integrity proof.

        This is the v1.0 issuance path per Specification §5 and §7.1. The
        returned credential is a dict that can be JSON-serialized and
        transmitted in an HTTP body or header.

        The intent can be passed either as a dict (the original form) or as the
        named keyword arguments `action`, `target`, and `resource`. The two
        styles are equivalent and may be combined; named arguments override the
        matching keys in the `intent` dict::

            signer.sign_credential(action="read", target="inbox",
                                   resource="https://mail/api/inbox")
            signer.sign_credential(intent={"action": "read", "target": "inbox",
                                           "resource": "https://mail/api/inbox"})

        Args:
          intent: Intent payload dict. MUST contain `action`, `target`,
            `resource` once merged with any named arguments.
          action: Optional intent action (alternative to `intent["action"]`).
          target: Optional intent target (alternative to `intent["target"]`).
          resource: Optional intent resource (alternative to
            `intent["resource"]`).
          valid_seconds: Optional validity window override.
          reputation_score: Optional self-reported score in [0, 100].
          delegation_chain: Pre-built delegation chain to attach (advanced).
          parent_credential: A previously-issued Vouch Credential dict; if
            provided, this Signer extends its delegation chain by appending
            a new link from the parent's subject to this Signer's DID.
          valid_from: Optional override for the credential's `validFrom`.
          credential_id: Optional credential ID. Defaults to a fresh UUID URN.
          credential_status: Optional W3C `credentialStatus` entry (typically
            from `vouch.status_list.build_status_list_entry`) so a credential
            can be revoked later. The proof covers it, so it must be set at
            signing time.

        Returns:
          A signed Vouch Credential dict conforming to VC Data Model 2.0
          with a `proof` object (eddsa-jcs-2022).

        Raises:
          ValueError: If the merged intent is missing required fields, the chain
            exceeds max depth, or the private key bytes are unavailable.
        """
        if self._raw_priv is None:
            raise ValueError(
                "Cannot issue Data Integrity credentials: private key bytes "
                "could not be derived from the JWK"
            )

        intent = _merge_intent(intent, action=action, target=target, resource=resource)

        chain = delegation_chain or []
        if parent_credential is not None:
            chain = self._extend_delegation_chain_from_parent(parent_credential, intent)

        credential = vc.build_vouch_credential(
            issuer_did=self.did,
            intent=intent,
            valid_seconds=valid_seconds or self.default_expiry,
            reputation_score=reputation_score,
            delegation_chain=chain or None,
            credential_id=credential_id,
            valid_from=valid_from,
            credential_status=credential_status,
        )

        proof = data_integrity.build_proof(
            credential,
            private_key=self._raw_priv,
            verification_method=self.verification_method_id(),
        )
        credential["proof"] = proof
        return credential

    def sign_credential_hybrid(
        self,
        intent: Optional[Dict[str, Any]] = None,
        *,
        action: Optional[str] = None,
        target: Optional[str] = None,
        resource: Optional[str] = None,
        valid_seconds: Optional[int] = None,
        reputation_score: Optional[int] = None,
        delegation_chain: Optional[List[Dict[str, Any]]] = None,
        parent_credential: Optional[Dict[str, Any]] = None,
        valid_from: Optional[datetime] = None,
        credential_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Issue a Vouch Credential under the hybrid post-quantum profile
        (Specification §13.2).

        The credential carries a hybrid-eddsa-mldsa44-jcs-2026 Data Integrity
        proof containing both an Ed25519 signature and an ML-DSA-44 signature
        over the same canonical form. Verification REQUIRES both signatures
        to validate, providing safety against compromise of either algorithm.

        Accepts the intent either as a dict or as the named `action`/`target`/
        `resource` arguments, exactly like :meth:`sign_credential`.

        Note: this profile produces credentials roughly 2.5 KB larger than
        the eddsa-jcs-2022 default. Implementations using this profile
        SHOULD transmit credentials in the HTTP request body (§5.6).

        Lazily generates the agent's ML-DSA-44 keypair on first call.
        Requires the `pqcrypto` package to be installed.
        """
        if self._raw_priv is None:
            raise ValueError(
                "Cannot issue Data Integrity credentials: private key bytes "
                "could not be derived from the JWK"
            )

        intent = _merge_intent(intent, action=action, target=target, resource=resource)

        chain = delegation_chain or []
        if parent_credential is not None:
            chain = self._extend_delegation_chain_from_parent(parent_credential, intent)

        credential = vc.build_vouch_credential(
            issuer_did=self.did,
            intent=intent,
            valid_seconds=valid_seconds or self.default_expiry,
            reputation_score=reputation_score,
            delegation_chain=chain or None,
            credential_id=credential_id,
            valid_from=valid_from,
        )

        self._ensure_mldsa44_keypair()
        proof = data_integrity_hybrid.build_hybrid_proof(
            credential,
            ed25519_private_key=self._raw_priv,
            mldsa44_secret_key=self._mldsa44_secret,
            verification_method=self.verification_method_id(),
        )
        credential["proof"] = proof
        return credential

    def public_key_mldsa44(self) -> bytes:
        """Return the ML-DSA-44 public key bytes (1312 bytes).

        Used by callers that want to publish a second Multikey verification
        method in the DID Document for hybrid verification.
        """
        self._ensure_mldsa44_keypair()
        return self._mldsa44_public

    def public_key_mldsa44_multikey(self) -> str:
        """Return the ML-DSA-44 public key in Multikey format."""
        return multikey.encode_mldsa44_public(self.public_key_mldsa44())

    def _ensure_mldsa44_keypair(self) -> None:
        """Generate an ML-DSA-44 keypair on first use and cache it."""
        if getattr(self, "_mldsa44_secret", None) is not None:
            return
        pub, sec = data_integrity_hybrid.generate_mldsa44_keypair()
        self._mldsa44_public = pub
        self._mldsa44_secret = sec

    def sign_credential_json(self, intent: Dict[str, Any], **kwargs: Any) -> str:
        """JSON-serialized form of :meth:`sign_credential` for HTTP transport."""
        cred = self.sign_credential(intent, **kwargs)
        return json.dumps(cred, separators=(",", ":"))

    def _extend_delegation_chain_from_parent(
        self,
        parent_credential: Dict[str, Any],
        current_intent: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Build a delegation link from `parent_credential` to this signer.

        Implements Specification §9.2 link structure. Validates depth limit
        (§9.4) and resource-narrowing (§9.3 step 5).
        """
        MAX_CHAIN_DEPTH = 5

        parent_subject = parent_credential.get("credentialSubject", {})
        parent_intent = parent_subject.get("intent", {})
        parent_chain = parent_subject.get("delegationChain") or []

        if len(parent_chain) >= MAX_CHAIN_DEPTH:
            raise ValueError(f"Delegation chain exceeds max depth of {MAX_CHAIN_DEPTH}")

        # Resource-narrowing check (§9.3): child resource must be a sub-resource
        # of (or equal to) the parent's resource.
        parent_resource = parent_intent.get("resource", "")
        child_resource = current_intent.get("resource", "")
        if (
            parent_resource
            and child_resource
            and not _is_sub_resource(child_resource, parent_resource)
        ):
            raise ValueError(
                "Delegation violates resource-narrowing rule: child resource "
                f"{child_resource!r} is not a sub-resource of parent "
                f"{parent_resource!r}"
            )

        parent_proof = parent_credential.get("proof", {}) or {}
        new_link = {
            "issuer": parent_credential.get("issuer", ""),
            "subject": self.did,
            "intent": current_intent,
            "validFrom": parent_credential.get("validFrom"),
            "validUntil": parent_credential.get("validUntil"),
            "parentProofValue": parent_proof.get("proofValue", "")[:64],
        }

        return list(parent_chain) + [new_link]

    # ------------------------------------------------------------------
    # Key/identity helpers
    # ------------------------------------------------------------------

    def get_public_key_jwk(self) -> str:
        """Return the public key in JWK format (legacy DID Documents)."""
        return self._key.export_public()

    def get_public_key_multikey(self) -> str:
        """
        Return the public key in Multikey format (z-prefixed base58btc).

        This is the verification-method format used in modern DID Documents,
        per Specification §4.3.
        """
        from jwcrypto.common import base64url_decode

        pub_b64 = self._key.get("x")
        if not pub_b64:
            raise ValueError("JWK does not expose the Ed25519 public component")
        raw = base64url_decode(pub_b64)
        return multikey.encode_ed25519_public(raw)

    def verification_method_id(self) -> str:
        """Return the canonical verification method ID for this signer."""
        return f"{self.did}#key-1"

    def get_did(self) -> str:
        """Returns the DID of this signer."""
        return self.did


def _is_sub_resource(child: str, parent: str) -> bool:
    """
    True if `child` is a sub-resource of `parent`. Conservative URL-prefix
    match: child must equal parent or extend it after a path separator.
    """
    if child == parent:
        return True
    if child.startswith(parent.rstrip("/") + "/"):
        return True
    return False


def _merge_intent(
    intent: Optional[Dict[str, Any]],
    *,
    action: Optional[str] = None,
    target: Optional[str] = None,
    resource: Optional[str] = None,
) -> Dict[str, Any]:
    """Combine a dict intent with the named action/target/resource arguments.

    Named arguments override the matching keys in `intent`. The original dict is
    never mutated. Required-field validation is left to `vc.build_vouch_credential`
    so the error message stays in one place.
    """
    merged: Dict[str, Any] = dict(intent) if intent else {}
    if action is not None:
        merged["action"] = action
    if target is not None:
        merged["target"] = target
    if resource is not None:
        merged["resource"] = resource
    return merged


# ---------------------------------------------------------------------------
# One-line signing (the sending-side counterpart to vouch.verify)
# ---------------------------------------------------------------------------


def sign(
    keypair: Any,
    intent: Optional[Dict[str, Any]] = None,
    *,
    action: Optional[str] = None,
    target: Optional[str] = None,
    resource: Optional[str] = None,
    valid_seconds: Optional[int] = None,
    reputation_score: Optional[int] = None,
    parent_credential: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Sign an intent as a Vouch Credential in one line, no Signer to construct.

    The no-class counterpart to :func:`vouch.verify`::

        keys = vouch.generate_identity("agent.example")
        signed = vouch.sign(keys, action="read", target="did:web:files",
                            resource="https://files/x")
        ok, who = vouch.verify(signed, keys.public_key_jwk)

    Args:
      keypair: a :class:`~vouch.keys.KeyPair` (must carry a DID).
      intent: optional intent dict; alternatively pass `action`/`target`/
        `resource` as named arguments. The two styles may be combined.
      action / target / resource: named intent fields.
      valid_seconds: optional validity window override.
      reputation_score: optional self-reported score in [0, 100].
      parent_credential: optional parent grant to chain this credential under.

    Returns:
      A signed Vouch Credential dict, identical to what
      ``Signer.from_keypair(keypair).sign_credential(...)`` returns.
    """
    signer = Signer.from_keypair(keypair)
    return signer.sign_credential(
        intent,
        action=action,
        target=target,
        resource=resource,
        valid_seconds=valid_seconds,
        reputation_score=reputation_score,
        parent_credential=parent_credential,
    )
