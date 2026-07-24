"""
Vouch Protocol Signer.

Issues Verifiable Credentials with Data Integrity proofs (eddsa-jcs-2022),
the v1.0 format, via ``Signer.sign()``. A JSON-serialized form is available
through ``Signer.sign_json()``, and the post-quantum profile (a proof set
holding an eddsa-jcs-2022 proof and an mldsa44-jcs-2024 proof) through
``Signer.sign_hybrid()``.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode

from . import data_integrity, data_integrity_hybrid, multikey, vc


class Signer:
    """
    Issues Vouch Credentials using Ed25519 keys.

    Sign an intent to get a Verifiable Credential with a Data Integrity proof:

      cred = signer.sign(intent={
        "action": "read",
        "target": "inbox",
        "resource": "https://mail.example.com/api/inbox",
      })

    Example:
      >>> signer = Signer(private_key='{"kty":"OKP",...}', did='did:web:example.com')
      >>> cred = signer.sign(intent={
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

        # A backend-signed Signer (see from_backend) leaves these set instead of
        # holding the raw key. None here means "this Signer holds the key".
        self._sign_func: Optional[Callable[[bytes], bytes]] = None
        self._public_jwk_str: Optional[str] = None
        self._public_multikey: Optional[str] = None

    @classmethod
    def from_backend(
        cls,
        did: str,
        public_key: str,
        sign: Callable[[bytes], bytes],
        default_expiry_seconds: int = 300,
    ) -> "Signer":
        """Construct a Signer whose private key lives outside this process.

        Instead of a private JWK, you supply the agent's public key and a
        callable ``sign(digest: bytes) -> bytes`` that returns the Ed25519
        signature over the digest. The raw key never enters this process, so it
        can live in an OS secure element, a sidecar, a cloud KMS/HSM, or an MPC
        quorum. This Signer issues Data Integrity credentials (the modern path);
        the legacy JWS ``sign()`` is not available without the private key.

        Args:
          did: the agent's DID.
          public_key: the agent's public key as a JWK JSON string or a Multikey
            (z-prefixed) string.
          sign: callable that signs a 32-byte digest and returns the 64-byte
            Ed25519 signature.
          default_expiry_seconds: token validity period (default 5 minutes).
        """
        if not did:
            raise ValueError("Signer.from_backend requires a 'did'")
        if not public_key:
            raise ValueError("Signer.from_backend requires the agent 'public_key'")
        if not callable(sign):
            raise ValueError("Signer.from_backend requires a callable 'sign'")

        self = cls.__new__(cls)
        self.did = did
        self.default_expiry = default_expiry_seconds
        self._key = None
        self._raw_priv = None
        self._sign_func = sign
        self._public_jwk_str, self._public_multikey = _normalize_public_key(public_key)
        return self

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
    # VC + Data Integrity (eddsa-jcs-2022).
    # ------------------------------------------------------------------

    def sign(
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

            signer.sign(action="read", target="inbox",
                                   resource="https://mail/api/inbox")
            signer.sign(intent={"action": "read", "target": "inbox",
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
            exceeds max depth, or no signing key/backend is available.
        """
        signer = self._credential_signer()

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
            private_key=signer,
            verification_method=self.verification_method_id(),
        )
        credential["proof"] = proof
        return credential

    def _credential_signer(self):
        """Return the signer for the Data Integrity path: the raw key if this
        Signer holds it, otherwise the backend sign callback."""
        if self._raw_priv is not None:
            return self._raw_priv
        if self._sign_func is not None:
            return self._sign_func
        raise ValueError(
            "Cannot issue Data Integrity credentials: no signing key is available "
            "(construct the Signer with a private key or via Signer.from_backend)"
        )

    def sign_hybrid(
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
        """Issue a Vouch Credential under the post-quantum profile
        (Specification §13.2).

        The credential carries a `proof` ARRAY of two independent Data
        Integrity proofs, an eddsa-jcs-2022 proof and an mldsa44-jcs-2024
        proof, over the same unsecured document. Verification REQUIRES both
        signatures to validate, providing safety against compromise of either
        algorithm, and a verifier that understands only one of the two
        cryptosuites can still check that proof on its own.

        Accepts the intent either as a dict or as the named `action`/`target`/
        `resource` arguments, exactly like :meth:`sign`.

        Note: this profile produces credentials roughly 2.5 KB larger than
        the eddsa-jcs-2022 default. Implementations using this profile
        SHOULD transmit credentials in the HTTP request body (§5.6).

        Lazily generates the agent's ML-DSA-44 keypair on first call.
        Requires the `pqcrypto` package to be installed.
        """
        if self._raw_priv is None:
            # The hybrid profile needs both an Ed25519 and an ML-DSA-44 signature.
            # A backend Signer only exposes the Ed25519 sign callback, so the
            # hybrid path is not available there yet.
            if self._sign_func is not None:
                raise NotImplementedError(
                    "sign_hybrid is not supported for a backend Signer "
                    "(from_backend); use the eddsa-jcs-2022 path or hold the key locally"
                )
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
        credential["proof"] = data_integrity_hybrid.build_dual_proof(
            credential,
            ed25519_private_key=self._raw_priv,
            mldsa44_secret_key=self._mldsa44_secret,
            ed25519_verification_method=self.verification_method_id(),
            mldsa44_verification_method=self.mldsa44_verification_method_id(),
        )
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

    def mldsa44_verification_method_id(self) -> str:
        """Return the verification method ID of this signer's ML-DSA-44 key,
        the #key-2 slot alongside the Ed25519 #key-1 entry."""
        _, mldsa_vm = data_integrity_hybrid.hybrid_verification_method_pair(
            self.verification_method_id()
        )
        return mldsa_vm

    def attach_hybrid_proof(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        """Attach a post-quantum proof set (an eddsa-jcs-2022 proof alongside an
        mldsa44-jcs-2024 proof) to a pre-built credential, for custom credential
        types the caller assembles directly rather than from an intent. Any
        existing proof is replaced. Both keys live in this process, so this is
        not available for a backend Signer."""
        if self._raw_priv is None:
            raise NotImplementedError(
                "attach_hybrid_proof needs the raw keys and is not available for a backend Signer"
            )
        self._ensure_mldsa44_keypair()
        return data_integrity_hybrid.sign_dual(
            credential,
            ed25519_private_key=self._raw_priv,
            mldsa44_secret_key=self._mldsa44_secret,
            ed25519_verification_method=self.verification_method_id(),
            mldsa44_verification_method=self.mldsa44_verification_method_id(),
        )

    def _ensure_mldsa44_keypair(self) -> None:
        """Generate an ML-DSA-44 keypair on first use and cache it."""
        if getattr(self, "_mldsa44_secret", None) is not None:
            return
        pub, sec = data_integrity_hybrid.generate_mldsa44_keypair()
        self._mldsa44_public = pub
        self._mldsa44_secret = sec

    def sign_json(self, intent: Dict[str, Any], **kwargs: Any) -> str:
        """JSON-serialized form of :meth:`sign` for HTTP transport."""
        cred = self.sign(intent, **kwargs)
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

        new_link = {
            "issuer": parent_credential.get("issuer", ""),
            "subject": self.did,
            "intent": current_intent,
            "validFrom": parent_credential.get("validFrom"),
            "validUntil": parent_credential.get("validUntil"),
            "parentProofValue": _parent_proof_binding_value(parent_credential)[:64],
        }

        return list(parent_chain) + [new_link]

    # ------------------------------------------------------------------
    # Key/identity helpers
    # ------------------------------------------------------------------

    def get_public_key_jwk(self) -> str:
        """Return the public key in JWK format (legacy DID Documents)."""
        if self._key is not None:
            return self._key.export_public()
        if self._public_jwk_str is not None:
            return self._public_jwk_str
        raise ValueError("No public key available for this Signer")

    def get_public_key_multikey(self) -> str:
        """
        Return the public key in Multikey format (z-prefixed base58btc).

        This is the verification-method format used in modern DID Documents,
        per Specification §4.3.
        """
        from jwcrypto.common import base64url_decode

        if self._key is None:
            if self._public_multikey is not None:
                return self._public_multikey
            raise ValueError("No public key available for this Signer")
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


def _parent_proof_binding_value(parent_credential: dict) -> str:
    """
    The proof value a delegation link binds to its parent. When the parent
    carries a proof set (a `proof` array), bind to the classical
    `eddsa-jcs-2022` member, whose value is deterministic, falling back to the
    first proof. For a single proof object, use its proof value.
    """
    proof = parent_credential.get("proof")
    if isinstance(proof, list):
        for entry in proof:
            if (
                isinstance(entry, dict)
                and entry.get("cryptosuite") == data_integrity.CRYPTOSUITE_ID
            ):
                return entry.get("proofValue", "")
        for entry in proof:
            if isinstance(entry, dict) and entry.get("proofValue"):
                return entry.get("proofValue", "")
        return ""
    if isinstance(proof, dict):
        return proof.get("proofValue", "")
    return ""


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


def _normalize_public_key(public_key: str) -> tuple:
    """Accept a JWK JSON string or a Multikey (z...) string and return
    (jwk_json_str, multikey_str) for both export formats."""
    from jwcrypto.common import base64url_decode

    if public_key.startswith("z"):
        alg, raw = multikey.decode(public_key)
        if alg != "Ed25519":
            raise ValueError(f"Expected an Ed25519 public key, got {alg}")
        key = jwk.JWK.from_json(
            json.dumps(
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": _b64url_nopad(raw),
                }
            )
        )
        return key.export_public(), public_key

    # Otherwise treat it as a JWK JSON string.
    key = jwk.JWK.from_json(public_key)
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        raise ValueError("Public key JWK must be an Ed25519 key (OKP, crv=Ed25519)")
    raw = base64url_decode(key.get("x"))
    return key.export_public(), multikey.encode_ed25519_public(raw)


def _b64url_nopad(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


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
      ``Signer.from_keypair(keypair).sign(...)`` returns.
    """
    signer = Signer.from_keypair(keypair)
    return signer.sign(
        intent,
        action=action,
        target=target,
        resource=resource,
        valid_seconds=valid_seconds,
        reputation_score=reputation_score,
        parent_credential=parent_credential,
    )
