"""
The ``Agent`` wrapper: one object that holds an identity and signs/verifies.

The minimal flow mints keys, builds a Signer from two unpacked fields, then
carries the public key around separately to verify. ``Agent`` collapses that
into a single object you pass around::

    agent = vouch.Agent("agent.example")          # mints identity, holds signer
    signed = agent.sign(action="read", target="did:web:files",
                        resource="https://files/x")
    ok, who = agent.verify(signed)                 # knows its own key
    agent.did, agent.public_key_jwk               # plain attributes

    # rehydrate from stored keys / env, no new identity minted:
    agent2 = vouch.Agent.load(private_key_jwk, did)

``Agent`` is sugar over the existing :class:`~vouch.signer.Signer`,
:class:`~vouch.verifier.Verifier`, and :func:`~vouch.keys.generate_identity`.
The credential it signs is the same dict those produce; nothing about the wire
format changes.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Tuple

from vouch.keys import KeyPair, generate_identity
from vouch.keystore import KeyStore, resolve_default_store
from vouch.signer import Signer
from vouch.verifier import CredentialPassport, Verifier, verify

logger = logging.getLogger(__name__)


class Agent:
    """An agent identity bundled with its signer.

    Construct it to mint a fresh identity, or use :meth:`load` /
    :meth:`from_keypair` / :meth:`from_store` to rehydrate an existing one. With
    a ``domain`` the identity is ``did:web:<domain>``; without one it is a
    self-certifying ``did:key`` (verifiable offline, no DID document to host).

    Storage (secure by default): a freshly minted identity is persisted to the
    most secure store available (OS keyring, else an encrypted file when a
    password is set) so it is not lost when the process exits. Pass ``store=`` to
    choose one explicitly, or ``persist=False`` to keep it in memory (logged
    clearly, since an unsaved identity disappears on exit). See
    :mod:`vouch.keystore`.

    The private key is not handed back by default. ``private_key_jwk`` and
    ``keypair`` raise unless the Agent was created with ``allow_key_export=True``,
    so an end user does not accidentally pass the raw key around. Signing always
    works regardless, through :meth:`sign`.
    """

    def __init__(
        self,
        domain: Optional[str] = None,
        *,
        default_expiry_seconds: int = 300,
        store: Optional[KeyStore] = None,
        persist: bool = True,
        password: Optional[str] = None,
        allow_key_export: bool = False,
    ) -> None:
        keypair = generate_identity(domain=domain)
        is_did_key = not keypair.did
        if is_did_key:
            keypair.did = _did_key_from_pub_jwk(keypair.public_key_jwk)
        self._keypair = keypair
        self._allow_key_export = allow_key_export
        self._store: Optional[KeyStore] = None
        self._signer = Signer.from_keypair(keypair, default_expiry_seconds=default_expiry_seconds)

        # Secure by default: persist the new identity somewhere durable, or say
        # plainly that it is memory-only so it is not silently lost.
        resolved = (
            store if store is not None else (resolve_default_store(password) if persist else None)
        )
        if persist and resolved is not None:
            try:
                location = resolved.save(keypair)
                self._store = resolved
                logger.info(
                    "vouch.Agent saved identity %s to %s. You can also save it "
                    "elsewhere (the CLI or another SDK) from the same keys.",
                    keypair.did,
                    location,
                )
            except Exception as e:  # never let a storage failure break minting
                logger.warning(
                    "vouch.Agent could not persist identity %s (%s); it is held "
                    "in memory only. Call agent.save(...) to store it.",
                    keypair.did,
                    e,
                )
        else:
            note = "did:key, " if is_did_key else ""
            logger.warning(
                "vouch.Agent minted identity %s (%sin memory only, not persisted). "
                "It is lost when this process exits; call agent.save(...) or set a "
                "store/password to keep it.",
                keypair.did,
                note,
            )

    # -- constructors ---------------------------------------------------------

    @classmethod
    def load(
        cls,
        private_key_jwk: str,
        did: str,
        *,
        public_key_jwk: Optional[str] = None,
        default_expiry_seconds: int = 300,
        allow_key_export: bool = True,
    ) -> "Agent":
        """Rehydrate an Agent from stored keys (no new identity is minted).

        The public key is derived from the private key when not supplied. The
        caller already holds the raw key here, so ``allow_key_export`` defaults
        to True; pass False to still gate it.
        """
        if public_key_jwk is None:
            public_key_jwk = _public_jwk_from_private(private_key_jwk)
        keypair = KeyPair(
            private_key_jwk=private_key_jwk,
            public_key_jwk=public_key_jwk,
            did=did,
        )
        return cls.from_keypair(
            keypair,
            default_expiry_seconds=default_expiry_seconds,
            allow_key_export=allow_key_export,
        )

    @classmethod
    def from_keypair(
        cls,
        keypair: KeyPair,
        *,
        default_expiry_seconds: int = 300,
        allow_key_export: bool = True,
    ) -> "Agent":
        """Build an Agent from an existing :class:`~vouch.keys.KeyPair`."""
        if not keypair.did:
            raise ValueError("Agent.from_keypair requires a keypair with a DID")
        agent = cls.__new__(cls)
        agent._keypair = keypair
        agent._allow_key_export = allow_key_export
        agent._store = None
        agent._signer = Signer.from_keypair(keypair, default_expiry_seconds=default_expiry_seconds)
        return agent

    @classmethod
    def from_store(
        cls,
        did: str,
        store: KeyStore,
        *,
        default_expiry_seconds: int = 300,
        allow_key_export: bool = False,
    ) -> "Agent":
        """Load a previously persisted identity from a :class:`KeyStore`.

        The raw key stays gated by default (``allow_key_export=False``): the
        Agent can sign, but does not hand the key back.
        """
        keypair = store.load(did)
        agent = cls.from_keypair(
            keypair,
            default_expiry_seconds=default_expiry_seconds,
            allow_key_export=allow_key_export,
        )
        agent._store = store
        return agent

    # -- identity -------------------------------------------------------------

    @property
    def did(self) -> str:
        return self._keypair.did or ""

    @property
    def public_key_jwk(self) -> str:
        return self._keypair.public_key_jwk

    @property
    def private_key_jwk(self) -> str:
        """The raw private key. Gated: requires ``allow_key_export=True``.

        The whole point of an Agent is that signing happens through it without
        the caller touching the key. Reading the raw key is an explicit,
        opt-in action so it does not leak by accident.
        """
        self._require_export("private_key_jwk")
        return self._keypair.private_key_jwk

    @property
    def keypair(self) -> KeyPair:
        """The full KeyPair (includes the private key). Gated like
        :attr:`private_key_jwk`."""
        self._require_export("keypair")
        return self._keypair

    def _require_export(self, what: str) -> None:
        if not self._allow_key_export:
            raise PermissionError(
                f"Access to {what} is disabled for this Agent. The private key is "
                "meant to stay inside the Agent and sign on your behalf. If you "
                "really need the raw key, create the Agent with allow_key_export=True."
            )

    @property
    def signer(self) -> Signer:
        return self._signer

    # -- signing --------------------------------------------------------------

    def sign(
        self,
        intent: Optional[Dict[str, Any]] = None,
        *,
        action: Optional[str] = None,
        target: Optional[str] = None,
        resource: Optional[str] = None,
        valid_seconds: Optional[int] = None,
        reputation_score: Optional[int] = None,
        parent_credential: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Sign an intent as a Vouch Credential. Same return as
        :meth:`Signer.sign`.
        """
        return self._signer.sign(
            intent,
            action=action,
            target=target,
            resource=resource,
            valid_seconds=valid_seconds,
            reputation_score=reputation_score,
            parent_credential=parent_credential,
        )

    def delegate(
        self,
        *,
        action: str,
        target: str,
        resource: str,
        to: Optional[str] = None,
        valid_seconds: Optional[int] = None,
        reputation_score: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Issue a delegation grant from this agent (the principal side).

        Hand the returned grant to a delegatee and pass it as
        ``parent_credential=`` to its :meth:`sign` calls; the resource-narrowing
        rule (Specification §9.3) then constrains what it can sign.
        """
        intent: Dict[str, Any] = {"action": action, "target": target, "resource": resource}
        if to:
            intent["delegatee"] = to
        return self._signer.sign(
            intent,
            valid_seconds=valid_seconds,
            reputation_score=reputation_score,
        )

    # -- verification ---------------------------------------------------------

    def verify(
        self,
        credential: Any,
        *,
        public_key: Optional[Any] = None,
        allow_did_resolution: bool = True,
    ) -> Tuple[bool, Optional[CredentialPassport]]:
        """Verify a credential.

        If it was issued by this agent (issuer matches :attr:`did`), it is
        verified offline against this agent's own public key. Otherwise the
        issuer key is resolved by DID (``did:web`` / ``did:key`` / trusted
        roots), exactly like :func:`vouch.verify`. An explicit ``public_key``
        always overrides and forces offline verification.
        """
        if public_key is None and _issuer_of(credential) == self.did:
            return Verifier.verify(credential, public_key=self.public_key_jwk)
        return verify(
            credential,
            public_key=public_key,
            allow_did_resolution=allow_did_resolution,
        )

    # -- persistence ----------------------------------------------------------

    def save(
        self,
        store: Optional[KeyStore] = None,
        *,
        password: Optional[str] = None,
        key_dir: Optional[str] = None,
    ) -> str:
        """Persist this identity and return where it was saved.

        Pass a :class:`KeyStore` to choose the backend. With no store, this saves
        to the on-disk encrypted keystore (``~/.vouch/keys``); pass a
        ``password`` to encrypt the private key at rest (strongly recommended).
        """
        if store is None:
            from vouch.keystore import EncryptedFileKeyStore

            store = EncryptedFileKeyStore(key_dir=key_dir, password=password)
        location = store.save(self._keypair)
        self._store = store
        logger.info("vouch.Agent saved identity %s to %s.", self.did, location)
        return location

    def __repr__(self) -> str:
        return f"Agent(did={self.did!r})"


def _issuer_of(credential: Any) -> Optional[str]:
    """Best-effort extraction of the issuer DID from a credential dict/JSON."""
    try:
        cred = json.loads(credential) if isinstance(credential, str) else credential
        if not isinstance(cred, dict):
            return None
        issuer = cred.get("issuer")
        if isinstance(issuer, list):
            return issuer[0] if issuer else None
        return issuer
    except (ValueError, TypeError):
        return None


def _did_key_from_pub_jwk(jwk_json: str) -> str:
    """Derive a did:key from an Ed25519 public-key JWK."""
    from jwcrypto.common import base64url_decode

    from vouch import multikey

    data = json.loads(jwk_json)
    raw = base64url_decode(data["x"])
    return "did:key:" + multikey.encode_ed25519_public(raw)


def _public_jwk_from_private(private_key_jwk: str) -> str:
    """Derive the public JWK string from a private JWK string."""
    from jwcrypto import jwk

    key = jwk.JWK.from_json(private_key_jwk)
    return key.export_public()


__all__ = ["Agent"]
