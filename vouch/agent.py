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

from vouch.keys import KeyManager, KeyPair, generate_identity
from vouch.signer import Signer
from vouch.verifier import CredentialPassport, Verifier, verify

logger = logging.getLogger(__name__)


class Agent:
    """An agent identity bundled with its signer.

    Construct it to mint a fresh identity, or use :meth:`load` /
    :meth:`from_keypair` to rehydrate an existing one. With a ``domain`` the
    identity is ``did:web:<domain>``; without one it is a self-certifying
    ``did:key`` (verifiable offline, no DID document to host).

    Storage: a freshly minted DID, private key, and public key live in memory
    only (on this Agent and its Signer). Nothing is written to disk until you
    call :meth:`save`, which stores the identity under ``~/.vouch/keys`` (pass a
    ``password`` to encrypt the private key at rest).
    """

    def __init__(self, domain: Optional[str] = None, *, default_expiry_seconds: int = 300) -> None:
        keypair = generate_identity(domain=domain)
        if not keypair.did:
            keypair.did = _did_key_from_pub_jwk(keypair.public_key_jwk)
            # No domain was given, so the identity is a self-certifying did:key:
            # the key IS the identifier, with nothing to host and no authority to
            # resolve. Say so once, because a caller expecting a did:web anchor
            # would otherwise not notice. Like every freshly minted identity it
            # lives in memory only; call agent.save(password=...) to persist it.
            logger.info(
                "vouch.Agent minted a self-certifying did:key identity (%s). It "
                "is held in memory only and is not persisted; pass a domain for a "
                "did:web identity, or call agent.save(password=...) to keep it.",
                keypair.did,
            )
        else:
            logger.info(
                "vouch.Agent minted identity %s (in memory only; call "
                "agent.save(password=...) to persist it).",
                keypair.did,
            )
        self._keypair = keypair
        self._signer = Signer.from_keypair(keypair, default_expiry_seconds=default_expiry_seconds)

    # -- constructors ---------------------------------------------------------

    @classmethod
    def load(
        cls,
        private_key_jwk: str,
        did: str,
        *,
        public_key_jwk: Optional[str] = None,
        default_expiry_seconds: int = 300,
    ) -> "Agent":
        """Rehydrate an Agent from stored keys (no new identity is minted).

        The public key is derived from the private key when not supplied.
        """
        if public_key_jwk is None:
            public_key_jwk = _public_jwk_from_private(private_key_jwk)
        keypair = KeyPair(
            private_key_jwk=private_key_jwk,
            public_key_jwk=public_key_jwk,
            did=did,
        )
        return cls.from_keypair(keypair, default_expiry_seconds=default_expiry_seconds)

    @classmethod
    def from_keypair(cls, keypair: KeyPair, *, default_expiry_seconds: int = 300) -> "Agent":
        """Build an Agent from an existing :class:`~vouch.keys.KeyPair`."""
        if not keypair.did:
            raise ValueError("Agent.from_keypair requires a keypair with a DID")
        agent = cls.__new__(cls)
        agent._keypair = keypair
        agent._signer = Signer.from_keypair(keypair, default_expiry_seconds=default_expiry_seconds)
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
        return self._keypair.private_key_jwk

    @property
    def keypair(self) -> KeyPair:
        return self._keypair

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
        :meth:`Signer.sign_credential`.
        """
        return self._signer.sign_credential(
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
        return self._signer.sign_credential(
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
            return Verifier.verify_credential(credential, public_key=self.public_key_jwk)
        return verify(
            credential,
            public_key=public_key,
            allow_did_resolution=allow_did_resolution,
        )

    # -- persistence ----------------------------------------------------------

    def save(self, *, password: Optional[str] = None, key_dir: Optional[str] = None) -> None:
        """Persist this identity to the on-disk keystore (``~/.vouch/keys``).

        Pass a ``password`` to encrypt the private key (strongly recommended).
        """
        km = KeyManager(key_dir) if key_dir else KeyManager()
        km.save_identity(self._keypair, password=password)

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
