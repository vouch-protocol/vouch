"""
Where a minted identity is saved, so it is not lost when the process exits.

A freshly generated identity (DID, private key, public key) lives only in memory
until something persists it. This module gives a small, uniform ``KeyStore``
interface and a few backends, so the SDK can save by default to the most secure
place available rather than leaving the key to vanish:

  - ``MemoryKeyStore``        in-process only (explicitly ephemeral)
  - ``EncryptedFileKeyStore`` encrypted file on disk (~/.vouch/keys), the
                              existing KeyManager, password-protected at rest
  - ``KeyringKeyStore``       the OS keyring/secret service (Keychain, Windows
                              Credential Locker, libsecret), optional dependency

``resolve_default_store()`` picks the best available backend. The private key
itself is never returned to the end user by these stores unless a caller
explicitly loads it; the intended flow is that signing happens through the stored
identity, not by handing the raw key around.
"""

from __future__ import annotations

import json
import logging
import os
from typing import List, Optional, Protocol, runtime_checkable

from vouch.keys import KeyManager, KeyPair

logger = logging.getLogger(__name__)


@runtime_checkable
class KeyStore(Protocol):
    """A place identities can be saved to and loaded from."""

    name: str

    def save(self, identity: KeyPair) -> str:
        """Persist an identity. Returns a human-readable location string."""
        ...

    def load(self, did: str) -> KeyPair:
        """Load a previously saved identity by DID."""
        ...

    def list(self) -> List[str]:
        """List the DIDs this store holds."""
        ...

    def delete(self, did: str) -> None:
        """Remove a stored identity."""
        ...


class MemoryKeyStore:
    """In-process store. Explicitly ephemeral: nothing survives the process."""

    name = "memory"

    def __init__(self) -> None:
        self._items: dict = {}

    def save(self, identity: KeyPair) -> str:
        if not identity.did:
            raise ValueError("Cannot store an identity without a DID")
        self._items[identity.did] = identity
        return "memory (not persisted)"

    def load(self, did: str) -> KeyPair:
        if did not in self._items:
            raise FileNotFoundError(f"Identity {did} not in memory store")
        return self._items[did]

    def list(self) -> List[str]:
        return list(self._items)

    def delete(self, did: str) -> None:
        self._items.pop(did, None)


class EncryptedFileKeyStore:
    """Encrypted-at-rest file store under ~/.vouch/keys (wraps KeyManager).

    Pass a ``password`` to encrypt the private key (strongly recommended). With
    no password the underlying KeyManager writes plaintext and logs a warning.
    """

    name = "encrypted-file"

    def __init__(self, key_dir: Optional[str] = None, password: Optional[str] = None) -> None:
        self._manager = KeyManager(key_dir) if key_dir else KeyManager()
        self._password = password

    def save(self, identity: KeyPair) -> str:
        self._manager.save_identity(identity, password=self._password)
        return f"{self._manager.key_dir} ({'encrypted' if self._password else 'plaintext'})"

    def load(self, did: str) -> KeyPair:
        return self._manager.load_identity(did, password=self._password)

    def list(self) -> List[str]:
        return [entry["did"] for entry in self._manager.list_identities()]

    def delete(self, did: str) -> None:
        path = self._manager._get_filename(did)
        if os.path.exists(path):
            os.remove(path)


class KeyringKeyStore:
    """OS keyring / secret service store (Keychain, Credential Locker, libsecret).

    Requires the optional ``keyring`` package. The OS protects the secret; the
    raw key is not written to a plaintext file. An index of stored DIDs is kept
    under a single keyring entry so :meth:`list` works.
    """

    name = "os-keyring"
    _SERVICE = "vouch-protocol"
    _INDEX = "__index__"

    def __init__(self, service: Optional[str] = None) -> None:
        try:
            import keyring  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                "KeyringKeyStore needs the optional 'keyring' package (pip install keyring)"
            ) from e
        self._service = service or self._SERVICE

    def _keyring(self):
        import keyring

        return keyring

    def save(self, identity: KeyPair) -> str:
        if not identity.did:
            raise ValueError("Cannot store an identity without a DID")
        kr = self._keyring()
        blob = json.dumps(
            {
                "did": identity.did,
                "public_key_jwk": identity.public_key_jwk,
                "private_key_jwk": identity.private_key_jwk,
            }
        )
        kr.set_password(self._service, identity.did, blob)
        index = set(self.list())
        index.add(identity.did)
        kr.set_password(self._service, self._INDEX, json.dumps(sorted(index)))
        return f"OS keyring (service {self._service!r})"

    def load(self, did: str) -> KeyPair:
        blob = self._keyring().get_password(self._service, did)
        if not blob:
            raise FileNotFoundError(f"Identity {did} not in keyring")
        data = json.loads(blob)
        return KeyPair(
            private_key_jwk=data["private_key_jwk"],
            public_key_jwk=data["public_key_jwk"],
            did=data["did"],
        )

    def list(self) -> List[str]:
        raw = self._keyring().get_password(self._service, self._INDEX)
        return json.loads(raw) if raw else []

    def delete(self, did: str) -> None:
        kr = self._keyring()
        try:
            kr.delete_password(self._service, did)
        except Exception:  # pragma: no cover - backend-specific "not found"
            pass
        index = [d for d in self.list() if d != did]
        kr.set_password(self._service, self._INDEX, json.dumps(index))


def resolve_default_store(password: Optional[str] = None) -> Optional[KeyStore]:
    """Pick the best available store for secure-by-default persistence.

    Order:
      1. ``VOUCH_KEYSTORE`` = ``memory`` | ``keyring`` | ``file`` (explicit).
      2. The OS keyring, if the ``keyring`` package is installed.
      3. The encrypted file store, if a password is available (argument or
         ``VOUCH_KEY_PASSWORD``).
      4. ``None`` (no secure persistence available; the caller should keep the
         identity in memory and tell the user).
    """
    choice = os.getenv("VOUCH_KEYSTORE", "").strip().lower()
    password = password or os.getenv("VOUCH_KEY_PASSWORD")

    if choice == "memory":
        return MemoryKeyStore()
    if choice == "keyring":
        return KeyringKeyStore()
    if choice == "file":
        return EncryptedFileKeyStore(password=password)

    try:
        return KeyringKeyStore()
    except RuntimeError:
        pass

    if password:
        return EncryptedFileKeyStore(password=password)

    return None


__all__ = [
    "KeyStore",
    "MemoryKeyStore",
    "EncryptedFileKeyStore",
    "KeyringKeyStore",
    "resolve_default_store",
]
