"""
Vouch Protocol Key Management.

Handles secure storage, encryption, and retrieval of agent identities.
Uses Scrypt for key derivation and ChaCha20Poly1305 for authenticated encryption.
"""

import os
import re
import json
import time
import hmac
import hashlib
import contextlib
import base64
import glob
import logging
import secrets
from dataclasses import dataclass, asdict, field
from typing import Optional, List, Dict, Any, Iterator, Tuple

from jwcrypto import jwk
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logger = logging.getLogger(__name__)

# Constants
VOUCH_DIR = os.path.expanduser("~/.vouch")
KEYS_DIR = os.path.join(VOUCH_DIR, "keys")


# The post-quantum key of an identity. It sits in the "#key-2" slot next to the
# Ed25519 key in "#key-1", the same slots a DID document publishes them under.
MLDSA44 = "ML-DSA-44"
MLDSA44_KEY_ID = "#key-2"
MLDSA44_PUBLIC_KEY_SIZE = 1312
MLDSA44_SECRET_KEY_SIZE = 2560


@dataclass
class StoredKey:
    """One further signing key of an identity, saved next to its Ed25519 key.

    Attributes:
      id: the key's slot on the identity's DID, such as "#key-2".
      alg: the algorithm, such as "ML-DSA-44".
      public_key: the public key as a Multikey string.
      private_key: the raw private key bytes.
    """

    id: str
    alg: str
    public_key: str
    private_key: bytes = field(repr=False)


@dataclass
class KeyPair:
    """An identity's keys: the Ed25519 key pair, plus any further keys."""

    private_key_jwk: str
    public_key_jwk: str
    did: Optional[str] = None
    additional_keys: List[StoredKey] = field(default_factory=list)
    # Rows of key types this release does not know, kept so a save does not
    # drop them.
    other_keys: List[Dict[str, Any]] = field(default_factory=list, repr=False)

    def key_for(self, alg: str) -> Optional[StoredKey]:
        """Return this identity's key for ``alg``, or None if it has none."""
        for key in self.additional_keys:
            if key.alg == alg:
                return key
        return None

    def mldsa44_keypair(self) -> Optional[Tuple[bytes, bytes]]:
        """The saved ML-DSA-44 key as raw (public, secret) bytes, or None."""
        from . import multikey

        key = self.key_for(MLDSA44)
        if key is None:
            return None
        return multikey.decode(key.public_key)[1], key.private_key


def new_post_quantum_key() -> StoredKey:
    """Generate a fresh ML-DSA-44 key for an identity's "#key-2" slot."""
    from . import data_integrity_hybrid, multikey

    public, secret = data_integrity_hybrid.generate_mldsa44_keypair()
    return StoredKey(
        id=MLDSA44_KEY_ID,
        alg=MLDSA44,
        public_key=multikey.encode_mldsa44_public(public),
        private_key=secret,
    )


class IdentityError(ValueError):
    """A saved identity cannot be used as it is."""


class IdentityLockedError(IdentityError):
    """The identity is locked with a passphrase and none was given."""


class WrongPasswordError(IdentityError):
    """The passphrase does not open the identity."""


class IdentityDamagedError(IdentityError):
    """The identity file was altered or is broken. Nothing is replaced on its own."""


class IdentityBusyError(IdentityError):
    """Another program is changing the identity file right now."""


class IdentityExistsError(IdentityError):
    """An identity file is already saved under this name."""


def _pqcrypto_available() -> bool:
    try:
        from . import data_integrity_hybrid

        data_integrity_hybrid._import_pqcrypto()
        return True
    except ImportError:
        return False


def _check_stored_key(key: StoredKey) -> None:
    """Check that a saved key is whole and that its two halves belong together.

    The halves are checked by signing a probe with the private key and
    verifying it with the public key. That needs the post-quantum package; when
    it is missing the sizes and the Multikey are still checked.

    Raises:
      IdentityDamagedError: the key is the wrong size, or its public half does
        not verify what its private half signs.
    """
    from . import data_integrity_hybrid, multikey

    if key.alg != MLDSA44:
        return
    try:
        alg, public = multikey.decode(key.public_key)
    except ValueError:
        raise IdentityDamagedError(f"saved {key.alg} public key is not a Multikey") from None
    if alg != MLDSA44 or len(public) != MLDSA44_PUBLIC_KEY_SIZE:
        raise IdentityDamagedError(f"saved {key.alg} public key is not an {MLDSA44} key")
    if len(key.private_key) != MLDSA44_SECRET_KEY_SIZE:
        raise IdentityDamagedError(f"saved {key.alg} private key is the wrong size")
    if not _pqcrypto_available():
        return
    ml_dsa_44 = data_integrity_hybrid._import_pqcrypto()
    probe = b"vouch-protocol key check"
    try:
        signature = ml_dsa_44.sign(key.private_key, probe)
    except Exception:
        raise IdentityDamagedError(f"saved {key.alg} private key is damaged") from None
    if not data_integrity_hybrid._mldsa44_verify(ml_dsa_44, public, probe, signature):
        raise IdentityDamagedError(f"saved {key.alg} public key does not match its private key")


def _row_binding(did: str, key_id: str, alg: str, public_key: str) -> bytes:
    """What an encrypted key row is bound to. Changing the DID, the slot, the
    algorithm or the stated public key makes the row fail to decrypt."""
    return json.dumps(
        {"did": did, "id": key_id, "alg": alg, "public_key": public_key},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class _NotJSON(ValueError):
    """NaN or Infinity, which strict JSON does not have."""


def _refuse_constant(name: str) -> Any:
    raise _NotJSON(name)


def _is_version_one(data: Dict[str, Any]) -> bool:
    """True for a file without key lists: no "v", or "v" exactly the number 1."""
    version = data.get("v", 1)
    return type(version) is int and version == 1


def _digest(private_key: bytes) -> str:
    """The check value stored beside an unlocked private key, so damage to
    any of its bytes is noticed when it is read back."""
    return hashlib.sha256(private_key).hexdigest()


def _damaged(what: str) -> IdentityDamagedError:
    return IdentityDamagedError(f"identity file is damaged: {what}")


def _read_rows(
    data: Dict[str, Any], cipher: Optional[ChaCha20Poly1305]
) -> Tuple[List[StoredKey], List[Dict[str, Any]]]:
    """Read the further keys of an identity file and check each one.

    Returns the keys this release knows, and the rows of key types it does not
    know, unchanged, so a later save carries them through. A row in the
    post-quantum slot, or one that names the post-quantum algorithm, must be
    exactly that key: anything else in it is damage, never an unknown key.

    Raises:
      IdentityDamagedError: the list or a known row is malformed or altered.
    """
    rows = data.get("keys")
    if rows is None:
        if "keys" in data or not _is_version_one(data):
            raise _damaged("its key list is missing")
        return [], []
    if not isinstance(rows, list):
        raise _damaged("its key list is not a list")

    loaded: List[StoredKey] = []
    unknown: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise _damaged("a key entry is not an object")
        alg, key_id, public_key = row.get("alg"), row.get("id"), row.get("public_key")
        if alg != MLDSA44 and key_id != MLDSA44_KEY_ID:
            # A key type this release does not know. Keep it as it is.
            unknown.append(row)
            continue
        if alg != MLDSA44 or key_id != MLDSA44_KEY_ID or not isinstance(public_key, str):
            raise _damaged(f"its {MLDSA44} entry is malformed")
        if loaded:
            raise _damaged(f"it holds two {MLDSA44} keys")
        try:
            if cipher is not None:
                # A locked file keeps every private key locked: a row that
                # also carries one in the clear has been altered.
                if "private_key" in row or "private_key_sha256" in row:
                    raise ValueError("unlocked key in a locked file")
                sealed = row["cipher"]
                private_key = cipher.decrypt(
                    base64.b64decode(sealed["nonce"], validate=True),
                    base64.b64decode(sealed["ciphertext"], validate=True),
                    _row_binding(data["id"], key_id, alg, public_key),
                )
            else:
                if "cipher" in row:
                    raise ValueError("locked key in an unlocked file")
                encoded = row["private_key"]
                private_key = base64.b64decode(encoded, validate=True)
                if base64.b64encode(private_key).decode("ascii") != encoded:
                    raise ValueError("not canonical base64")
                digest = row["private_key_sha256"]
                if not isinstance(digest, str) or not hmac.compare_digest(
                    digest.lower(), _digest(private_key)
                ):
                    raise ValueError("check value does not match")
        except Exception:
            raise _damaged(f"its {MLDSA44} key cannot be read") from None
        key = StoredKey(id=key_id, alg=alg, public_key=public_key, private_key=private_key)
        _check_stored_key(key)
        loaded.append(key)
    return loaded, unknown


def _try_lock(fd: int) -> None:
    """Take an exclusive lock on an open file without waiting. The operating
    system drops it when the holder exits, so a stopped program never leaves
    the identity locked."""
    if os.name == "nt":  # pragma: no cover - exercised on Windows only
        import msvcrt

        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(fd: int) -> None:
    if os.name == "nt":  # pragma: no cover - exercised on Windows only
        import msvcrt

        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


class KeyManager:
    """Manages secure storage and retrieval of Vouch identities."""

    def __init__(self, key_dir: str = KEYS_DIR):
        self.key_dir = key_dir
        self._ensure_dir()

    def _ensure_dir(self):
        """Ensure keys directory exists with secure permissions."""
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir, mode=0o700, exist_ok=True)

    def _get_filename(self, did: str) -> str:
        """
        Convert a DID to a safe filename. Whitelists filename characters so a
        crafted DID (containing '/', '\\', or '..') cannot escape the key
        directory via path traversal. For normal DIDs this matches the historic
        scheme (':' becomes '-'), so existing files keep their names.
        """
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "-", did).strip(".")
        if not safe_name:
            raise ValueError(f"DID does not yield a safe filename: {did!r}")
        path = os.path.join(self.key_dir, f"{safe_name}.json")
        # Defense in depth: the resolved path must stay inside key_dir.
        if os.path.dirname(os.path.realpath(path)) != os.path.realpath(self.key_dir):
            raise ValueError(f"unsafe key path for DID {did!r}")
        return path

    def save_identity(self, identity: KeyPair, password: Optional[str] = None):
        """
        Save identity to disk. Encrypts the private keys if password provided.

        The Ed25519 key keeps the fields it has always had, so earlier readers
        still open the file. Any further keys (see ``KeyPair.additional_keys``)
        go into a "keys" list, one row per key. The file is written to a
        temporary name and moved into place, so an interrupted save leaves the
        previous file intact.
        """
        if not identity.did:
            raise ValueError("Cannot save identity without a DID")
        rows = list(identity.additional_keys)
        others = list(identity.other_keys)
        if len({row.alg for row in rows}) != len(rows) or len({row.id for row in rows}) != len(
            rows
        ):
            raise ValueError("an identity holds one key per algorithm and per key id")
        for row in rows:
            _check_stored_key(row)

        filename = self._get_filename(identity.did)

        data: Dict[str, Any] = {
            "v": 2 if rows or others else 1,
            "id": identity.did,
            "algo": "Ed25519",
            "public_key": identity.public_key_jwk,
            "encrypted": False,
        }

        if password:
            # Encrypt private key
            salt = os.urandom(16)

            # KDF: Scrypt (Standard params for interactive login)
            n_cost = 16384  # 2^14
            r_block = 8
            p_parallel = 1

            kdf = Scrypt(
                salt=salt,
                length=32,
                n=n_cost,
                r=r_block,
                p=p_parallel,
            )
            key = kdf.derive(password.encode())

            # Encryption: ChaCha20-Poly1305
            nonce = os.urandom(12)
            cipher = ChaCha20Poly1305(key)
            ciphertext = cipher.encrypt(nonce, identity.private_key_jwk.encode(), None)

            data["encrypted"] = True
            data["kdf"] = {
                "algo": "scrypt",
                "params": {
                    "n": n_cost,
                    "r": r_block,
                    "p": p_parallel,
                    "salt": base64.b64encode(salt).decode("utf-8"),
                },
            }
            data["cipher"] = {
                "algo": "chacha20-poly1305",
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            }
            # Each further key is encrypted on its own, under the same derived
            # key and a fresh nonce, bound to this DID and to its own slot.
            encrypted_rows = []
            for row in rows:
                row_nonce = os.urandom(12)
                sealed = cipher.encrypt(
                    row_nonce,
                    row.private_key,
                    _row_binding(identity.did, row.id, row.alg, row.public_key),
                )
                encrypted_rows.append(
                    {
                        "id": row.id,
                        "alg": row.alg,
                        "public_key": row.public_key,
                        "cipher": {
                            "algo": "chacha20-poly1305",
                            "nonce": base64.b64encode(row_nonce).decode("utf-8"),
                            "ciphertext": base64.b64encode(sealed).decode("utf-8"),
                        },
                    }
                )
            if encrypted_rows or others:
                data["keys"] = encrypted_rows + others
        else:
            # Plaintext storage: discouraged. The private key sits unencrypted
            # on disk; prefer passing a password.
            logger.warning(
                "Saving identity %s WITHOUT a password: the private key is "
                "stored in plaintext. Provide a password to encrypt it.",
                identity.did,
            )
            data["private_key"] = identity.private_key_jwk
            if rows or others:
                data["keys"] = [
                    {
                        "id": row.id,
                        "alg": row.alg,
                        "public_key": row.public_key,
                        "private_key": base64.b64encode(row.private_key).decode("utf-8"),
                        "private_key_sha256": _digest(row.private_key),
                    }
                    for row in rows
                ] + others

        self._sweep_temporary_files(filename)
        # Write to a temporary file created with 0o600, so there is no window
        # where the keys are world/group-readable, then move it into place.
        temporary = f"{filename}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, filename)
        except BaseException:
            if os.path.exists(temporary):
                os.remove(temporary)
            raise
        os.chmod(filename, 0o600)

    @staticmethod
    def _sweep_temporary_files(filename: str) -> None:
        """Remove temporary files a stopped save left behind. They hold private
        keys, so they are not left lying around. A save takes milliseconds,
        so a temporary file older than a minute belongs to no live save."""
        for leftover in glob.glob(glob.escape(filename) + ".*.tmp"):
            try:
                if time.time() - os.path.getmtime(leftover) > 60:
                    os.remove(leftover)
            except OSError:
                continue

    def _read_file(self, did: str) -> Dict[str, Any]:
        filename = self._get_filename(did)
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Identity {did} not found")
        try:
            with open(filename, "r") as f:
                data = json.load(f, parse_constant=_refuse_constant)
        except (json.JSONDecodeError, _NotJSON):
            raise _damaged("it is not valid JSON") from None
        if not isinstance(data, dict):
            raise _damaged("it is not a JSON object")
        return data

    def load_identity(self, did: str, password: Optional[str] = None) -> KeyPair:
        """
        Load identity from disk. Decrypts if encrypted.

        Raises:
          FileNotFoundError: no identity is saved for ``did``.
          IdentityLockedError: the identity is locked and no password was given.
          WrongPasswordError: the password does not open it, or a password was
            given for a file that is not locked (it may have been replaced).
          IdentityDamagedError: the file or a saved key is damaged. A damaged
            key is never replaced with a new one on its own.
        """
        data = self._read_file(did)

        cipher: Optional[ChaCha20Poly1305] = None
        if data.get("encrypted"):
            if not password:
                raise IdentityLockedError("Password required to decrypt identity")

            try:
                # Extract KDF params
                kdf_params = data["kdf"]["params"]
                salt = base64.b64decode(kdf_params["salt"])

                # Derive key
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=kdf_params["n"],
                    r=kdf_params["r"],
                    p=kdf_params["p"],
                )
                key = kdf.derive(password.encode())

                # Decrypt
                cipher_info = data["cipher"]
                nonce = base64.b64decode(cipher_info["nonce"])
                ciphertext = base64.b64decode(cipher_info["ciphertext"])

                cipher = ChaCha20Poly1305(key)
                private_key_jwk = cipher.decrypt(nonce, ciphertext, None).decode("utf-8")

            except Exception as e:
                raise WrongPasswordError(
                    "Decryption failed. Invalid password or corrupted file."
                ) from e
        else:
            if password:
                raise WrongPasswordError(
                    f"the identity file for {did} is not locked, but a passphrase was given. "
                    "If it was saved without a passphrase, unset VOUCH_KEY_PASSPHRASE. Otherwise "
                    "it may have been replaced; check it before using it"
                )
            try:
                private_key_jwk = data["private_key"]
            except KeyError:
                raise _damaged("it has no private key") from None

        rows, others = _read_rows(data, cipher)
        try:
            return KeyPair(
                did=data["id"],
                public_key_jwk=data["public_key"],
                private_key_jwk=private_key_jwk,
                additional_keys=rows,
                other_keys=others,
            )
        except KeyError as e:
            raise _damaged(f"it has no {e.args[0]!r} field") from None

    @contextlib.contextmanager
    def _identity_lock(self, did: str, timeout: float = 10.0) -> Iterator[None]:
        """Hold the identity's lock while its file is created or changed.

        The lock is held by the operating system on a ".lock" file next to the
        identity, so it is released when the holder exits, even after a crash.

        Raises:
          IdentityBusyError: another program held it for longer than ``timeout``.
          OSError: the lock file cannot be created (for example, a read-only
            keystore).
        """
        path = self._get_filename(did) + ".lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    _try_lock(fd)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise IdentityBusyError(
                            f"the identity for {did} is busy; try again"
                        ) from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                _unlock(fd)
        finally:
            os.close(fd)

    def create_identity(self, identity: KeyPair, password: Optional[str] = None) -> None:
        """
        Save a new identity, refusing to replace any file already saved under
        its name. Two programs creating the same identity at once: one saves,
        the other gets IdentityExistsError.

        Raises:
          IdentityExistsError: a file is already saved under this name.
        """
        if not identity.did:
            raise ValueError("Cannot save identity without a DID")
        with self._identity_lock(identity.did):
            if os.path.exists(self._get_filename(identity.did)):
                raise IdentityExistsError(f"an identity is already saved for {identity.did}")
            self.save_identity(identity, password)

    def ensure_post_quantum_key(
        self, did: str, password: Optional[str] = None, timeout: float = 10.0
    ) -> KeyPair:
        """
        Make sure the identity has a saved ML-DSA-44 key, and return the identity.

        An identity created before post-quantum keys were saved (a file with no
        key list) gains one here, once, and keeps it. Its Ed25519 key is left as
        it is. A file that has a key list but no post-quantum key has been
        altered, and is refused rather than given a new key. Two programs that
        call this at the same moment end up with the same key.

        Raises:
          FileNotFoundError: no identity is saved for ``did``.
          IdentityError: locked, wrong password, damaged, or busy.
          OSError: the keystore cannot be written.
        """
        self._sweep_temporary_files(self._get_filename(did))
        identity = self.load_identity(did, password)
        if identity.key_for(MLDSA44) is not None:
            return identity
        with self._identity_lock(did, timeout):
            identity = self.load_identity(did, password)
            if identity.key_for(MLDSA44) is not None:
                return identity
            data = self._read_file(did)
            if "keys" in data or not _is_version_one(data):
                raise _damaged(
                    "it has a key list but no post-quantum key, so it was altered. "
                    "Restore it from a backup"
                )
            identity.additional_keys.append(new_post_quantum_key())
            self.save_identity(identity, password)
            logger.warning(
                "Added a post-quantum key (#key-2) to the saved identity %s. Publish it in the "
                "DID document before relying on post-quantum proofs.",
                did,
            )
            return self.load_identity(did, password)

    def is_locked(self, did: str) -> bool:
        """True when the identity file for ``did`` is locked with a passphrase."""
        try:
            return bool(self._read_file(did).get("encrypted"))
        except (FileNotFoundError, IdentityError):
            return False

    def post_quantum_public_key(self, did: str, password: Optional[str] = None) -> Optional[str]:
        """
        The identity's saved ML-DSA-44 public key (a Multikey), or None.

        The key is returned only after the identity has been fully read and
        checked, so a locked identity needs its passphrase. Without it the
        answer is None: a stated key that cannot be checked is never published.

        Raises:
          FileNotFoundError: no identity is saved for ``did``.
          WrongPasswordError, IdentityDamagedError: as for load_identity.
        """
        try:
            identity = self.load_identity(did, password)
        except IdentityLockedError:
            return None
        key = identity.key_for(MLDSA44)
        return key.public_key if key else None

    def get_public_key(self, did: str) -> Optional[str]:
        """
        Return the public key JWK stored for ``did``, or None if this keystore
        does not hold that identity.

        The public key is stored in the clear even when the private key is
        encrypted, so no password is needed.
        """
        try:
            filename = self._get_filename(did)
        except ValueError:
            return None
        if not os.path.exists(filename):
            return None
        try:
            with open(filename, "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
        # Different DIDs can map to the same filename, so the file has to name
        # this exact DID before its key is used for it.
        if not isinstance(data, dict) or data.get("id") != did:
            return None
        public_key = data.get("public_key")
        return public_key if isinstance(public_key, str) and public_key else None

    def list_identities(self) -> List[Dict[str, Any]]:
        """List all stored identities."""
        identities = []
        pattern = os.path.join(self.key_dir, "*.json")
        for filepath in glob.glob(pattern):
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                    identities.append(
                        {
                            "did": data["id"],
                            "encrypted": data.get("encrypted", False),
                            "file": filepath,
                        }
                    )
            except Exception:
                continue
        return identities


def generate_identity(domain: Optional[str] = None, post_quantum: bool = False) -> KeyPair:
    """Generate a new Ed25519 keypair for agent identity.

    With ``post_quantum`` the identity also gets an ML-DSA-44 key, so that both
    keys are saved, and can be published, from the start.
    """
    key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    private_key = key.export_private()
    public_key = key.export_public()
    did = f"did:web:{domain}" if domain else None
    identity = KeyPair(private_key_jwk=private_key, public_key_jwk=public_key, did=did)
    if post_quantum:
        identity.additional_keys.append(new_post_quantum_key())
    return identity
