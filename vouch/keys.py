"""
Vouch Protocol Key Management.

Handles secure storage, encryption, and retrieval of agent identities.
Uses Scrypt for key derivation and ChaCha20Poly1305 for authenticated encryption.
"""

import os
import re
import json
import base64
import glob
import logging
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any

from jwcrypto import jwk
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logger = logging.getLogger(__name__)

# Constants
VOUCH_DIR = os.path.expanduser("~/.vouch")
KEYS_DIR = os.path.join(VOUCH_DIR, "keys")


@dataclass
class KeyPair:
    """Represents an Ed25519 key pair for Vouch identity."""

    private_key_jwk: str
    public_key_jwk: str
    did: Optional[str] = None


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
        Save identity to disk. Encrypts private key if password provided.
        """
        if not identity.did:
            raise ValueError("Cannot save identity without a DID")

        filename = self._get_filename(identity.did)

        data = {
            "v": 1,
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
        else:
            # Plaintext storage: discouraged. The private key sits unencrypted
            # on disk; prefer passing a password.
            logger.warning(
                "Saving identity %s WITHOUT a password: the private key is "
                "stored in plaintext. Provide a password to encrypt it.",
                identity.did,
            )
            data["private_key"] = identity.private_key_jwk

        # Write with 0o600 at creation so there is no window where the file is
        # world/group-readable (umask only removes permission bits, never adds
        # them). chmod afterwards also tightens a pre-existing looser file.
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
        finally:
            os.chmod(filename, 0o600)

    def load_identity(self, did: str, password: Optional[str] = None) -> KeyPair:
        """
        Load identity from disk. Decrypts if encrypted.
        """
        filename = self._get_filename(did)
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Identity {did} not found")

        with open(filename, "r") as f:
            data = json.load(f)

        if data.get("encrypted"):
            if not password:
                raise ValueError("Password required to decrypt identity")

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
                raise ValueError("Decryption failed. Invalid password or corrupted file.") from e
        else:
            private_key_jwk = data["private_key"]

        return KeyPair(
            did=data["id"], public_key_jwk=data["public_key"], private_key_jwk=private_key_jwk
        )

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


def generate_identity(domain: Optional[str] = None) -> KeyPair:
    """Generate a new Ed25519 keypair for agent identity."""
    key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    private_key = key.export_private()
    public_key = key.export_public()
    did = f"did:web:{domain}" if domain else None
    return KeyPair(private_key_jwk=private_key, public_key_jwk=public_key, did=did)
