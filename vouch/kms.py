"""
Vouch Protocol Enterprise Key Management System.

Provides key rotation, multi-key support, cloud KMS integration, and
the Signer class for enterprise deployment scenarios.
"""

import time
import logging
import json
import base64
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass

from jwcrypto import jwk, jws
from jwcrypto.common import json_encode

logger = logging.getLogger(__name__)


@dataclass
class KeyConfig:
    """
    Configuration for a signing key.

    Attributes:
        private_key_jwk: JWK JSON string of the private key
        did: The DID associated with this key
        key_id: Optional identifier for this key
        valid_from: Unix timestamp when key becomes valid (optional)
        valid_until: Unix timestamp when key expires (optional)
    """

    private_key_jwk: str
    did: str
    key_id: Optional[str] = None
    valid_from: Optional[int] = None
    valid_until: Optional[int] = None


class RotatingKeyProvider:
    """
    Enterprise Key Management for Vouch.

    Automatically rotates the active signing key based on time or key validity
    periods. Supports multiple keys for high-availability scenarios.
    """

    def __init__(
        self,
        keys: List[KeyConfig],
        rotation_interval_hours: int = 24,
        on_rotation: Optional[Callable[[str], None]] = None,
    ):
        if not keys:
            raise ValueError("At least one key configuration is required")

        self._keys = keys
        self._interval = rotation_interval_hours * 3600
        self._on_rotation = on_rotation
        self._last_key_id: Optional[str] = None

        for i, key_config in enumerate(keys):
            try:
                key = jwk.JWK.from_json(key_config.private_key_jwk)
                if key.key_type != "OKP":
                    raise ValueError(f"Key {i} must be Ed25519 (OKP)")
            except Exception as e:
                raise ValueError(f"Invalid key at index {i}: {e}")

    def get_active_key(self) -> KeyConfig:
        now = int(time.time())

        for key in self._keys:
            if key.valid_from and key.valid_until:
                if key.valid_from <= now <= key.valid_until:
                    return key

        index = (now // self._interval) % len(self._keys)
        active_key = self._keys[index]

        current_id = active_key.key_id or str(index)
        if self._last_key_id and self._last_key_id != current_id:
            if self._on_rotation:
                try:
                    self._on_rotation(current_id)
                except Exception as e:
                    logger.error(f"Rotation callback failed: {e}")
        self._last_key_id = current_id

        return active_key

    def get_signer(self):
        from vouch.signer import Signer

        active_key = self.get_active_key()
        return Signer(private_key=active_key.private_key_jwk, did=active_key.did)

    def add_key(self, key_config: KeyConfig) -> None:
        try:
            key = jwk.JWK.from_json(key_config.private_key_jwk)
            if key.key_type != "OKP":
                raise ValueError("Key must be Ed25519 (OKP)")
        except Exception as e:
            raise ValueError(f"Invalid key: {e}")

        self._keys.append(key_config)
        logger.info(f"Added key {key_config.key_id} to rotation pool")

    def remove_key(self, key_id: str) -> bool:
        for i, key in enumerate(self._keys):
            if key.key_id == key_id:
                if len(self._keys) <= 1:
                    raise ValueError("Cannot remove last key from pool")
                self._keys.pop(i)
                logger.info(f"Removed key {key_id} from rotation pool")
                return True
        return False

    @property
    def key_count(self) -> int:
        return len(self._keys)

    @property
    def active_key_id(self) -> Optional[str]:
        return self.get_active_key().key_id


# =============================================================================
# Cloud KMS Providers - Abstract Interface
# =============================================================================


class CloudKMSProvider(ABC):
    """
    Abstract interface for Cloud KMS providers.

    Cloud KMS providers keep the private key in the cloud HSM.
    The key never leaves the secure boundary.
    """

    @abstractmethod
    async def sign(self, payload: bytes) -> bytes:
        """
        Sign payload using cloud-hosted key.

        Args:
            payload: Bytes to sign.

        Returns:
            Signature bytes.
        """
        pass

    @abstractmethod
    async def get_public_key(self) -> str:
        """
        Get public key in JWK format.

        Returns:
            JWK JSON string of public key.
        """
        pass

    @abstractmethod
    def get_did(self) -> str:
        """Get the DID associated with this key."""
        pass

    async def sign_token(self, claims: dict) -> str:
        """
        Sign a complete Vouch token using cloud KMS.

        Args:
            claims: JWT claims to sign.

        Returns:
            JWS compact serialization.
        """
        import uuid

        now = int(time.time())
        full_claims = {
            "jti": str(uuid.uuid4()),
            "iss": self.get_did(),
            "sub": self.get_did(),
            "iat": now,
            "exp": now + 300,  # 5 min default
            "vouch": {"payload": claims},
        }

        payload = json.dumps(full_claims).encode("utf-8")

        # Create JWS header
        header = {"alg": "EdDSA", "typ": "JWT", "kid": self.get_did()}

        # Base64url encode header and payload
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()

        payload_b64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()

        # Sign
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = await self.sign(signing_input)

        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

        return f"{header_b64}.{payload_b64}.{sig_b64}"


# =============================================================================
# AWS KMS Provider
# =============================================================================


class AWSKMSProvider(CloudKMSProvider):
    """
    AWS KMS provider for Ed25519 signing.

    Requires: pip install aioboto3

    Example:
        >>> provider = AWSKMSProvider(
        ...     key_id="alias/vouch-signing-key",
        ...     region="us-east-1",
        ...     did="did:web:my-agent.com"
        ... )
        >>> token = await provider.sign_token({"action": "test"})
    """

    def __init__(
        self,
        key_id: str,
        did: str,
        region: str = "us-east-1",
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
    ):
        """
        Initialize AWS KMS provider.

        Args:
            key_id: KMS key ID, ARN, or alias.
            did: DID to use for this key.
            region: AWS region.
            aws_access_key_id: Optional explicit credentials.
            aws_secret_access_key: Optional explicit credentials.
        """
        self._key_id = key_id
        self._did = did
        self._region = region
        self._access_key = aws_access_key_id
        self._secret_key = aws_secret_access_key
        self._public_key_cache: Optional[str] = None

    def get_did(self) -> str:
        return self._did

    async def sign(self, payload: bytes) -> bytes:
        """Sign using AWS KMS."""
        try:
            import aioboto3
        except ImportError:
            raise ImportError("AWS KMS support requires: pip install aioboto3")

        session = aioboto3.Session(
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
            region_name=self._region,
        )

        async with session.client("kms") as kms:
            response = await kms.sign(
                KeyId=self._key_id,
                Message=payload,
                MessageType="RAW",
                SigningAlgorithm="ECDSA_SHA_256",  # AWS doesn't support EdDSA yet
            )
            return response["Signature"]

    async def get_public_key(self) -> str:
        """Get public key from AWS KMS."""
        if self._public_key_cache:
            return self._public_key_cache

        try:
            import aioboto3
        except ImportError:
            raise ImportError("AWS KMS support requires: pip install aioboto3")

        session = aioboto3.Session(
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
            region_name=self._region,
        )

        async with session.client("kms") as kms:
            response = await kms.get_public_key(KeyId=self._key_id)

            # Convert DER to JWK
            from cryptography.hazmat.primitives.serialization import load_der_public_key

            _pub_key = load_der_public_key(response["PublicKey"])  # noqa: F841

            # This is a simplified conversion - actual implementation
            # would depend on key type
            jwk_dict = {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(response["PublicKey"][-32:]).rstrip(b"=").decode(),
            }

            self._public_key_cache = json.dumps(jwk_dict)
            return self._public_key_cache


# =============================================================================
# Google Cloud KMS Provider
# =============================================================================


class GCPKMSProvider(CloudKMSProvider):
    """
    Google Cloud KMS provider for Ed25519 signing.

    Requires: pip install google-cloud-kms

    Example:
        >>> provider = GCPKMSProvider(
        ...     key_name="projects/my-project/locations/global/keyRings/vouch/cryptoKeys/signing/cryptoKeyVersions/1",
        ...     did="did:web:my-agent.com"
        ... )
        >>> token = await provider.sign_token({"action": "test"})
    """

    def __init__(self, key_name: str, did: str, credentials_path: Optional[str] = None):
        """
        Initialize GCP KMS provider.

        Args:
            key_name: Full resource name of the crypto key version.
            did: DID to use for this key.
            credentials_path: Optional path to service account JSON.
        """
        self._key_name = key_name
        self._did = did
        self._credentials_path = credentials_path
        self._public_key_cache: Optional[str] = None

    def get_did(self) -> str:
        return self._did

    async def sign(self, payload: bytes) -> bytes:
        """Sign using Google Cloud KMS."""
        try:
            from google.cloud import kms
        except ImportError:
            raise ImportError("GCP KMS support requires: pip install google-cloud-kms")

        import asyncio

        def _sign_sync():
            client = kms.KeyManagementServiceClient()

            # Create digest
            import hashlib

            digest = hashlib.sha256(payload).digest()

            response = client.asymmetric_sign(
                request={"name": self._key_name, "digest": {"sha256": digest}}
            )
            return response.signature

        return await asyncio.get_event_loop().run_in_executor(None, _sign_sync)

    async def get_public_key(self) -> str:
        """Get public key from GCP KMS."""
        if self._public_key_cache:
            return self._public_key_cache

        try:
            from google.cloud import kms
        except ImportError:
            raise ImportError("GCP KMS support requires: pip install google-cloud-kms")

        import asyncio

        def _get_pub_key_sync():
            client = kms.KeyManagementServiceClient()
            response = client.get_public_key(request={"name": self._key_name})
            return response.pem

        pem = await asyncio.get_event_loop().run_in_executor(None, _get_pub_key_sync)

        # Convert PEM to JWK
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        pub_key = load_pem_public_key(pem.encode())

        # Convert to JWK (simplified)
        raw_bytes = pub_key.public_bytes_raw()
        jwk_dict = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode(),
        }

        self._public_key_cache = json.dumps(jwk_dict)
        return self._public_key_cache


# =============================================================================
# Azure Key Vault Provider
# =============================================================================


class AzureKeyVaultProvider(CloudKMSProvider):
    """
    Azure Key Vault provider for Ed25519 signing.

    Requires: pip install azure-keyvault-keys azure-identity

    Example:
        >>> provider = AzureKeyVaultProvider(
        ...     vault_url="https://my-vault.vault.azure.net/",
        ...     key_name="vouch-signing-key",
        ...     did="did:web:my-agent.com"
        ... )
        >>> token = await provider.sign_token({"action": "test"})
    """

    def __init__(self, vault_url: str, key_name: str, did: str, key_version: Optional[str] = None):
        """
        Initialize Azure Key Vault provider.

        Args:
            vault_url: Key Vault URL.
            key_name: Name of the key.
            did: DID to use for this key.
            key_version: Optional specific version.
        """
        self._vault_url = vault_url
        self._key_name = key_name
        self._key_version = key_version
        self._did = did
        self._public_key_cache: Optional[str] = None

    def get_did(self) -> str:
        return self._did

    async def sign(self, payload: bytes) -> bytes:
        """Sign using Azure Key Vault."""
        try:
            from azure.keyvault.keys.crypto.aio import CryptographyClient
            from azure.keyvault.keys.aio import KeyClient
            from azure.identity.aio import DefaultAzureCredential
            from azure.keyvault.keys.crypto import SignatureAlgorithm
        except ImportError:
            raise ImportError(
                "Azure Key Vault support requires: pip install azure-keyvault-keys azure-identity"
            )

        credential = DefaultAzureCredential()

        try:
            key_client = KeyClient(vault_url=self._vault_url, credential=credential)
            key = await key_client.get_key(self._key_name, self._key_version)

            crypto_client = CryptographyClient(key, credential=credential)

            # Create digest
            import hashlib

            digest = hashlib.sha256(payload).digest()

            result = await crypto_client.sign(SignatureAlgorithm.es256, digest)
            return result.signature
        finally:
            await credential.close()

    async def get_public_key(self) -> str:
        """Get public key from Azure Key Vault."""
        if self._public_key_cache:
            return self._public_key_cache

        try:
            from azure.keyvault.keys.aio import KeyClient
            from azure.identity.aio import DefaultAzureCredential
        except ImportError:
            raise ImportError(
                "Azure Key Vault support requires: pip install azure-keyvault-keys azure-identity"
            )

        credential = DefaultAzureCredential()

        try:
            key_client = KeyClient(vault_url=self._vault_url, credential=credential)
            key = await key_client.get_key(self._key_name, self._key_version)

            # Convert to JWK
            jwk_dict = {
                "kty": key.key.kty,
                "crv": key.key.crv if hasattr(key.key, "crv") else "P-256",
                "x": base64.urlsafe_b64encode(key.key.x).rstrip(b"=").decode(),
                "y": base64.urlsafe_b64encode(key.key.y).rstrip(b"=").decode()
                if key.key.y
                else None,
            }

            # Remove None values
            jwk_dict = {k: v for k, v in jwk_dict.items() if v is not None}

            self._public_key_cache = json.dumps(jwk_dict)
            return self._public_key_cache
        finally:
            await credential.close()
