"""
Vouch Protocol Enterprise Key Management System.

Provides key rotation, multi-key support, and integration with the Signer class
for enterprise deployment scenarios.
"""

import time
import logging
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass

from jwcrypto import jwk

from vouch.signer import Signer


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
    
    Example:
        >>> keys = [
        ...     KeyConfig(private_key_jwk='...', did='did:web:agent.com', key_id='key1'),
        ...     KeyConfig(private_key_jwk='...', did='did:web:agent.com', key_id='key2'),
        ... ]
        >>> provider = RotatingKeyProvider(keys, rotation_interval_hours=24)
        >>> signer = provider.get_signer()
        >>> token = signer.sign({'action': 'test'})
    """
    
    def __init__(
        self,
        keys: List[KeyConfig],
        rotation_interval_hours: int = 24,
        on_rotation: Optional[Callable[[str], None]] = None
    ):
        """
        Initialize the key provider.
        
        Args:
            keys: List of KeyConfig objects with signing keys.
            rotation_interval_hours: Hours between automatic key rotations.
            on_rotation: Optional callback when key rotation occurs.
            
        Raises:
            ValueError: If no keys are provided or keys are invalid.
        """
        if not keys:
            raise ValueError("At least one key configuration is required")
        
        self._keys = keys
        self._interval = rotation_interval_hours * 3600
        self._on_rotation = on_rotation
        self._last_key_id: Optional[str] = None
        
        # Validate all keys on init
        for i, key_config in enumerate(keys):
            try:
                key = jwk.JWK.from_json(key_config.private_key_jwk)
                if key.key_type != 'OKP':
                    raise ValueError(f"Key {i} must be Ed25519 (OKP)")
            except Exception as e:
                raise ValueError(f"Invalid key at index {i}: {e}")
    
    def get_active_key(self) -> KeyConfig:
        """
        Get the currently active key based on rotation schedule.
        
        Keys rotate based on the rotation interval. If keys have validity
        periods defined, those take precedence.
        
        Returns:
            The currently active KeyConfig.
        """
        now = int(time.time())
        
        # First, check for keys with explicit validity periods
        for key in self._keys:
            if key.valid_from and key.valid_until:
                if key.valid_from <= now <= key.valid_until:
                    return key
        
        # Fall back to time-based rotation
        index = (now // self._interval) % len(self._keys)
        active_key = self._keys[index]
        
        # Trigger rotation callback if key changed
        current_id = active_key.key_id or str(index)
        if self._last_key_id and self._last_key_id != current_id:
            if self._on_rotation:
                try:
                    self._on_rotation(current_id)
                except Exception as e:
                    logger.error(f"Rotation callback failed: {e}")
        self._last_key_id = current_id
        
        return active_key
    
    def get_signer(self) -> Signer:
        """
        Get a Signer instance configured with the active key.
        
        Returns:
            A Signer instance ready to sign tokens.
        """
        active_key = self.get_active_key()
        return Signer(
            private_key=active_key.private_key_jwk,
            did=active_key.did
        )
    
    def add_key(self, key_config: KeyConfig) -> None:
        """Add a new key to the rotation pool."""
        # Validate the key
        try:
            key = jwk.JWK.from_json(key_config.private_key_jwk)
            if key.key_type != 'OKP':
                raise ValueError("Key must be Ed25519 (OKP)")
        except Exception as e:
            raise ValueError(f"Invalid key: {e}")
        
        self._keys.append(key_config)
        logger.info(f"Added key {key_config.key_id} to rotation pool")
    
    def remove_key(self, key_id: str) -> bool:
        """
        Remove a key from the rotation pool by its ID.
        
        Returns:
            True if key was found and removed, False otherwise.
        """
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
        """Number of keys in the rotation pool."""
        return len(self._keys)
    
    @property
    def active_key_id(self) -> Optional[str]:
        """ID of the currently active key."""
        return self.get_active_key().key_id
