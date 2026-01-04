"""
Vouch Protocol Key Generation Utilities.

Provides functions for generating Ed25519 key pairs for agent identity.
"""

from dataclasses import dataclass
from typing import Optional

from jwcrypto import jwk


@dataclass
class KeyPair:
    """
    Represents an Ed25519 key pair for Vouch identity.

    Attributes:
        private_key_jwk: The private key in JWK format (JSON string)
        public_key_jwk: The public key in JWK format (JSON string)
        did: The generated DID (if domain was provided)
    """

    private_key_jwk: str
    public_key_jwk: str
    did: Optional[str] = None


def generate_identity(domain: Optional[str] = None) -> KeyPair:
    """
    Generate a new Ed25519 keypair for agent identity.

    Args:
        domain: Optional domain for did:web generation (e.g., 'example.com')

    Returns:
        KeyPair containing private key, public key, and optional DID.

    Example:
        >>> keys = generate_identity(domain='myagent.com')
        >>> print(keys.did)
        'did:web:myagent.com'
        >>> # Use keys.private_key_jwk with Signer
        >>> # Publish keys.public_key_jwk in vouch.json
    """
    # Generate Ed25519 key
    key = jwk.JWK.generate(kty="OKP", crv="Ed25519")

    # Export keys
    private_key = key.export_private()
    public_key = key.export_public()

    # Build DID if domain provided
    did = f"did:web:{domain}" if domain else None

    return KeyPair(private_key_jwk=private_key, public_key_jwk=public_key, did=did)


def generate_identity_keys(domain: Optional[str] = None) -> KeyPair:
    """
    Alias for generate_identity for backward compatibility.

    Deprecated: Use generate_identity() instead.
    """
    return generate_identity(domain)


# Run as script for quick key generation
if __name__ == "__main__":
    import sys

    domain = sys.argv[1] if len(sys.argv) > 1 else None
    keys = generate_identity(domain)

    print("🔑 NEW AGENT IDENTITY GENERATED\n")
    if keys.did:
        print(f"DID: {keys.did}")
    print("\n--- PRIVATE KEY (Keep Secret / Set as Env Var) ---")
    print(keys.private_key_jwk)
    print("\n--- PUBLIC KEY (Put this in vouch.json) ---")
    print(keys.public_key_jwk)
