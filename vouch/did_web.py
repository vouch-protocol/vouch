"""
did:web DID Resolution

Resolves did:web identifiers to DID Documents without requiring a central registry.
The domain itself is the root of trust.

Usage:
    did = "did:web:optum.com"
    doc = await resolve_did_web(did)
    public_key = extract_public_key(doc)
"""

from __future__ import annotations

import urllib.parse
from typing import Optional, List
from dataclasses import dataclass

import httpx


@dataclass
class VerificationMethod:
    """A verification method from a DID Document."""

    id: str
    type: str
    controller: str
    public_key_jwk: Optional[dict] = None
    public_key_multibase: Optional[str] = None


@dataclass
class DIDDocument:
    """Parsed DID Document."""

    id: str
    verification_methods: List[VerificationMethod]
    authentication: List[str]
    assertion_method: List[str]

    @classmethod
    def from_json(cls, data: dict) -> "DIDDocument":
        """Parse a DID Document from JSON."""
        methods = []
        for vm in data.get("verificationMethod", []):
            methods.append(
                VerificationMethod(
                    id=vm.get("id", ""),
                    type=vm.get("type", ""),
                    controller=vm.get("controller", ""),
                    public_key_jwk=vm.get("publicKeyJwk"),
                    public_key_multibase=vm.get("publicKeyMultibase"),
                )
            )

        return cls(
            id=data.get("id", ""),
            verification_methods=methods,
            authentication=data.get("authentication", []),
            assertion_method=data.get("assertionMethod", []),
        )

    def get_public_key_jwk(self, key_id: Optional[str] = None) -> Optional[dict]:
        """
        Get a public key JWK from the document.

        Args:
            key_id: Optional specific key ID to find. If None, returns first available.

        Returns:
            JWK dict or None if not found.
        """
        for vm in self.verification_methods:
            if key_id and vm.id != key_id:
                continue
            if vm.public_key_jwk:
                return vm.public_key_jwk
        return None


def did_web_to_url(did: str) -> str:
    """
    Convert a did:web identifier to a URL.

    Examples:
        did:web:example.com → https://example.com/.well-known/did.json
        did:web:example.com:user:alice → https://example.com/user/alice/did.json
        did:web:example.com%3A8080 → https://example.com:8080/.well-known/did.json

    Args:
        did: A did:web identifier

    Returns:
        URL string to fetch the DID Document

    Raises:
        ValueError: If the DID is not a valid did:web identifier
    """
    if not did.startswith("did:web:"):
        raise ValueError(f"Not a did:web identifier: {did}")

    # Remove the did:web: prefix
    domain_and_path = did[8:]

    # Split by colons (path segments)
    parts = domain_and_path.split(":")

    # First part is the domain (URL-decoded)
    domain = urllib.parse.unquote(parts[0])

    # Remaining parts are path segments
    path_segments = parts[1:] if len(parts) > 1 else []

    # Build the URL
    if path_segments:
        path = "/" + "/".join(path_segments) + "/did.json"
    else:
        path = "/.well-known/did.json"

    return f"https://{domain}{path}"


async def resolve_did_web(
    did: str,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> DIDDocument:
    """
    Resolve a did:web identifier to a DID Document.

    This fetches the DID Document from the domain specified in the DID.
    The domain is the root of trust - no central registry required.

    Args:
        did: A did:web identifier (e.g., "did:web:optum.com")
        timeout: HTTP request timeout in seconds
        verify_ssl: Whether to verify SSL certificates

    Returns:
        Parsed DIDDocument

    Raises:
        ValueError: If the DID is invalid
        httpx.HTTPError: If the request fails
    """
    url = did_web_to_url(did)

    async with httpx.AsyncClient(timeout=timeout, verify=verify_ssl) as client:
        response = await client.get(
            url,
            headers={
                "Accept": "application/did+json, application/json",
            },
        )
        response.raise_for_status()
        data = response.json()

    return DIDDocument.from_json(data)


def resolve_did_web_sync(
    did: str,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> DIDDocument:
    """
    Synchronous version of resolve_did_web.

    For use in non-async contexts.
    """
    url = did_web_to_url(did)

    with httpx.Client(timeout=timeout, verify=verify_ssl) as client:
        response = client.get(
            url,
            headers={
                "Accept": "application/did+json, application/json",
            },
        )
        response.raise_for_status()
        data = response.json()

    return DIDDocument.from_json(data)


# =============================================================================
# Utility Functions
# =============================================================================


def extract_domain_from_did_web(did: str) -> str:
    """
    Extract the domain from a did:web identifier.

    Args:
        did: A did:web identifier

    Returns:
        The domain portion of the DID
    """
    if not did.startswith("did:web:"):
        raise ValueError(f"Not a did:web identifier: {did}")

    parts = did[8:].split(":")
    return urllib.parse.unquote(parts[0])


def is_did_web(did: str) -> bool:
    """Check if a string is a did:web identifier."""
    return did.startswith("did:web:")


def create_did_web(domain: str, path: Optional[List[str]] = None) -> str:
    """
    Create a did:web identifier from a domain and optional path.

    Args:
        domain: The domain (e.g., "optum.com" or "example.com:8080")
        path: Optional path segments (e.g., ["user", "alice"])

    Returns:
        A did:web identifier string
    """
    # URL-encode the domain (for ports)
    encoded_domain = urllib.parse.quote(domain, safe="")

    if path:
        return "did:web:" + encoded_domain + ":" + ":".join(path)
    return "did:web:" + encoded_domain
