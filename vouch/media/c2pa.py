# vouch/media/c2pa.py
"""
C2PA Integration for Vouch Protocol

This module provides Content Authenticity Initiative (C2PA) compliant
media signing and verification, enabling cryptographic proof of
image/video provenance using the industry standard.

Key Features:
- Signs images with embedded C2PA manifests
- Adds vouch.identity assertions to manifests
- Verifies C2PA manifests and extracts signer info
- Compatible with Adobe Photoshop, Lightroom, etc.
"""

import json
import hashlib
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

try:
    import c2pa

    C2PA_AVAILABLE = True
except (ImportError, SyntaxError):
    # SyntaxError: c2pa-python uses match statements (Python 3.10+)
    C2PA_AVAILABLE = False

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class VouchIdentity:
    """Represents a Vouch identity assertion in C2PA manifest."""

    did: str
    display_name: str
    email: Optional[str] = None
    credential_type: str = "FREE"  # FREE or PRO
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None

    def to_assertion(self) -> Dict[str, Any]:
        """Convert to C2PA assertion format."""
        return {
            "label": "vouch.identity",
            "data": {
                "did": self.did,
                "display_name": self.display_name,
                "email": self.email,
                "credential": {
                    "type": self.credential_type,
                    "issued_at": self.issued_at or datetime.now(timezone.utc).isoformat(),
                    "expires_at": self.expires_at,
                },
            },
        }


@dataclass
class SignedMediaResult:
    """Result of signing an image."""

    source_path: str
    output_path: str
    manifest_hash: str
    identity: VouchIdentity
    timestamp: str
    success: bool
    error: Optional[str] = None


@dataclass
class VerificationResult:
    """Result of verifying an image."""

    is_valid: bool
    signer_identity: Optional[VouchIdentity] = None
    claim_generator: Optional[str] = None
    signed_at: Optional[str] = None
    manifest_json: Optional[Dict] = None
    error: Optional[str] = None


# =============================================================================
# Signer Classes
# =============================================================================


class VouchC2PASigner:
    """
    Custom C2PA signer using Ed25519 for Vouch Protocol.

    This wraps the Vouch identity keypair to create C2PA-compliant signatures.
    """

    def __init__(self, private_key: Ed25519PrivateKey, certificate_pem: bytes):
        """
        Initialize with Ed25519 private key and certificate.

        Args:
            private_key: Ed25519 private key for signing
            certificate_pem: PEM-encoded certificate
        """
        if not C2PA_AVAILABLE:
            raise ImportError("c2pa-python is required. Install with: pip install c2pa-python")

        self._private_key = private_key
        self._certificate_pem = certificate_pem

        # Export private key as PEM
        self._private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def get_signer_info(self) -> "c2pa.C2paSignerInfo":
        """Get C2PA signer info for the builder."""
        return c2pa.C2paSignerInfo(
            alg=c2pa.C2paSigningAlg.ED25519,
            sign_cert=self._certificate_pem,
            private_key=self._private_key_pem,
            ta_url="",
        )


# =============================================================================
# Main Classes
# =============================================================================


class MediaSigner:
    """
    Signs images with C2PA manifests containing Vouch identity assertions.

    Usage:
        signer = MediaSigner(private_key, certificate_chain, identity)
        result = signer.sign_image("photo.jpg", "photo_signed.jpg")
    """

    CLAIM_GENERATOR = "Vouch Protocol/1.0.0"

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        certificate_chain: bytes,
        identity: VouchIdentity,
    ):
        """
        Initialize MediaSigner.

        Args:
            private_key: Ed25519 private key for signing
            certificate_chain: PEM-encoded X.509 certificate chain
            identity: Vouch identity to embed in manifests
        """
        if not C2PA_AVAILABLE:
            raise ImportError("c2pa-python is required. Install with: pip install c2pa-python")

        self._private_key = private_key
        self._certificate_chain = certificate_chain
        self._identity = identity

    def sign_image(
        self,
        source_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
        title: Optional[str] = None,
    ) -> SignedMediaResult:
        """
        Sign an image with a C2PA manifest.

        Args:
            source_path: Path to source image
            output_path: Path for signed output (default: source_signed.ext)
            title: Optional title for the manifest

        Returns:
            SignedMediaResult with signing status and details
        """
        source_path = Path(source_path)

        if not source_path.exists():
            return SignedMediaResult(
                source_path=str(source_path),
                output_path="",
                manifest_hash="",
                identity=self._identity,
                timestamp="",
                success=False,
                error=f"Source file not found: {source_path}",
            )

        # Generate output path if not provided
        if output_path is None:
            output_path = source_path.parent / f"{source_path.stem}_signed{source_path.suffix}"
        output_path = Path(output_path)

        try:
            # Build the C2PA manifest
            manifest_json = self._build_manifest(source_path, title)

            # Export private key as PEM
            private_key_pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Create signer info with PEM-encoded key and cert
            signer_info = c2pa.C2paSignerInfo(
                alg=c2pa.C2paSigningAlg.ED25519,
                sign_cert=self._certificate_chain,
                private_key=private_key_pem,
                ta_url="",
            )
            signer = c2pa.Signer.from_info(signer_info)

            # Create builder and add manifest
            builder = c2pa.Builder(json.dumps(manifest_json))

            # Sign the image
            manifest_bytes = builder.sign_file(
                source_path=str(source_path),
                dest_path=str(output_path),
                signer=signer,
            )

            # Calculate manifest hash
            manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()[:16]
            timestamp = datetime.now(timezone.utc).isoformat()

            return SignedMediaResult(
                source_path=str(source_path),
                output_path=str(output_path),
                manifest_hash=manifest_hash,
                identity=self._identity,
                timestamp=timestamp,
                success=True,
            )

        except Exception as e:
            return SignedMediaResult(
                source_path=str(source_path),
                output_path=str(output_path),
                manifest_hash="",
                identity=self._identity,
                timestamp="",
                success=False,
                error=str(e),
            )

    def _build_manifest(self, source_path: Path, title: Optional[str] = None) -> Dict[str, Any]:
        """Build the C2PA manifest JSON."""
        return {
            "claim_generator": self.CLAIM_GENERATOR,
            "claim_generator_info": [
                {
                    "name": "Vouch Protocol",
                    "version": "1.0.0",
                }
            ],
            "title": title or source_path.name,
            "format": self._get_mime_type(source_path),
            "assertions": [
                # Standard C2PA action assertion
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "when": datetime.now(timezone.utc).isoformat(),
                                "softwareAgent": self.CLAIM_GENERATOR,
                            }
                        ]
                    },
                },
                # Vouch identity assertion
                self._identity.to_assertion(),
            ],
        }

    def _get_mime_type(self, path: Path) -> str:
        """Get MIME type from file extension."""
        extension_map = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".webp": "image/webp",
            ".heic": "image/heic",
            ".heif": "image/heif",
            ".tiff": "image/tiff",
            ".tif": "image/tiff",
            ".avif": "image/avif",
        }
        return extension_map.get(path.suffix.lower(), "application/octet-stream")


class MediaVerifier:
    """
    Verifies C2PA manifests and extracts Vouch identity assertions.

    Usage:
        verifier = MediaVerifier()
        result = verifier.verify_image("photo_signed.jpg")
        if result.is_valid:
            print(f"Signed by: {result.signer_identity.display_name}")
    """

    def __init__(self):
        """Initialize MediaVerifier."""
        if not C2PA_AVAILABLE:
            raise ImportError("c2pa-python is required. Install with: pip install c2pa-python")

    def verify_image(self, image_path: Union[str, Path]) -> VerificationResult:
        """
        Verify an image's C2PA manifest.

        Args:
            image_path: Path to image to verify

        Returns:
            VerificationResult with validation status and signer info
        """
        image_path = Path(image_path)

        if not image_path.exists():
            return VerificationResult(is_valid=False, error=f"File not found: {image_path}")

        try:
            # Read C2PA manifest
            with open(image_path, "rb") as f:
                reader = c2pa.Reader(self._get_mime_type(image_path), f)
                manifest_json = json.loads(reader.json())

            # Extract Vouch identity if present
            vouch_identity = self._extract_vouch_identity(manifest_json)

            # Get claim generator info
            active_manifest = manifest_json.get("active_manifest")
            if active_manifest:
                manifest_data = manifest_json.get("manifests", {}).get(active_manifest, {})
                claim_generator = manifest_data.get("claim_generator", "Unknown")
                signed_at = manifest_data.get("signature_info", {}).get("time")
            else:
                claim_generator = None
                signed_at = None

            return VerificationResult(
                is_valid=True,
                signer_identity=vouch_identity,
                claim_generator=claim_generator,
                signed_at=signed_at,
                manifest_json=manifest_json,
            )

        except Exception as e:
            return VerificationResult(
                is_valid=False,
                error=str(e),
            )

    def _extract_vouch_identity(self, manifest_json: Dict) -> Optional[VouchIdentity]:
        """Extract Vouch identity assertion from manifest."""
        active_manifest = manifest_json.get("active_manifest")
        if not active_manifest:
            return None

        manifest_data = manifest_json.get("manifests", {}).get(active_manifest, {})
        assertions = manifest_data.get("assertions", [])

        for assertion in assertions:
            if assertion.get("label") == "vouch.identity":
                data = assertion.get("data", {})
                credential = data.get("credential", {})

                return VouchIdentity(
                    did=data.get("did", ""),
                    display_name=data.get("display_name", ""),
                    email=data.get("email"),
                    credential_type=credential.get("type", "FREE"),
                    issued_at=credential.get("issued_at"),
                    expires_at=credential.get("expires_at"),
                )

        return None

    def _get_mime_type(self, path: Path) -> str:
        """Get MIME type from file extension."""
        extension_map = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".webp": "image/webp",
            ".heic": "image/heic",
            ".heif": "image/heif",
            ".tiff": "image/tiff",
            ".tif": "image/tiff",
            ".avif": "image/avif",
        }
        return extension_map.get(path.suffix.lower(), "application/octet-stream")


# =============================================================================
# Convenience Functions
# =============================================================================


def sign_image(
    source_path: Union[str, Path],
    private_key: Ed25519PrivateKey,
    certificate_chain: bytes,
    identity: VouchIdentity,
    output_path: Optional[Union[str, Path]] = None,
) -> SignedMediaResult:
    """
    Sign an image with Vouch identity.

    Args:
        source_path: Path to source image
        private_key: Ed25519 private key
        certificate_chain: PEM certificate chain
        identity: Vouch identity to embed
        output_path: Optional output path

    Returns:
        SignedMediaResult
    """
    signer = MediaSigner(private_key, certificate_chain, identity)
    return signer.sign_image(source_path, output_path)


def verify_image(image_path: Union[str, Path]) -> VerificationResult:
    """
    Verify an image's C2PA manifest.

    Args:
        image_path: Path to image

    Returns:
        VerificationResult
    """
    verifier = MediaVerifier()
    return verifier.verify_image(image_path)


# =============================================================================
# Certificate Generation Helpers
# =============================================================================


def generate_self_signed_certificate(
    private_key: Ed25519PrivateKey,
    common_name: str,
    organization: str = "Vouch Protocol",
) -> bytes:
    """
    Generate a self-signed X.509 certificate for C2PA signing.

    Note: For production, use certificates from a trusted CA.

    Args:
        private_key: Ed25519 private key
        common_name: Certificate common name (e.g., email or DID)
        organization: Organization name

    Returns:
        PEM-encoded certificate chain (bytes)
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from datetime import timedelta

    # Build certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    public_key = private_key.public_key()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                content_commitment=True,  # nonRepudiation
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CODE_SIGNING,
                    ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ]
            ),
            critical=False,
        )
        .sign(private_key, algorithm=None)  # Ed25519 doesn't need algorithm
    )

    return cert.public_bytes(serialization.Encoding.PEM)
