# vouch/bridge/server.py
"""
Vouch Bridge Server — FastAPI service wrapping C2PA signing + QR badge.

Endpoints:
    POST /sign    — Sign an image (C2PA manifest + QR badge)
    POST /verify  — Verify a signed image's C2PA manifest
    GET  /health  — Health check

Auth:
    All endpoints except /health require:
        Authorization: Bearer <VOUCH_BRIDGE_SECRET>
"""

import base64
import hashlib
import json as _json
import tempfile
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from vouch.bridge.config import BridgeSettings, load_settings

# =============================================================================
# Pydantic Models
# =============================================================================


class SignRequest(BaseModel):
    """Request body for POST /sign."""

    image_base64: str = Field(..., description="Base64-encoded source image")
    did: str = Field(..., description="DID of the signer")
    display_name: str = Field(..., description="Human-readable signer name")
    email: Optional[str] = Field(None, description="Signer email (optional)")
    credential_type: str = Field("FREE", description="FREE or PRO")
    title: Optional[str] = Field(None, description="Image title for C2PA manifest")
    badge_position: Optional[str] = Field("bottom-right", description="QR badge position")
    shortlink_domain: Optional[str] = Field(
        None, description="Override shortlink domain (e.g. https://cygn.me)"
    )


class SignResponse(BaseModel):
    """Response body for POST /sign."""

    success: bool
    signed_image_base64: Optional[str] = None
    manifest_hash: Optional[str] = None
    verify_url: Optional[str] = None
    timestamp: Optional[str] = None
    error: Optional[str] = None


class VerifyRequest(BaseModel):
    """Request body for POST /verify."""

    image_base64: str = Field(..., description="Base64-encoded image to verify")


class VerifyResponse(BaseModel):
    """Response body for POST /verify."""

    is_valid: bool
    signer_identity: Optional[dict] = None
    signed_at: Optional[str] = None
    claim_generator: Optional[str] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Response body for GET /health."""

    status: str
    version: str
    c2pa_available: bool


# =============================================================================
# App Setup
# =============================================================================


app = FastAPI(
    title="Vouch Bridge",
    description="C2PA image signing and QR badge overlay service",
    version="1.0.0",
)

_settings: Optional[BridgeSettings] = None


def get_settings() -> BridgeSettings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def _check_auth(authorization: Optional[str]) -> None:
    """Validate bearer token against bridge secret."""
    settings = get_settings()
    if not settings.auth_enabled:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization[len("Bearer "):]
    if token != settings.bridge_secret:
        raise HTTPException(status_code=403, detail="Invalid bridge secret")


def _generate_cert_chain(common_name: str) -> tuple["Ed25519PrivateKey", bytes]:
    """
    Generate a 3-level certificate chain for C2PA signing.

    C2PA requires: Root CA → Intermediate CA → End-entity.
    The sign_cert chain must contain end-entity + intermediate (NO root).

    Returns (end_entity_private_key, pem_chain).
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from datetime import timedelta

    now = datetime.now(timezone.utc)

    # --- Root CA (self-signed) ---
    root_key = Ed25519PrivateKey.generate()
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vouch Protocol"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Vouch Root CA"),
    ])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, algorithm=None)
    )

    # --- Intermediate CA (signed by root) ---
    inter_key = Ed25519PrivateKey.generate()
    inter_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vouch Protocol"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Vouch Intermediate CA"),
    ])
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(inter_name)
        .issuer_name(root_name)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3000))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, algorithm=None)
    )

    # --- End-entity signing cert (signed by intermediate) ---
    ee_key = Ed25519PrivateKey.generate()
    ee_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vouch Protocol"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    ee_cert = (
        x509.CertificateBuilder()
        .subject_name(ee_name)
        .issuer_name(inter_name)
        .public_key(ee_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
                x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36"),  # documentSigning
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key()),
            critical=False,
        )
        .sign(inter_key, algorithm=None)
    )

    # Chain: end-entity + intermediate (NO root — per C2PA spec)
    chain_pem = (
        ee_cert.public_bytes(serialization.Encoding.PEM)
        + inter_cert.public_bytes(serialization.Encoding.PEM)
    )

    return ee_key, chain_pem


def _detect_mime_type(ext: str) -> str:
    """Map file extension to MIME type."""
    return {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".png": "image/png", ".gif": "image/gif",
        ".webp": "image/webp", ".tiff": "image/tiff",
        ".tif": "image/tiff", ".avif": "image/avif",
    }.get(ext, "application/octet-stream")


def _detect_extension(image_bytes: bytes) -> str:
    """Detect image format from magic bytes and return file extension."""
    if image_bytes[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if image_bytes[:2] == b"\xff\xd8":
        return ".jpg"
    if image_bytes[:4] == b"RIFF" and image_bytes[8:12] == b"WEBP":
        return ".webp"
    if image_bytes[:3] == b"GIF":
        return ".gif"
    if image_bytes[:4] in (b"II\x2a\x00", b"MM\x00\x2a"):
        return ".tiff"
    # Default to JPEG
    return ".jpg"


# =============================================================================
# Endpoints
# =============================================================================


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Health check — no auth required."""
    try:
        from vouch.media.c2pa import C2PA_AVAILABLE
    except (ImportError, SyntaxError):
        C2PA_AVAILABLE = False

    return HealthResponse(
        status="ok",
        version="1.0.0",
        c2pa_available=C2PA_AVAILABLE,
    )


@app.post("/sign", response_model=SignResponse)
async def sign_image(
    req: SignRequest,
    authorization: Optional[str] = Header(None),
) -> SignResponse:
    """Sign an image with C2PA manifest and QR badge."""
    _check_auth(authorization)

    try:
        from vouch.media.c2pa import VouchIdentity, C2PA_AVAILABLE
        from vouch.media.badge import BadgeFactory, BadgeOptions
        import c2pa
    except (ImportError, SyntaxError) as e:
        return SignResponse(success=False, error=f"Media modules unavailable: {e}")

    if not C2PA_AVAILABLE:
        return SignResponse(success=False, error="c2pa-python not installed or Python < 3.10")

    # Decode image
    try:
        image_bytes = base64.b64decode(req.image_base64)
    except Exception:
        return SignResponse(success=False, error="Invalid base64 image data")

    if len(image_bytes) < 100:
        return SignResponse(success=False, error="Image data too small")

    # Detect format
    ext = _detect_extension(image_bytes)

    # Use temp files for processing
    tmp_dir = tempfile.mkdtemp(prefix="vouch_bridge_")
    source_path = Path(tmp_dir) / f"source{ext}"
    signed_path = Path(tmp_dir) / f"signed{ext}"
    badged_path = Path(tmp_dir) / f"badged{ext}"

    try:
        # Write source image
        source_path.write_bytes(image_bytes)

        # Generate ephemeral 3-level cert chain for C2PA (Root → Intermediate → End-entity)
        private_key, cert_pem = _generate_cert_chain(common_name=req.did)

        # Build Vouch identity assertion
        identity = VouchIdentity(
            did=req.did,
            display_name=req.display_name,
            email=req.email,
            credential_type=req.credential_type,
        )

        # Build C2PA manifest
        manifest_def = {
            "claim_generator": "Vouch Protocol/1.0.0",
            "claim_generator_info": [{"name": "Vouch Protocol", "version": "1.0.0"}],
            "title": req.title or source_path.name,
            "format": _detect_mime_type(ext),
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "when": datetime.now(timezone.utc).isoformat(),
                                "softwareAgent": "Vouch Protocol/1.0.0",
                            }
                        ]
                    },
                },
                identity.to_assertion(),
            ],
        }

        # Use from_callback to avoid ta_url="" HTTP fetch issue
        def _sign_cb(data: bytes) -> bytes:
            return private_key.sign(data)

        c2pa_signer = c2pa.Signer.from_callback(
            callback=_sign_cb,
            alg=c2pa.C2paSigningAlg.ED25519,
            certs=cert_pem,
            tsa_url=None,
        )

        builder = c2pa.Builder(_json.dumps(manifest_def))
        manifest_bytes = builder.sign_file(
            source_path=str(source_path),
            dest_path=str(signed_path),
            signer=c2pa_signer,
        )

        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()[:16]

        # QR badge overlay
        shortlink_domain = req.shortlink_domain or get_settings().shortlink_domain
        badge_options = BadgeOptions(
            position=req.badge_position or "bottom-right",
            base_url=shortlink_domain,
        )
        badge_factory = BadgeFactory(options=badge_options)
        badge_result = badge_factory.add_badge(
            source_path=str(signed_path),
            signature_hash=manifest_hash,
            output_path=str(badged_path),
        )

        if badge_result.success and badge_result.output_path:
            final_path = Path(badge_result.output_path)
            verify_url = badge_result.verify_url
        else:
            # Badge failed (e.g. Pillow not installed) — return C2PA-only
            final_path = signed_path
            verify_url = None

        # Read final image
        signed_image_base64 = base64.b64encode(final_path.read_bytes()).decode("ascii")
        timestamp = datetime.now(timezone.utc).isoformat()

        return SignResponse(
            success=True,
            signed_image_base64=signed_image_base64,
            manifest_hash=manifest_hash,
            verify_url=verify_url,
            timestamp=timestamp,
        )

    except Exception as e:
        return SignResponse(success=False, error=str(e))

    finally:
        # Cleanup temp files
        for f in (source_path, signed_path, badged_path):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
        try:
            Path(tmp_dir).rmdir()
        except Exception:
            pass


@app.post("/verify", response_model=VerifyResponse)
async def verify_image(
    req: VerifyRequest,
    authorization: Optional[str] = Header(None),
) -> VerifyResponse:
    """Verify a signed image's C2PA manifest."""
    _check_auth(authorization)

    try:
        from vouch.media.c2pa import MediaVerifier, C2PA_AVAILABLE
    except (ImportError, SyntaxError) as e:
        return VerifyResponse(is_valid=False, error=f"Media modules unavailable: {e}")

    if not C2PA_AVAILABLE:
        return VerifyResponse(is_valid=False, error="c2pa-python not installed or Python < 3.10")

    # Decode image
    try:
        image_bytes = base64.b64decode(req.image_base64)
    except Exception:
        return VerifyResponse(is_valid=False, error="Invalid base64 image data")

    ext = _detect_extension(image_bytes)

    tmp_dir = tempfile.mkdtemp(prefix="vouch_bridge_")
    image_path = Path(tmp_dir) / f"verify{ext}"

    try:
        image_path.write_bytes(image_bytes)

        verifier = MediaVerifier()
        result = verifier.verify_image(image_path)

        signer_identity = None
        if result.signer_identity:
            signer_identity = {
                "did": result.signer_identity.did,
                "display_name": result.signer_identity.display_name,
                "email": result.signer_identity.email,
                "credential_type": result.signer_identity.credential_type,
            }

        return VerifyResponse(
            is_valid=result.is_valid,
            signer_identity=signer_identity,
            signed_at=result.signed_at,
            claim_generator=result.claim_generator,
            error=result.error,
        )

    except Exception as e:
        return VerifyResponse(is_valid=False, error=str(e))

    finally:
        try:
            image_path.unlink(missing_ok=True)
        except Exception:
            pass
        try:
            Path(tmp_dir).rmdir()
        except Exception:
            pass


# =============================================================================
# Entry Point
# =============================================================================


def main() -> None:
    """CLI entry point for vouch-bridge command."""
    import uvicorn

    settings = load_settings()
    print(f"Starting Vouch Bridge on {settings.bridge_host}:{settings.bridge_port}")
    uvicorn.run(
        "vouch.bridge.server:app",
        host=settings.bridge_host,
        port=settings.bridge_port,
    )


if __name__ == "__main__":
    main()
