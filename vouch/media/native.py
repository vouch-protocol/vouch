# vouch/media/native.py
"""
Native Vouch Media Signing (Certificate-Free)

This module provides Ed25519-based image signing without requiring CA certificates.
Uses EXIF/XMP metadata or sidecar files to embed signatures.

Key Benefits:
- No certificates required (just a keypair)
- Fully decentralized (DID-based identity)
- Simple user experience
- Compatible with existing Vouch identity system

Claim Types:
- CAPTURED: Photo taken by this device (requires EXIF proof)
- SIGNED: Person vouches for this image (weaker claim)
- SHARED: Resharing someone else's image (links to chain)
"""

import json
import hashlib
import base64
import uuid
from pathlib import Path
from typing import Optional, Dict, Any, Union, Tuple, List
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# Try to import PIL for image manipulation
try:
    from PIL import Image
    from PIL.ExifTags import TAGS

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# =============================================================================
# Constants
# =============================================================================

VOUCH_SIGNATURE_VERSION = "2.0"
VOUCH_XMP_NAMESPACE = "http://vouch-protocol.com/xmp/1.0/"
VOUCH_COMMENT_PREFIX = "VOUCH-SIG:"


# =============================================================================
# Claim Types
# =============================================================================


class ClaimType(str, Enum):
    """Type of claim the signer is making about the image."""

    CAPTURED = "captured"  # I took this photo (device attestation)
    SIGNED = "signed"  # I vouch for this image (manual approval)
    SHARED = "shared"  # I'm resharing this (links to chain)


# =============================================================================
# EXIF Analysis
# =============================================================================


@dataclass
class EXIFAnalysis:
    """Analysis of image EXIF data to detect original vs downloaded."""

    has_camera_info: bool = False
    has_gps: bool = False
    has_lens_info: bool = False
    has_timestamp: bool = False
    is_timestamp_recent: bool = False
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    capture_time: Optional[str] = None

    @property
    def confidence_score(self) -> float:
        """Score from 0-1 indicating likelihood this is an original capture."""
        score = 0.0
        if self.has_camera_info:
            score += 0.35
        if self.has_gps:
            score += 0.15
        if self.has_lens_info:
            score += 0.15
        if self.has_timestamp:
            score += 0.15
        if self.is_timestamp_recent:
            score += 0.20
        return min(score, 1.0)

    @property
    def is_likely_original(self) -> bool:
        """Returns True if this appears to be an original capture."""
        return self.confidence_score >= 0.5

    @property
    def suggested_claim_type(self) -> ClaimType:
        """Suggest appropriate claim type based on EXIF analysis."""
        if self.confidence_score >= 0.7:
            return ClaimType.CAPTURED
        else:
            return ClaimType.SIGNED


def analyze_exif(image_path: Path) -> EXIFAnalysis:
    """Analyze image EXIF data to determine if it's an original capture."""
    analysis = EXIFAnalysis()

    if not PIL_AVAILABLE:
        return analysis

    try:
        with Image.open(image_path) as img:
            exif = img._getexif()
            if not exif:
                return analysis

            # Build tag name lookup
            exif_dict = {}
            for tag_id, value in exif.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                exif_dict[tag_name] = value

            # Check camera info
            if exif_dict.get("Make") and exif_dict.get("Model"):
                analysis.has_camera_info = True
                analysis.camera_make = str(exif_dict.get("Make", "")).strip()
                analysis.camera_model = str(exif_dict.get("Model", "")).strip()

            # Check GPS
            if "GPSInfo" in exif_dict:
                analysis.has_gps = True

            # Check lens info
            if exif_dict.get("LensModel") or exif_dict.get("LensMake"):
                analysis.has_lens_info = True

            # Check timestamp
            capture_time = exif_dict.get("DateTimeOriginal") or exif_dict.get("DateTime")
            if capture_time:
                analysis.has_timestamp = True
                analysis.capture_time = str(capture_time)

                # Check if recent (within 24 hours)
                try:
                    # EXIF datetime format: "2024:01:07 12:30:45"
                    dt = datetime.strptime(str(capture_time), "%Y:%m:%d %H:%M:%S")
                    dt = dt.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) - dt < timedelta(hours=24):
                        analysis.is_timestamp_recent = True
                except (ValueError, TypeError):
                    pass

    except Exception:
        pass

    return analysis


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class VouchMediaSignature:
    """Represents a native Vouch signature for media."""

    version: str
    did: str
    display_name: str
    email: Optional[str]
    public_key: str  # Base64-encoded public key
    timestamp: str
    image_hash: str  # SHA-256 of file bytes
    signature: str  # Base64-encoded Ed25519 signature
    credential_type: str = "FREE"
    claim_type: str = "signed"  # captured/signed/shared
    chain_id: Optional[str] = None  # Unique chain identifier
    chain_depth: int = 0  # 0 = original, 1+ = reshares
    parent_hash: Optional[str] = None  # For shared: parent signature hash
    credentials: Optional[List[Dict[str, Any]]] = None  # Employment credentials from org

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_json(cls, json_str: str) -> "VouchMediaSignature":
        """Create from JSON string."""
        data = json.loads(json_str)
        # Handle old signatures without new fields
        data.setdefault("claim_type", "signed")
        data.setdefault("chain_id", None)
        data.setdefault("chain_depth", 0)
        data.setdefault("parent_hash", None)
        data.setdefault("credentials", None)
        return cls(**data)

    def to_comment(self) -> str:
        """Format as image comment (for embedding in JPEG COM marker)."""
        return f"{VOUCH_COMMENT_PREFIX}{self.to_json()}"

    @classmethod
    def from_comment(cls, comment: str) -> Optional["VouchMediaSignature"]:
        """Parse from image comment."""
        if comment.startswith(VOUCH_COMMENT_PREFIX):
            json_str = comment[len(VOUCH_COMMENT_PREFIX) :]
            return cls.from_json(json_str)
        return None

    @property
    def chain_strength(self) -> float:
        """Calculate trust strength based on chain depth."""
        return 1.0 / (1 + 0.2 * self.chain_depth)


@dataclass
class NativeSignResult:
    """Result of native signing operation."""

    success: bool
    source_path: str
    output_path: str
    signature: Optional[VouchMediaSignature] = None
    sidecar_path: Optional[str] = None
    exif_analysis: Optional[EXIFAnalysis] = None
    warning: Optional[str] = None
    error: Optional[str] = None


@dataclass
class NativeVerifyResult:
    """Result of native verification operation."""

    is_valid: bool
    signature: Optional[VouchMediaSignature] = None
    source: Optional[str] = None  # "embedded" or "sidecar"
    error: Optional[str] = None


# =============================================================================
# Core Functions
# =============================================================================


def compute_image_hash(image_path: Path) -> str:
    """
    Compute SHA-256 hash of image pixel data.

    This hashes the actual pixel content, not the file bytes,
    so the hash survives metadata changes.
    """
    if not PIL_AVAILABLE:
        # Fallback: hash file bytes
        return hashlib.sha256(image_path.read_bytes()).hexdigest()

    with Image.open(image_path) as img:
        # Convert to RGB to normalize
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")

        # Hash pixel data
        pixel_data = img.tobytes()
        return hashlib.sha256(pixel_data).hexdigest()


def create_signature_payload(
    image_hash: str,
    did: str,
    display_name: str,
    email: Optional[str],
    timestamp: str,
    credential_type: str,
) -> bytes:
    """Create the canonical payload to sign."""
    payload = {
        "version": VOUCH_SIGNATURE_VERSION,
        "image_hash": image_hash,
        "did": did,
        "display_name": display_name,
        "email": email,
        "timestamp": timestamp,
        "credential_type": credential_type,
    }
    # Use sorted keys for canonical JSON
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_image_native(
    source_path: Union[str, Path],
    private_key: Ed25519PrivateKey,
    did: str,
    display_name: str,
    email: Optional[str] = None,
    credential_type: str = "FREE",
    output_path: Optional[Union[str, Path]] = None,
    embed_in_image: bool = False,
    create_sidecar: bool = True,
    claim_type: Optional[ClaimType] = None,
    parent_signature: Optional[VouchMediaSignature] = None,
    credentials: Optional[List[Dict[str, Any]]] = None,  # Org credentials
) -> NativeSignResult:
    """
    Sign an image with Ed25519 (no certificates needed).

    Args:
        source_path: Path to source image
        private_key: Ed25519 private key
        did: Signer's DID (e.g., "did:key:z6Mk...")
        display_name: Human-readable name
        email: Optional email address
        credential_type: "FREE" or "PRO"
        output_path: Output path (default: source_signed.ext)
        embed_in_image: Whether to embed signature in image (PNG only)
        create_sidecar: Whether to create .vouch sidecar file (recommended)
        claim_type: Type of claim (captured/signed/shared) - auto-detected if None
        parent_signature: For SHARED claims, the parent signature
        credentials: List of org credentials (EmploymentCredential dicts)

    Returns:
        NativeSignResult with signature details
    """
    source_path = Path(source_path)
    warning = None

    if not source_path.exists():
        return NativeSignResult(
            success=False,
            source_path=str(source_path),
            output_path="",
            error=f"File not found: {source_path}",
        )

    # Analyze EXIF data
    exif_analysis = analyze_exif(source_path)

    # Determine claim type
    if claim_type is None:
        claim_type = exif_analysis.suggested_claim_type

    # Validate claim type against EXIF
    if claim_type == ClaimType.CAPTURED and not exif_analysis.is_likely_original:
        warning = (
            f"⚠️  This image appears to be downloaded (EXIF score: {exif_analysis.confidence_score:.0%}). "
            f"Using 'signed' claim instead of 'captured'."
        )
        claim_type = ClaimType.SIGNED

    # Handle chain for SHARED claims
    chain_id = None
    chain_depth = 0
    parent_hash = None

    if claim_type == ClaimType.SHARED:
        if parent_signature:
            # Continue existing chain
            chain_id = parent_signature.chain_id or f"vouch:chain:{uuid.uuid4().hex[:12]}"
            chain_depth = parent_signature.chain_depth + 1
            parent_hash = hashlib.sha256(parent_signature.signature.encode()).hexdigest()[:16]
        else:
            return NativeSignResult(
                success=False,
                source_path=str(source_path),
                output_path="",
                error="SHARED claim requires parent_signature",
            )
    else:
        # New chain for captured/signed
        chain_id = f"vouch:chain:{uuid.uuid4().hex[:12]}"
        chain_depth = 0

    # Generate output path
    if output_path is None:
        output_path = source_path.parent / f"{source_path.stem}_signed{source_path.suffix}"
    output_path = Path(output_path)

    try:
        # Copy source to output first (lossless copy)
        import shutil

        shutil.copy2(source_path, output_path)

        # Compute hash from the OUTPUT file
        image_hash = hashlib.sha256(output_path.read_bytes()).hexdigest()

        # Get timestamp
        timestamp = datetime.now(timezone.utc).isoformat()

        # Create signature payload
        payload = create_signature_payload(
            image_hash=image_hash,
            did=did,
            display_name=display_name,
            email=email,
            timestamp=timestamp,
            credential_type=credential_type,
        )

        # Sign with Ed25519
        signature_bytes = private_key.sign(payload)
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        # Get public key
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_key_b64 = base64.b64encode(public_key_bytes).decode("ascii")

        # Create signature object
        vouch_sig = VouchMediaSignature(
            version=VOUCH_SIGNATURE_VERSION,
            did=did,
            display_name=display_name,
            email=email,
            public_key=public_key_b64,
            timestamp=timestamp,
            image_hash=image_hash,
            signature=signature_b64,
            credential_type=credential_type,
            claim_type=claim_type.value if isinstance(claim_type, ClaimType) else claim_type,
            chain_id=chain_id,
            chain_depth=chain_depth,
            parent_hash=parent_hash,
            credentials=credentials,
        )

        sidecar_path = None

        # Create sidecar file (recommended - always works)
        if create_sidecar:
            sidecar_path = output_path.with_suffix(output_path.suffix + ".vouch")
            sidecar_path.write_text(vouch_sig.to_json())

        # Embed in image if requested (only for PNG, not JPEG)
        if embed_in_image and PIL_AVAILABLE:
            if output_path.suffix.lower() == ".png":
                # TODO: Implement _embed_signature_in_png
                # For now, embedding in PNG is not implemented - use sidecar
                pass
            else:
                # For JPEG, embedding changes pixel data, so we skip it
                pass

        return NativeSignResult(
            success=True,
            source_path=str(source_path),
            output_path=str(output_path),
            signature=vouch_sig,
            sidecar_path=str(sidecar_path) if sidecar_path else None,
            exif_analysis=exif_analysis,
            warning=warning,
        )

    except Exception as e:
        return NativeSignResult(
            success=False,
            source_path=str(source_path),
            output_path=str(output_path),
            error=str(e),
        )


def verify_image_native(
    image_path: Union[str, Path],
    sidecar_path: Optional[Union[str, Path]] = None,
) -> NativeVerifyResult:
    """
    Verify a natively-signed image.

    Checks both embedded signature and sidecar file.

    Args:
        image_path: Path to image
        sidecar_path: Optional path to sidecar file

    Returns:
        NativeVerifyResult with verification status
    """
    image_path = Path(image_path)

    if not image_path.exists():
        return NativeVerifyResult(
            is_valid=False,
            error=f"File not found: {image_path}",
        )

    # Try to find signature
    vouch_sig = None
    source = None

    # Check embedded signature first
    if PIL_AVAILABLE:
        vouch_sig = _extract_signature_from_image(image_path)
        if vouch_sig:
            source = "embedded"

    # Check sidecar file
    if vouch_sig is None:
        if sidecar_path is None:
            sidecar_path = image_path.with_suffix(image_path.suffix + ".vouch")
        else:
            sidecar_path = Path(sidecar_path)

        if sidecar_path.exists():
            try:
                vouch_sig = VouchMediaSignature.from_json(sidecar_path.read_text())
                source = "sidecar"
            except Exception:
                pass

    if vouch_sig is None:
        return NativeVerifyResult(
            is_valid=False,
            error="No Vouch signature found (checked embedded and sidecar)",
        )

    try:
        # Verify the signature
        is_valid = _verify_signature(image_path, vouch_sig)

        return NativeVerifyResult(
            is_valid=is_valid,
            signature=vouch_sig,
            source=source,
            error=None if is_valid else "Signature verification failed",
        )

    except Exception as e:
        return NativeVerifyResult(
            is_valid=False,
            signature=vouch_sig,
            source=source,
            error=str(e),
        )


# =============================================================================
# Helper Functions
# =============================================================================


def _embed_signature_in_image(
    source_path: Path,
    output_path: Path,
    signature: VouchMediaSignature,
) -> None:
    """Embed signature in image EXIF comment field."""
    with Image.open(source_path) as img:
        # Get existing EXIF data
        exif = img.getexif()

        # Add signature as EXIF UserComment (tag 0x9286)
        # We use ImageDescription (tag 0x010E) as fallback
        comment = signature.to_comment()

        # For JPEG, we can add the signature as a comment
        if source_path.suffix.lower() in (".jpg", ".jpeg"):
            # Add to EXIF
            exif[0x010E] = comment  # ImageDescription
            img.save(output_path, exif=exif, quality=95)
        elif source_path.suffix.lower() == ".png":
            # For PNG, use pnginfo
            from PIL import PngImagePlugin

            pnginfo = PngImagePlugin.PngInfo()
            pnginfo.add_text("Vouch-Signature", signature.to_json())
            img.save(output_path, pnginfo=pnginfo)
        else:
            # For other formats, just copy
            img.save(output_path)


def _extract_signature_from_image(image_path: Path) -> Optional[VouchMediaSignature]:
    """Extract embedded Vouch signature from image."""
    try:
        with Image.open(image_path) as img:
            # Check EXIF
            exif = img.getexif()
            if exif:
                # Check ImageDescription
                if 0x010E in exif:
                    desc = exif[0x010E]
                    sig = VouchMediaSignature.from_comment(desc)
                    if sig:
                        return sig

            # Check PNG text chunks
            if hasattr(img, "text") and "Vouch-Signature" in img.text:
                return VouchMediaSignature.from_json(img.text["Vouch-Signature"])

            # Check info dict
            if hasattr(img, "info") and "Vouch-Signature" in img.info:
                return VouchMediaSignature.from_json(img.info["Vouch-Signature"])

    except Exception:
        pass

    return None


def _verify_signature(image_path: Path, signature: VouchMediaSignature) -> bool:
    """Verify the Ed25519 signature against the image."""
    # Compute current image hash using file bytes (same method as signing)
    current_hash = hashlib.sha256(image_path.read_bytes()).hexdigest()

    # Check if hash matches
    if current_hash != signature.image_hash:
        return False

    # Recreate the signed payload
    payload = create_signature_payload(
        image_hash=signature.image_hash,
        did=signature.did,
        display_name=signature.display_name,
        email=signature.email,
        timestamp=signature.timestamp,
        credential_type=signature.credential_type,
    )

    # Decode public key and signature
    public_key_bytes = base64.b64decode(signature.public_key)
    signature_bytes = base64.b64decode(signature.signature)

    # Load public key
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    # Verify
    try:
        public_key.verify(signature_bytes, payload)
        return True
    except Exception:
        return False


# =============================================================================
# Key Generation Helpers
# =============================================================================


def generate_keypair() -> Tuple[Ed25519PrivateKey, str]:
    """
    Generate a new Ed25519 keypair and DID.

    Returns:
        Tuple of (private_key, did)
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Create did:key from public key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # did:key uses multibase/multicodec encoding
    # Ed25519 public key multicodec prefix is 0xED01
    import base58

    multicodec_bytes = bytes([0xED, 0x01]) + public_bytes
    did = f"did:key:z{base58.b58encode(multicodec_bytes).decode('ascii')}"

    return private_key, did


def truncate_did(did: str, prefix_len: int = 12, suffix_len: int = 4) -> str:
    """
    Truncate a DID for display purposes.

    Example:
        did:key:z6MkvweFGBZYakNE2yGkVRCnuUgqeQvAPp6KAzTBjwtKzSKy
        → did:key:z6MkvweF...zSKy

    Args:
        did: Full DID string
        prefix_len: Characters to show after 'did:key:'
        suffix_len: Characters to show at end

    Returns:
        Truncated DID string
    """
    if not did or len(did) <= prefix_len + suffix_len + 10:
        return did

    # Find the key part after 'did:key:' or similar
    if ":" in did:
        parts = did.split(":")
        if len(parts) >= 3:
            method = ":".join(parts[:2])  # 'did:key'
            key = parts[2]  # 'z6Mkv...'
            if len(key) > prefix_len + suffix_len + 3:
                return f"{method}:{key[:prefix_len]}...{key[-suffix_len:]}"

    return did


def generate_verify_shortlink(
    signature: VouchMediaSignature, base_url: str = "https://vouch.me"
) -> str:
    """
    Generate a verification shortlink for a signature.

    The shortlink contains a hash of the signature that can be used
    to look up the full verification details.

    Args:
        signature: The VouchMediaSignature object
        base_url: Base URL for verification service

    Returns:
        Verification shortlink (e.g., "https://vouch.me/v/abc123")
    """
    # Create a short ID from signature hash
    sig_hash = hashlib.sha256(signature.signature.encode()).hexdigest()[:8]
    return f"{base_url}/v/{sig_hash}"
