# vouch/bridge/audio_routes.py
"""
Audio Bridge Routes — FastAPI endpoints for server-side audio watermarking.

Endpoints:
    POST /audio/embed   — Embed spread-spectrum watermark (multi-format)
    POST /audio/detect  — Detect watermark in audio
    POST /audio/sign    — Full C2PA signing with VouchCovenant
    GET  /audio/health  — Audio subsystem health check

Auth:
    All endpoints except /audio/health require:
        Authorization: Bearer <VOUCH_BRIDGE_SECRET>

This module handles non-browser clients (CLI, third-party integrations, batch
processing) that cannot use WASM. Browser clients should always prefer WASM.
"""

import base64
import hashlib
import tempfile
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from vouch.bridge.config import BridgeSettings, load_settings

# =============================================================================
# Pydantic Models
# =============================================================================


class AudioEmbedRequest(BaseModel):
    """Request body for POST /audio/embed."""

    audio_base64: str = Field(..., description="Base64-encoded audio (WAV/MP3/FLAC/OGG/M4A/AAC/Opus/WebM)")
    did: str = Field(..., description="DID of the signer")
    display_name: str = Field("", description="Human-readable signer name")
    covenant: Optional[dict] = Field(None, description="VouchCovenant policy dict")


class AudioEmbedResponse(BaseModel):
    """Response body for POST /audio/embed."""

    success: bool
    audio_base64: Optional[str] = None
    watermark_id: Optional[str] = None
    audio_hash: Optional[str] = None
    payload_hash: Optional[str] = None
    timestamp: Optional[str] = None
    error: Optional[str] = None


class AudioDetectRequest(BaseModel):
    """Request body for POST /audio/detect."""

    audio_base64: str = Field(..., description="Base64-encoded audio to scan")


class AudioDetectResponse(BaseModel):
    """Response body for POST /audio/detect."""

    success: bool
    detected: bool = False
    confidence: float = 0.0
    signer_did: Optional[str] = None
    payload_hash: Optional[str] = None
    covenant: Optional[dict] = None
    error: Optional[str] = None


class AudioSignRequest(BaseModel):
    """Request body for POST /audio/sign — full C2PA container signing."""

    audio_base64: str = Field(..., description="Base64-encoded audio file")
    did: str = Field(..., description="DID of the signer")
    display_name: str = Field("", description="Human-readable signer name")
    covenant: Optional[dict] = Field(None, description="VouchCovenant policy dict")
    title: Optional[str] = Field(None, description="Title for C2PA manifest")


class AudioSignResponse(BaseModel):
    """Response body for POST /audio/sign."""

    success: bool
    signed_audio_base64: Optional[str] = None
    manifest_hash: Optional[str] = None
    watermark_embedded: bool = False
    timestamp: Optional[str] = None
    error: Optional[str] = None


class AudioHealthResponse(BaseModel):
    """Response body for GET /audio/health."""

    status: str
    version: str
    numpy_available: bool
    c2pa_available: bool
    audioseal_available: bool
    watermarker: str


# =============================================================================
# Router Setup
# =============================================================================

router = APIRouter(prefix="/audio", tags=["audio"])

_settings: Optional[BridgeSettings] = None


def _get_settings() -> BridgeSettings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def _check_auth(authorization: Optional[str]) -> None:
    """Validate bearer token against bridge secret."""
    settings = _get_settings()
    if not settings.auth_enabled:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization[len("Bearer "):]
    if token != settings.bridge_secret:
        raise HTTPException(status_code=403, detail="Invalid bridge secret")


# =============================================================================
# Audio Format Detection
# =============================================================================

_AUDIO_MAGIC = [
    (b"RIFF", 0, ".wav"),
    (b"fLaC", 0, ".flac"),
    (b"OggS", 0, ".ogg"),
    (b"\xff\xfb", 0, ".mp3"),
    (b"\xff\xf3", 0, ".mp3"),
    (b"\xff\xf2", 0, ".mp3"),
    (b"ID3", 0, ".mp3"),
]


def _detect_audio_extension(audio_bytes: bytes) -> str:
    """Detect audio format from magic bytes."""
    for magic, offset, ext in _AUDIO_MAGIC:
        if audio_bytes[offset: offset + len(magic)] == magic:
            return ext
    # Check for MP4/M4A containers (ftyp box)
    if len(audio_bytes) >= 12 and audio_bytes[4:8] == b"ftyp":
        return ".m4a"
    # Default to WAV
    return ".wav"


def _audio_mime_type(ext: str) -> str:
    """Map extension to MIME type."""
    return {
        ".wav": "audio/wav",
        ".mp3": "audio/mpeg",
        ".flac": "audio/flac",
        ".ogg": "audio/ogg",
        ".m4a": "audio/mp4",
        ".aac": "audio/aac",
        ".opus": "audio/opus",
        ".webm": "audio/webm",
    }.get(ext, "audio/wav")


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/health", response_model=AudioHealthResponse)
async def audio_health() -> AudioHealthResponse:
    """Audio subsystem health check — no auth required."""
    from vouch.audio import (
        NUMPY_AVAILABLE,
        C2PA_AVAILABLE,
        AUDIOSEAL_AVAILABLE,
        create_watermarker,
        WatermarkMode,
    )

    wm = create_watermarker(WatermarkMode.HYBRID)

    return AudioHealthResponse(
        status="ok",
        version="1.0.0",
        numpy_available=NUMPY_AVAILABLE,
        c2pa_available=C2PA_AVAILABLE,
        audioseal_available=AUDIOSEAL_AVAILABLE,
        watermarker=wm.name,
    )


@router.post("/embed", response_model=AudioEmbedResponse)
async def audio_embed(
    req: AudioEmbedRequest,
    authorization: Optional[str] = Header(None),
) -> AudioEmbedResponse:
    """Embed spread-spectrum watermark into audio (server-side)."""
    _check_auth(authorization)

    try:
        from vouch.audio import (
            AudioSigner,
            VouchCovenant,
            NUMPY_AVAILABLE,
            create_watermarker,
            WatermarkMode,
        )
    except ImportError as e:
        return AudioEmbedResponse(success=False, error=f"Audio modules unavailable: {e}")

    if not NUMPY_AVAILABLE:
        return AudioEmbedResponse(success=False, error="NumPy not installed — required for audio watermarking")

    # Decode audio
    try:
        audio_bytes = base64.b64decode(req.audio_base64)
    except Exception:
        return AudioEmbedResponse(success=False, error="Invalid base64 audio data")

    if len(audio_bytes) < 100:
        return AudioEmbedResponse(success=False, error="Audio data too small")

    ext = _detect_audio_extension(audio_bytes)

    # Build covenant if provided
    covenant = None
    if req.covenant:
        covenant = VouchCovenant.from_dict(req.covenant)

    tmp_dir = tempfile.mkdtemp(prefix="vouch_audio_bridge_")
    source_path = Path(tmp_dir) / f"source{ext}"
    output_path = Path(tmp_dir) / f"watermarked{ext}"

    try:
        source_path.write_bytes(audio_bytes)

        watermarker = create_watermarker(WatermarkMode.HYBRID)
        signer = AudioSigner(
            did=req.did,
            display_name=req.display_name or req.did,
            watermarker=watermarker,
        )

        result = signer.sign_with_watermark(
            source_path=str(source_path),
            output_path=str(output_path),
            covenant=covenant,
        )

        if not result.success:
            return AudioEmbedResponse(success=False, error=result.error)

        # Read watermarked audio
        watermarked_bytes = output_path.read_bytes()
        audio_hash = hashlib.sha256(audio_bytes).hexdigest()
        watermark_id = f"sonic-{hashlib.sha256(f'{req.did}:{datetime.now(timezone.utc).isoformat()}'.encode()).hexdigest()[:16]}"
        payload_hash = hashlib.sha256(watermark_id.encode()).hexdigest()

        return AudioEmbedResponse(
            success=True,
            audio_base64=base64.b64encode(watermarked_bytes).decode("ascii"),
            watermark_id=watermark_id,
            audio_hash=audio_hash,
            payload_hash=payload_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    except Exception as e:
        return AudioEmbedResponse(success=False, error=str(e))

    finally:
        for f in (source_path, output_path):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
        try:
            Path(tmp_dir).rmdir()
        except Exception:
            pass


@router.post("/detect", response_model=AudioDetectResponse)
async def audio_detect(
    req: AudioDetectRequest,
    authorization: Optional[str] = Header(None),
) -> AudioDetectResponse:
    """Detect watermark in audio (server-side)."""
    _check_auth(authorization)

    try:
        from vouch.audio import (
            AudioVerifier,
            NUMPY_AVAILABLE,
        )
    except ImportError as e:
        return AudioDetectResponse(success=False, error=f"Audio modules unavailable: {e}")

    if not NUMPY_AVAILABLE:
        return AudioDetectResponse(success=False, error="NumPy not installed — required for detection")

    # Decode audio
    try:
        audio_bytes = base64.b64decode(req.audio_base64)
    except Exception:
        return AudioDetectResponse(success=False, error="Invalid base64 audio data")

    if len(audio_bytes) < 100:
        return AudioDetectResponse(success=False, error="Audio data too small")

    ext = _detect_audio_extension(audio_bytes)

    tmp_dir = tempfile.mkdtemp(prefix="vouch_audio_bridge_")
    audio_path = Path(tmp_dir) / f"detect{ext}"

    try:
        audio_path.write_bytes(audio_bytes)

        verifier = AudioVerifier()
        info = verifier.verify(str(audio_path))

        covenant_dict = None
        if info.covenant:
            covenant_dict = info.covenant.to_assertion().get("data")

        return AudioDetectResponse(
            success=True,
            detected=info.has_watermark or info.has_c2pa,
            confidence=info.watermark_confidence,
            signer_did=info.signer_did,
            payload_hash=None,  # Payload hash requires WASM-side extraction
            covenant=covenant_dict,
        )

    except Exception as e:
        return AudioDetectResponse(success=False, error=str(e))

    finally:
        try:
            audio_path.unlink(missing_ok=True)
        except Exception:
            pass
        try:
            Path(tmp_dir).rmdir()
        except Exception:
            pass


@router.post("/sign", response_model=AudioSignResponse)
async def audio_sign(
    req: AudioSignRequest,
    authorization: Optional[str] = Header(None),
) -> AudioSignResponse:
    """Full C2PA container signing with VouchCovenant + optional watermark."""
    _check_auth(authorization)

    try:
        from vouch.audio import (
            AudioSigner,
            VouchCovenant,
            C2PA_AVAILABLE,
            NUMPY_AVAILABLE,
            create_watermarker,
            WatermarkMode,
        )
    except ImportError as e:
        return AudioSignResponse(success=False, error=f"Audio modules unavailable: {e}")

    if not C2PA_AVAILABLE:
        return AudioSignResponse(success=False, error="c2pa-python not installed or Python < 3.10")

    # Decode audio
    try:
        audio_bytes = base64.b64decode(req.audio_base64)
    except Exception:
        return AudioSignResponse(success=False, error="Invalid base64 audio data")

    if len(audio_bytes) < 100:
        return AudioSignResponse(success=False, error="Audio data too small")

    ext = _detect_audio_extension(audio_bytes)

    # Build covenant if provided
    covenant = None
    if req.covenant:
        covenant = VouchCovenant.from_dict(req.covenant)

    tmp_dir = tempfile.mkdtemp(prefix="vouch_audio_bridge_")
    source_path = Path(tmp_dir) / f"source{ext}"
    signed_path = Path(tmp_dir) / f"signed{ext}"

    try:
        source_path.write_bytes(audio_bytes)

        import json as _json
        import c2pa

        # Generate cert chain for C2PA signing (reuse from server.py)
        from vouch.bridge.server import _generate_cert_chain

        private_key, cert_pem = _generate_cert_chain(common_name=req.did)

        # Build C2PA manifest with identity + covenant
        assertions = [
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
            {
                "label": "vouch.identity",
                "data": {
                    "did": req.did,
                    "display_name": req.display_name or req.did,
                    "protocol_version": "1.0",
                },
            },
        ]

        if covenant:
            assertions.append(covenant.to_assertion())

        manifest_def = {
            "claim_generator": "Vouch Protocol/1.0.0 (Audio)",
            "claim_generator_info": [{"name": "Vouch Protocol", "version": "1.0.0"}],
            "title": req.title or source_path.name,
            "format": _audio_mime_type(ext),
            "assertions": assertions,
        }

        # Use from_callback for Ed25519 signing
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

        # Also embed watermark if NumPy available
        watermark_embedded = False
        final_path = signed_path
        if NUMPY_AVAILABLE and signed_path.exists():
            wm_path = Path(tmp_dir) / f"signed_wm{ext}"
            try:
                signer = AudioSigner(
                    did=req.did,
                    display_name=req.display_name or req.did,
                )
                wm_result = signer.sign_with_watermark(
                    source_path=str(signed_path),
                    output_path=str(wm_path),
                    covenant=covenant,
                )
                if wm_result.success and wm_path.exists():
                    final_path = wm_path
                    watermark_embedded = True
            except Exception:
                pass  # Watermark is optional — C2PA alone is valid

        signed_bytes = final_path.read_bytes()

        return AudioSignResponse(
            success=True,
            signed_audio_base64=base64.b64encode(signed_bytes).decode("ascii"),
            manifest_hash=manifest_hash,
            watermark_embedded=watermark_embedded,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    except Exception as e:
        return AudioSignResponse(success=False, error=str(e))

    finally:
        for f in Path(tmp_dir).glob("*"):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
        try:
            Path(tmp_dir).rmdir()
        except Exception:
            pass
