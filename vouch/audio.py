"""
Vouch Protocol Audio Signing - Proves origin of Voice AI audio.

Provides cryptographic signing for audio streams to establish
provenance and non-repudiation for voice AI applications.
"""

import hashlib
from typing import Dict, Any, Optional
from dataclasses import dataclass

from vouch.signer import Signer


@dataclass
class SignedAudioFrame:
    """
    Represents a signed audio frame with Vouch credentials.

    Attributes:
        content_type: MIME type of the audio content
        fingerprint: SHA-256 hash of the audio bytes
        vouch_token: The Vouch-Token proving origin
        duration_ms: Optional duration in milliseconds
    """

    content_type: str
    fingerprint: str
    vouch_token: str
    duration_ms: Optional[int] = None


class AudioSigner:
    """
    Signs audio buffers to prove origin of Voice AI.

    Integrates with the Vouch Protocol to provide cryptographic
    proof of audio origin for voice AI applications.

    Example:
        >>> from vouch import Signer
        >>> from vouch.audio import AudioSigner
        >>>
        >>> signer = Signer(private_key='...', did='did:web:voice-ai.com')
        >>> audio_signer = AudioSigner(signer)
        >>>
        >>> signed = audio_signer.sign_frame(audio_bytes)
        >>> print(signed.vouch_token)
    """

    def __init__(self, signer: Signer):
        """
        Initialize the AudioSigner with a Vouch Signer.

        Args:
            signer: A configured Vouch Signer instance.
        """
        self._signer = signer

    @staticmethod
    def fingerprint_audio(audio_bytes: bytes) -> str:
        """
        Creates a deterministic SHA-256 hash of the audio clip.

        Args:
            audio_bytes: Raw audio data.

        Returns:
            Hex-encoded SHA-256 hash.
        """
        return hashlib.sha256(audio_bytes).hexdigest()

    def sign_frame(
        self,
        audio_bytes: bytes,
        content_type: str = "audio/pcm",
        duration_ms: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SignedAudioFrame:
        """
        Signs an audio frame with Vouch credentials.

        Args:
            audio_bytes: Raw audio data to sign.
            content_type: MIME type of the audio.
            duration_ms: Optional duration in milliseconds.
            metadata: Optional additional metadata to include.

        Returns:
            A SignedAudioFrame with the Vouch-Token.
        """
        fingerprint = self.fingerprint_audio(audio_bytes)

        # Build the payload
        payload = {
            "type": "audio_frame",
            "content_type": content_type,
            "fingerprint": f"sha256:{fingerprint}",
            "size_bytes": len(audio_bytes),
        }

        if duration_ms:
            payload["duration_ms"] = duration_ms

        if metadata:
            payload["metadata"] = metadata

        # Sign with Vouch
        vouch_token = self._signer.sign(payload)

        return SignedAudioFrame(
            content_type=content_type,
            fingerprint=fingerprint,
            vouch_token=vouch_token,
            duration_ms=duration_ms,
        )

    def sign_stream(self, audio_chunks: list, content_type: str = "audio/pcm") -> Dict[str, Any]:
        """
        Signs an entire audio stream (multiple chunks).

        Args:
            audio_chunks: List of audio byte chunks.
            content_type: MIME type of the audio.

        Returns:
            Dictionary with overall fingerprint and Vouch-Token.
        """
        # Combine all chunks for overall fingerprint
        combined = b"".join(audio_chunks)
        fingerprint = self.fingerprint_audio(combined)

        payload = {
            "type": "audio_stream",
            "content_type": content_type,
            "fingerprint": f"sha256:{fingerprint}",
            "total_chunks": len(audio_chunks),
            "total_bytes": len(combined),
        }

        vouch_token = self._signer.sign(payload)

        return {
            "fingerprint": fingerprint,
            "vouch_token": vouch_token,
            "chunk_count": len(audio_chunks),
            "total_bytes": len(combined),
        }


# =============================================================================
# Audio Watermarking Functions
# =============================================================================
# These functions provide lightweight audio watermarking for Voice AI streams.
# For production use, consider integrating with:
# - Meta's AudioSeal: https://github.com/facebookresearch/audioseal
# - Google's SynthID: Available via Vertex AI
# =============================================================================

# Vouch watermark header format (32 bytes)
# [MAGIC:4][VERSION:1][FLAGS:1][SIGNER_ID_HASH:12][TIMESTAMP:8][CHECKSUM:6]
WATERMARK_MAGIC = b"VWMK"  # Vouch WaterMarK
WATERMARK_VERSION = 0x01


@dataclass
class WatermarkResult:
    """Result of watermark verification.
    
    Attributes:
        valid: Whether the watermark is valid
        signer_id_hash: First 12 chars of signer ID hash (if valid)
        timestamp: Unix timestamp when watermarked (if valid)
        error: Error message (if invalid)
    """
    valid: bool
    signer_id_hash: Optional[str] = None
    timestamp: Optional[int] = None
    error: Optional[str] = None


def watermark_chunk(
    chunk: bytes,
    signer_id: str,
    timestamp: Optional[int] = None,
) -> bytes:
    """Add Vouch watermark header to an audio chunk.
    
    This is a metadata-based watermarking approach suitable for trusted
    pipelines where the audio bytes are not modified in transit.
    
    For adversarial scenarios (audio may be re-encoded), use a DSP-based
    watermarking library like AudioSeal or SynthID.
    
    Args:
        chunk: Raw audio bytes to watermark
        signer_id: Identifier of the signing entity (DID or agent ID)
        timestamp: Optional Unix timestamp (defaults to current time)
        
    Returns:
        Watermarked audio chunk with Vouch header prepended
        
    Example:
        >>> watermarked = watermark_chunk(audio_bytes, "did:vouch:abc123")
        >>> # Send watermarked to downstream services
    
    TODO: Integrate with AudioSeal or SynthID for robust watermarking
    that survives re-encoding, compression, and other transformations.
    """
    import struct
    import time as time_module
    
    if timestamp is None:
        timestamp = int(time_module.time())
    
    # Create signer ID hash (first 12 chars of SHA256)
    signer_hash = hashlib.sha256(signer_id.encode()).hexdigest()[:12].encode()
    
    # Flags byte (reserved for future use)
    flags = 0x00
    
    # Build header (without checksum)
    header_data = (
        WATERMARK_MAGIC +                           # 4 bytes
        bytes([WATERMARK_VERSION]) +                # 1 byte
        bytes([flags]) +                            # 1 byte
        signer_hash +                               # 12 bytes
        struct.pack(">Q", timestamp)                # 8 bytes (big-endian)
    )
    
    # Calculate checksum (first 6 bytes of SHA256 of header + chunk)
    checksum = hashlib.sha256(header_data + chunk).digest()[:6]
    
    # Complete header
    header = header_data + checksum
    
    return header + chunk


def verify_watermark(chunk: bytes) -> WatermarkResult:
    """Verify a Vouch watermark on an audio chunk.
    
    Args:
        chunk: Potentially watermarked audio bytes
        
    Returns:
        WatermarkResult with validity status and extracted metadata
        
    Example:
        >>> result = verify_watermark(received_audio)
        >>> if result.valid:
        ...     print(f"Signed by: {result.signer_id_hash}")
    """
    import struct
    
    # Minimum size: 32 byte header
    if len(chunk) < 32:
        return WatermarkResult(
            valid=False,
            error="Chunk too small to contain watermark",
        )
    
    # Check magic bytes
    if chunk[:4] != WATERMARK_MAGIC:
        return WatermarkResult(
            valid=False,
            error="Missing Vouch watermark header",
        )
    
    # Extract header components
    version = chunk[4]
    if version != WATERMARK_VERSION:
        return WatermarkResult(
            valid=False,
            error=f"Unsupported watermark version: {version}",
        )
    
    # flags = chunk[5]  # Reserved for future use
    signer_id_hash = chunk[6:18].decode("utf-8")
    timestamp = struct.unpack(">Q", chunk[18:26])[0]
    stored_checksum = chunk[26:32]
    
    # Verify checksum
    audio_data = chunk[32:]
    header_data = chunk[:26]
    expected_checksum = hashlib.sha256(header_data + audio_data).digest()[:6]
    
    if stored_checksum != expected_checksum:
        return WatermarkResult(
            valid=False,
            error="Checksum mismatch - audio may have been tampered with",
        )
    
    return WatermarkResult(
        valid=True,
        signer_id_hash=signer_id_hash,
        timestamp=timestamp,
    )


def strip_watermark(chunk: bytes) -> bytes:
    """Remove Vouch watermark header from an audio chunk.
    
    Args:
        chunk: Watermarked audio bytes
        
    Returns:
        Original audio bytes without watermark header
        
    Raises:
        ValueError: If chunk doesn't have a valid watermark
    """
    result = verify_watermark(chunk)
    if not result.valid:
        raise ValueError(f"Cannot strip watermark: {result.error}")
    
    return chunk[32:]

