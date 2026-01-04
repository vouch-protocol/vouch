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
