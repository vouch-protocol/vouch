import hashlib
from typing import Tuple, Callable

class AudioSigner:
    """Signs audio buffers to prove origin of Voice AI."""
    
    @staticmethod
    def fingerprint_audio(audio_bytes: bytes) -> str:
        """Creates a deterministic SHA-256 hash of the audio clip."""
        return hashlib.sha256(audio_bytes).hexdigest()

    def sign_frame(self, audio_bytes: bytes, signer_func: Callable[[str], str]) -> dict:
        """
        Signs a generic audio frame.
        signer_func: A function that takes a string (fingerprint) and returns a signature.
        """
        fingerprint = self.fingerprint_audio(audio_bytes)
        signature = signer_func(fingerprint)
        
        return {
            "content_type": "audio/pcm",
            "fingerprint": fingerprint,
            "signature": signature
        }
