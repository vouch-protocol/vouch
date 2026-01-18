# vouch/media/__init__.py
"""
Vouch Media Module - Image and Video Provenance

This module provides C2PA-compliant media signing and verification
for establishing content authenticity and provenance.
"""

# C2PA imports - conditional because c2pa-python requires Python 3.10+
try:
    from vouch.media.c2pa import (
        MediaSigner,
        MediaVerifier,
        sign_image,
        verify_image,
        C2PA_AVAILABLE,
    )
except (ImportError, SyntaxError):
    # c2pa-python uses match statements (Python 3.10+)
    MediaSigner = None  # type: ignore
    MediaVerifier = None  # type: ignore
    sign_image = None  # type: ignore
    verify_image = None  # type: ignore
    C2PA_AVAILABLE = False

__all__ = [
    "MediaSigner",
    "MediaVerifier",
    "sign_image",
    "verify_image",
    "C2PA_AVAILABLE",
]
