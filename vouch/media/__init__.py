# vouch/media/__init__.py
"""
Vouch Media Module - Image and Video Provenance

This module provides C2PA-compliant media signing and verification
for establishing content authenticity and provenance.
"""

from vouch.media.c2pa import (
    MediaSigner,
    MediaVerifier,
    sign_image,
    verify_image,
)

__all__ = [
    "MediaSigner",
    "MediaVerifier",
    "sign_image",
    "verify_image",
]
