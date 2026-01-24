# tests/test_media_native.py
"""
Comprehensive test suite for Vouch Media Native Signing.

Tests cover:
- EXIF analysis and claim type detection
- Sign and verify flow
- Chain tracking and trust decay
- DID generation and truncation
- Shortlink generation
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone

from vouch.media.native import (
    # Core functions
    sign_image_native,
    verify_image_native,
    generate_keypair,
    # EXIF analysis
    analyze_exif,
    EXIFAnalysis,
    # Claim types
    ClaimType,
    # Signature
    VouchMediaSignature,
    # Utilities
    truncate_did,
    generate_verify_shortlink,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def keypair():
    """Generate a test keypair."""
    private_key, did = generate_keypair()
    return private_key, did


@pytest.fixture
def test_image(tmp_path):
    """Create a minimal test image."""
    from PIL import Image

    img = Image.new("RGB", (100, 100), color="red")
    img_path = tmp_path / "test_image.jpg"
    img.save(img_path, "JPEG")
    return img_path


@pytest.fixture
def signed_image(test_image, keypair, tmp_path):
    """Create a signed test image."""
    private_key, did = keypair
    output_path = tmp_path / "signed_image.jpg"

    result = sign_image_native(
        source_path=test_image,
        private_key=private_key,
        did=did,
        display_name="Test Signer",
        email="test@example.com",
        output_path=output_path,
    )

    return result


# =============================================================================
# Test DID Generation
# =============================================================================


class TestDIDGeneration:
    """Tests for DID keypair generation."""

    def test_generate_keypair_returns_tuple(self):
        """Keypair generation returns (private_key, did) tuple."""
        result = generate_keypair()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_did_format(self, keypair):
        """DID follows did:key:z6Mk format."""
        _, did = keypair
        assert did.startswith("did:key:z")
        assert len(did) > 20

    def test_unique_dids(self):
        """Each keypair generates unique DID."""
        _, did1 = generate_keypair()
        _, did2 = generate_keypair()
        assert did1 != did2


# =============================================================================
# Test DID Truncation
# =============================================================================


class TestDIDTruncation:
    """Tests for DID truncation utility."""

    def test_truncate_long_did(self):
        """Long DID is truncated correctly."""
        did = "did:key:z6MkvweFGBZYakNE2yGkVRCnuUgqeQvAPp6KAzTBjwtKzSKy"
        result = truncate_did(did)
        assert result.startswith("did:key:z6MkvweFGBZY")
        assert result.endswith("zSKy")
        assert "..." in result

    def test_short_did_unchanged(self):
        """Short DID is not modified."""
        did = "did:key:z6Mk123"
        result = truncate_did(did)
        assert result == did

    def test_empty_did(self):
        """Empty string returns empty."""
        assert truncate_did("") == ""

    def test_none_did(self):
        """None returns None."""
        assert truncate_did(None) is None


# =============================================================================
# Test EXIF Analysis
# =============================================================================


class TestEXIFAnalysis:
    """Tests for EXIF metadata analysis."""

    def test_no_exif_returns_empty_analysis(self, test_image):
        """Image without EXIF returns low confidence."""
        analysis = analyze_exif(test_image)
        assert analysis.confidence_score < 0.5
        assert not analysis.is_likely_original

    def test_suggested_claim_type_for_no_exif(self, test_image):
        """Image without EXIF suggests SIGNED claim type."""
        analysis = analyze_exif(test_image)
        assert analysis.suggested_claim_type == ClaimType.SIGNED

    def test_confidence_score_range(self, test_image):
        """Confidence score is between 0 and 1."""
        analysis = analyze_exif(test_image)
        assert 0 <= analysis.confidence_score <= 1


# =============================================================================
# Test Sign Flow
# =============================================================================


class TestSignFlow:
    """Tests for image signing."""

    def test_sign_creates_output_file(self, test_image, keypair, tmp_path):
        """Signing creates output image file."""
        private_key, did = keypair
        output_path = tmp_path / "output.jpg"

        result = sign_image_native(
            source_path=test_image,
            private_key=private_key,
            did=did,
            display_name="Test",
            output_path=output_path,
        )

        assert result.success
        assert Path(result.output_path).exists()

    def test_sign_creates_sidecar(self, test_image, keypair, tmp_path):
        """Signing creates .vouch sidecar file."""
        private_key, did = keypair
        output_path = tmp_path / "output.jpg"

        result = sign_image_native(
            source_path=test_image,
            private_key=private_key,
            did=did,
            display_name="Test",
            output_path=output_path,
        )

        assert result.sidecar_path is not None
        assert Path(result.sidecar_path).exists()
        assert result.sidecar_path.endswith(".vouch")

    def test_sign_returns_signature_object(self, signed_image):
        """Signing returns VouchMediaSignature object."""
        assert signed_image.signature is not None
        assert isinstance(signed_image.signature, VouchMediaSignature)

    def test_signature_contains_signer_info(self, signed_image):
        """Signature contains signer information."""
        sig = signed_image.signature
        assert sig.display_name == "Test Signer"
        assert sig.email == "test@example.com"
        assert sig.did.startswith("did:key:")

    def test_signature_has_version_2(self, signed_image):
        """Signature uses version 2.0."""
        assert signed_image.signature.version == "2.0"


# =============================================================================
# Test Claim Types
# =============================================================================


class TestClaimTypes:
    """Tests for claim type handling."""

    def test_default_claim_type_is_signed(self, test_image, keypair, tmp_path):
        """Default claim type is SIGNED for images without EXIF."""
        private_key, did = keypair

        result = sign_image_native(
            source_path=test_image,
            private_key=private_key,
            did=did,
            display_name="Test",
            output_path=tmp_path / "output.jpg",
        )

        assert result.signature.claim_type == "signed"

    def test_captured_downgraded_without_exif(self, test_image, keypair, tmp_path):
        """CAPTURED claim is downgraded to SIGNED without EXIF proof."""
        private_key, did = keypair

        result = sign_image_native(
            source_path=test_image,
            private_key=private_key,
            did=did,
            display_name="Test",
            output_path=tmp_path / "output.jpg",
            claim_type=ClaimType.CAPTURED,  # Force captured
        )

        # Should be downgraded to signed due to lack of EXIF
        assert result.signature.claim_type == "signed"
        assert result.warning is not None


# =============================================================================
# Test Chain Tracking
# =============================================================================


class TestChainTracking:
    """Tests for chain ID and depth tracking."""

    def test_new_signature_has_chain_id(self, signed_image):
        """New signature has chain ID."""
        assert signed_image.signature.chain_id is not None
        assert signed_image.signature.chain_id.startswith("vouch:chain:")

    def test_new_signature_has_depth_zero(self, signed_image):
        """New signature has chain depth 0."""
        assert signed_image.signature.chain_depth == 0

    def test_chain_strength_is_100_for_depth_zero(self, signed_image):
        """Chain strength is 100% for depth 0."""
        assert signed_image.signature.chain_strength == 1.0


# =============================================================================
# Test Trust Decay
# =============================================================================


class TestTrustDecay:
    """Tests for trust decay formula."""

    def test_decay_formula(self):
        """Trust decays correctly with depth."""
        sig = VouchMediaSignature(
            version="2.0",
            did="did:key:test",
            display_name="Test",
            email=None,
            public_key="test",
            timestamp="2024-01-01",
            image_hash="abc",
            signature="xyz",
            chain_depth=0,
        )
        assert sig.chain_strength == 1.0

        sig.chain_depth = 1
        assert abs(sig.chain_strength - 0.833) < 0.01

        sig.chain_depth = 5
        assert abs(sig.chain_strength - 0.5) < 0.01


# =============================================================================
# Test Verify Flow
# =============================================================================


class TestVerifyFlow:
    """Tests for image verification."""

    def test_verify_valid_signature(self, signed_image):
        """Valid signed image verifies successfully."""
        result = verify_image_native(signed_image.output_path)
        assert result.is_valid
        assert result.signature is not None

    def test_verify_returns_signer_info(self, signed_image):
        """Verification returns signer information."""
        result = verify_image_native(signed_image.output_path)
        assert result.signature.display_name == "Test Signer"
        assert result.signature.email == "test@example.com"

    def test_verify_detects_source_sidecar(self, signed_image):
        """Verification detects signature source as sidecar."""
        result = verify_image_native(signed_image.output_path)
        assert result.source == "sidecar"

    def test_verify_unsigned_image_fails(self, test_image):
        """Unsigned image fails verification."""
        result = verify_image_native(test_image)
        assert not result.is_valid
        assert result.error is not None

    def test_verify_tampered_image_fails(self, signed_image, tmp_path):
        """Tampered image fails verification."""
        from PIL import Image

        # Modify the image
        with Image.open(signed_image.output_path) as img:
            img.putpixel((0, 0), (0, 0, 0))
            img.save(signed_image.output_path)

        result = verify_image_native(signed_image.output_path)
        assert not result.is_valid


# =============================================================================
# Test Shortlink Generation
# =============================================================================


class TestShortlinkGeneration:
    """Tests for verification shortlink generation."""

    def test_shortlink_format(self, signed_image):
        """Shortlink has correct format."""
        shortlink = generate_verify_shortlink(signed_image.signature)
        assert shortlink.startswith("https://vch.sh/")
        assert len(shortlink.split("/")[-1]) == 8  # 8 char hash

    def test_shortlink_with_custom_base(self, signed_image):
        """Shortlink uses custom base URL."""
        shortlink = generate_verify_shortlink(signed_image.signature, base_url="https://custom.dev")
        assert shortlink.startswith("https://custom.dev/")


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
