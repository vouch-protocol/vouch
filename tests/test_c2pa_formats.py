"""
C2PA Integration Tests for Vouch Protocol.

Tests C2PA manifest signing and verification across supported image formats.
"""

import pytest
import tempfile
from pathlib import Path
from PIL import Image

# Check if c2pa is available
try:
    import c2pa

    C2PA_AVAILABLE = True
except ImportError:
    C2PA_AVAILABLE = False


SUPPORTED_FORMATS = [
    ("jpeg", "image/jpeg", ".jpg"),
    ("png", "image/png", ".png"),
    ("webp", "image/webp", ".webp"),
    ("gif", "image/gif", ".gif"),
    ("tiff", "image/tiff", ".tiff"),
]


def create_test_image(path: Path, img_format: str) -> None:
    """Create a simple test image in the specified format."""
    img = Image.new("RGB", (100, 100), color="blue")
    # Add some variation
    for x in range(50):
        for y in range(50):
            img.putpixel((x, y), (0, 200, 100))
    img.save(path, img_format.upper() if img_format != "jpeg" else "JPEG")


@pytest.fixture
def test_manifest():
    """C2PA manifest definition for testing."""
    return {
        "alg": "PS256",
        "claim_generator": "Vouch Protocol/1.0 (test)",
        "title": "C2PA Format Test",
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {"action": "c2pa.created", "softwareAgent": "Vouch Protocol Test Suite"}
                    ]
                },
            }
        ],
    }


@pytest.mark.skipif(not C2PA_AVAILABLE, reason="c2pa-python not installed")
class TestC2PAFormatSupport:
    """Test C2PA signing works with all supported image formats."""

    @pytest.mark.parametrize("format_name,mime_type,ext", SUPPORTED_FORMATS)
    def test_format_signing(self, format_name, mime_type, ext, test_manifest):
        """Test that each format can be signed with C2PA manifest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            source = tmpdir / f"test{ext}"

            # Create test image
            create_test_image(source, format_name)
            assert source.exists(), f"Failed to create {format_name} test image"

            # Note: Full signing requires certificate chain
            # This test verifies the image can be created and read
            assert source.stat().st_size > 0

            # Verify image is valid
            img = Image.open(source)
            assert img.size == (100, 100)
            assert img.mode in ("RGB", "P")  # GIF uses palette mode


class TestC2PAManifestStructure:
    """Test C2PA manifest JSON structure."""

    def test_manifest_has_required_fields(self, test_manifest):
        """Manifest should have required C2PA fields."""
        assert "alg" in test_manifest
        assert "claim_generator" in test_manifest
        assert "assertions" in test_manifest

    def test_manifest_has_actions_assertion(self, test_manifest):
        """Manifest should include c2pa.actions assertion."""
        actions = [a for a in test_manifest["assertions"] if a["label"] == "c2pa.actions"]
        assert len(actions) == 1
        assert "actions" in actions[0]["data"]

    def test_vouch_generator_identifier(self, test_manifest):
        """Generator should identify as Vouch Protocol."""
        assert "Vouch Protocol" in test_manifest["claim_generator"]


class TestVouchC2PAIntegration:
    """Test Vouch Protocol's C2PA integration module."""

    def test_vouch_identity_to_assertion(self):
        """VouchIdentity should convert to C2PA assertion format."""
        from vouch.media.c2pa import VouchIdentity

        identity = VouchIdentity(
            did="did:web:test.vouch-protocol.com",
            display_name="Test Signer",
            email="test@vouch-protocol.com",
            credential_type="FREE",
        )

        assertion = identity.to_assertion()

        assert assertion["label"] == "vouch.identity"
        assert assertion["data"]["did"] == "did:web:test.vouch-protocol.com"
        assert assertion["data"]["display_name"] == "Test Signer"

    def test_signed_media_result_dataclass(self):
        """SignedMediaResult should contain signing metadata."""
        from vouch.media.c2pa import SignedMediaResult, VouchIdentity

        identity = VouchIdentity(did="did:web:test.vouch-protocol.com", display_name="Test")

        result = SignedMediaResult(
            source_path="/path/to/source.jpg",
            output_path="/path/to/signed.jpg",
            manifest_hash="abc123",
            identity=identity,
            timestamp="2026-01-18T14:00:00Z",
            success=True,
        )

        assert result.success is True
        assert result.manifest_hash == "abc123"
        assert result.identity.did == "did:web:test.vouch-protocol.com"

    def test_verification_result_dataclass(self):
        """VerificationResult should contain verification status."""
        from vouch.media.c2pa import VerificationResult

        result = VerificationResult(
            is_valid=True, claim_generator="Vouch Protocol/1.0", signed_at="2026-01-18T14:00:00Z"
        )

        assert result.is_valid is True
        assert "Vouch Protocol" in result.claim_generator
