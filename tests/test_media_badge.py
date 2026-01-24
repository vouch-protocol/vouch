# tests/test_media_badge.py
"""
Test suite for BadgeFactory - QR codes and visual badges.

Tests cover:
- Position calculations
- QR code generation
- Badge application to images
- URL generation
"""

import pytest
import tempfile
from pathlib import Path

from vouch.media.badge import (
    BadgeFactory,
    BadgeOptions,
    BadgeResult,
    calculate_position,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def test_image(tmp_path):
    """Create a minimal test image."""
    from PIL import Image

    img = Image.new("RGB", (1920, 1080), color="blue")
    img_path = tmp_path / "test_badge_image.jpg"
    img.save(img_path, "JPEG")
    return img_path


@pytest.fixture
def factory():
    """Create default BadgeFactory."""
    return BadgeFactory()


# =============================================================================
# Test Position Calculations
# =============================================================================


class TestPositionCalculations:
    """Tests for badge position calculations."""

    def test_bottom_right_position(self):
        """Bottom-right calculates correctly."""
        x, y = calculate_position((1920, 1080), 64, "bottom-right", 16)
        assert x == 1920 - 64 - 16  # 1840
        assert y == 1080 - 64 - 16  # 1000

    def test_top_left_position(self):
        """Top-left calculates correctly."""
        x, y = calculate_position((1920, 1080), 64, "top-left", 16)
        assert x == 16
        assert y == 16

    def test_top_right_position(self):
        """Top-right calculates correctly."""
        x, y = calculate_position((1920, 1080), 64, "top-right", 16)
        assert x == 1920 - 64 - 16
        assert y == 16

    def test_bottom_left_position(self):
        """Bottom-left calculates correctly."""
        x, y = calculate_position((1920, 1080), 64, "bottom-left", 16)
        assert x == 16
        assert y == 1080 - 64 - 16

    def test_center_bottom_position(self):
        """Center-bottom calculates correctly."""
        x, y = calculate_position((1920, 1080), 64, "center-bottom", 16)
        assert x == (1920 - 64) // 2
        assert y == 1080 - 64 - 16

    def test_different_badge_sizes(self):
        """Position adjusts for different badge sizes."""
        x1, y1 = calculate_position((1000, 1000), 64, "bottom-right", 10)
        x2, y2 = calculate_position((1000, 1000), 128, "bottom-right", 10)

        # Larger badge should be further from edge
        assert x2 < x1
        assert y2 < y1


# =============================================================================
# Test BadgeFactory Configuration
# =============================================================================


class TestBadgeFactoryConfig:
    """Tests for BadgeFactory configuration."""

    def test_default_options(self, factory):
        """Default options are set correctly."""
        config = factory.get_config()
        assert config.position == "bottom-right"
        assert config.size == 64
        assert config.include_qr
        assert config.base_url == "https://vch.sh"

    def test_custom_options(self):
        """Custom options override defaults."""
        custom = BadgeOptions(position="top-left", size=128, base_url="https://custom.dev")
        factory = BadgeFactory(custom)
        config = factory.get_config()

        assert config.position == "top-left"
        assert config.size == 128
        assert config.base_url == "https://custom.dev"

    def test_set_position(self, factory):
        """set_position updates position."""
        factory.set_position("center-bottom")
        assert factory.get_config().position == "center-bottom"


# =============================================================================
# Test URL Generation
# =============================================================================


class TestURLGeneration:
    """Tests for verification URL generation."""

    def test_url_format(self, factory):
        """URL has correct format."""
        url = factory.generate_verify_url("test_signature")
        assert url.startswith("https://vch.sh/")
        assert len(url.split("/")[-1]) == 8

    def test_url_with_custom_base(self):
        """URL uses custom base."""
        factory = BadgeFactory(BadgeOptions(base_url="https://custom.dev"))
        url = factory.generate_verify_url("test")
        assert url.startswith("https://custom.dev/")

    def test_consistent_hash(self, factory):
        """Same input produces same hash."""
        url1 = factory.generate_verify_url("same_signature")
        url2 = factory.generate_verify_url("same_signature")
        assert url1 == url2

    def test_different_signatures_different_urls(self, factory):
        """Different signatures produce different URLs."""
        url1 = factory.generate_verify_url("sig_a")
        url2 = factory.generate_verify_url("sig_b")
        assert url1 != url2


# =============================================================================
# Test QR Code Generation
# =============================================================================


class TestQRCodeGeneration:
    """Tests for QR code creation."""

    def test_qr_code_created(self, factory):
        """QR code image is created."""
        qr = factory.create_qr_code("https://vch.sh/abc123")
        # Will be None if qrcode not installed, otherwise Image
        if qr is not None:
            assert qr.size[0] > 0
            assert qr.size[1] > 0

    def test_qr_code_size(self, factory):
        """QR code respects size parameter."""
        qr = factory.create_qr_code("test", size=128)
        if qr is not None:
            assert qr.size == (128, 128)


# =============================================================================
# Test Badge Application
# =============================================================================


class TestBadgeApplication:
    """Tests for applying badges to images."""

    def test_add_badge_creates_output(self, factory, test_image, tmp_path):
        """add_badge creates output file."""
        output = tmp_path / "badged.jpg"
        result = factory.add_badge(str(test_image), "sig_hash", str(output))

        assert result.success
        assert Path(result.output_path).exists()

    def test_add_badge_returns_verify_url(self, factory, test_image, tmp_path):
        """add_badge returns verification URL."""
        output = tmp_path / "badged.jpg"
        result = factory.add_badge(str(test_image), "sig_hash", str(output))

        assert result.verify_url is not None
        assert result.verify_url.startswith("https://vch.sh/")

    def test_add_badge_missing_source(self, factory, tmp_path):
        """add_badge handles missing source file."""
        result = factory.add_badge("/nonexistent/path.jpg", "sig", str(tmp_path / "out.jpg"))

        assert not result.success
        assert "not found" in result.error.lower()

    def test_add_badge_default_output_path(self, factory, test_image):
        """add_badge generates output path if not provided."""
        result = factory.add_badge(str(test_image), "sig_hash")

        assert result.success
        assert "_badged" in result.output_path


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
