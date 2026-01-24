# vouch/media/badge.py
"""
BadgeFactory - Visual verification badges for signed images.

Features:
- QR code with verification shortlink
- Visual checkmark overlay
- Configurable position (default: bottom-right)
"""

from pathlib import Path
from typing import Optional, Tuple, Literal
from dataclasses import dataclass
import hashlib

try:
    from PIL import Image, ImageDraw, ImageFont
    import qrcode

    PIL_AVAILABLE = True
    QR_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    QR_AVAILABLE = False


# Type definitions
BadgePosition = Literal["top-left", "top-right", "bottom-left", "bottom-right", "center-bottom"]


@dataclass
class BadgeOptions:
    """Configuration options for badge placement."""

    position: BadgePosition = "bottom-right"
    size: int = 64  # Badge size in pixels
    opacity: float = 0.9
    include_qr: bool = True
    include_checkmark: bool = True
    padding: int = 16
    base_url: str = None  # Will use SHORTLINK_DOMAIN from config if None
    
    def __post_init__(self):
        if self.base_url is None:
            from vouch.config import SHORTLINK_DOMAIN
            self.base_url = SHORTLINK_DOMAIN


@dataclass
class BadgeResult:
    """Result of badge application."""

    success: bool
    output_path: Optional[str] = None
    verify_url: Optional[str] = None
    error: Optional[str] = None


def calculate_position(
    image_size: Tuple[int, int], badge_size: int, position: BadgePosition, padding: int
) -> Tuple[int, int]:
    """
    Calculate (x, y) coordinates for badge placement.

    Args:
        image_size: (width, height) of source image
        badge_size: Size of badge in pixels
        position: Position string
        padding: Padding from edge

    Returns:
        (x, y) coordinates for badge
    """
    width, height = image_size

    positions = {
        "top-left": (padding, padding),
        "top-right": (width - badge_size - padding, padding),
        "bottom-left": (padding, height - badge_size - padding),
        "bottom-right": (width - badge_size - padding, height - badge_size - padding),
        "center-bottom": ((width - badge_size) // 2, height - badge_size - padding),
    }

    return positions.get(position, positions["bottom-right"])


class BadgeFactory:
    """
    Factory for creating and applying visual Vouch badges.

    Usage:
        factory = BadgeFactory(position='bottom-right')
        result = factory.add_badge(image_path, signature_hash, output_path)
    """

    def __init__(self, options: Optional[BadgeOptions] = None):
        """Initialize with options."""
        self.options = options or BadgeOptions()

    def generate_verify_url(self, signature_hash: str) -> str:
        """Generate verification shortlink from signature hash."""
        short_hash = hashlib.sha256(signature_hash.encode()).hexdigest()[:8]
        base = self.options.base_url.rstrip("/")
        return f"{base}/{short_hash}"

    def create_qr_code(self, data: str, size: int = 64) -> Optional["Image.Image"]:
        """
        Generate QR code image.

        Args:
            data: Data to encode in QR
            size: Output size in pixels

        Returns:
            PIL Image or None if qrcode not available
        """
        if not QR_AVAILABLE:
            return None

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=2,
            border=1,
        )
        qr.add_data(data)
        qr.make(fit=True)

        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img = qr_img.resize((size, size), Image.Resampling.LANCZOS)

        return qr_img

    def add_badge(
        self,
        source_path: str,
        signature_hash: str,
        output_path: Optional[str] = None,
    ) -> BadgeResult:
        """
        Add Vouch badge to image.

        Args:
            source_path: Path to source image
            signature_hash: Signature hash for QR code
            output_path: Output path (default: source_badged.ext)

        Returns:
            BadgeResult with output path and verify URL
        """
        if not PIL_AVAILABLE:
            return BadgeResult(success=False, error="PIL/Pillow not installed")

        source_path = Path(source_path)
        if not source_path.exists():
            return BadgeResult(success=False, error=f"File not found: {source_path}")

        # Generate output path
        if output_path is None:
            output_path = source_path.parent / f"{source_path.stem}_badged{source_path.suffix}"
        output_path = Path(output_path)

        try:
            # Open image
            img = Image.open(source_path).convert("RGBA")

            # Generate verify URL
            verify_url = self.generate_verify_url(signature_hash)

            # Create QR code
            if self.options.include_qr:
                qr_img = self.create_qr_code(verify_url, self.options.size)

                if qr_img:
                    # Calculate position
                    x, y = calculate_position(
                        img.size, self.options.size, self.options.position, self.options.padding
                    )

                    # Paste QR code
                    qr_img = qr_img.convert("RGBA")
                    img.paste(qr_img, (x, y), qr_img)

            # Save
            if source_path.suffix.lower() in (".jpg", ".jpeg"):
                img = img.convert("RGB")
            img.save(output_path)

            return BadgeResult(
                success=True,
                output_path=str(output_path),
                verify_url=verify_url,
            )

        except Exception as e:
            return BadgeResult(success=False, error=str(e))

    def set_position(self, position: BadgePosition) -> None:
        """Update badge position (for Badge Studio customization)."""
        self.options.position = position

    def get_config(self) -> BadgeOptions:
        """Get current configuration."""
        return self.options
