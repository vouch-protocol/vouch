# tests/test_bridge.py
"""
Tests for the Vouch Bridge server.

Run: pytest tests/test_bridge.py -v
"""

import base64
import os
import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")
from fastapi.testclient import TestClient

# Set a test secret before importing the app
os.environ["VOUCH_BRIDGE_SECRET"] = "test-secret-123"

from vouch.bridge.server import app, _settings

# Reset cached settings so env var takes effect
import vouch.bridge.server as bridge_mod

bridge_mod._settings = None

client = TestClient(app)

AUTH_HEADER = {"Authorization": "Bearer test-secret-123"}
BAD_AUTH = {"Authorization": "Bearer wrong-secret"}

# Minimal 1x1 red JPEG (valid JFIF)
TINY_JPEG = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n"
    b"\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d"
    b"\x1a\x1c\x1c $.\' \",#\x1c\x1c(7),01444\x1f\'9=82<.342\xff\xc0\x00"
    b"\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01"
    b"\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02"
    b"\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\x00\xb5\x10\x00\x02\x01\x03"
    b"\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01}\x01\x02\x03\x00\x04\x11"
    b"\x05\x12!1A\x06\x13Qa\x07\"q\x142\x81\x91\xa1\x08#B\xb1\xc1\x15R\xd1"
    b"\xf0$3br\x82\t\n\x16\x17\x18\x19\x1a%&\'()*456789:CDEFGHIJSTUVWXYZcd"
    b"efghijstuvwxyz\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96"
    b"\x97\x98\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5"
    b"\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3"
    b"\xd4\xd5\xd6\xd7\xd8\xd9\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea"
    b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xda\x00\x08\x01\x01\x00"
    b"\x00?\x00\xfb\xd2\x8a+\xff\xd9"
)
TINY_JPEG_B64 = base64.b64encode(TINY_JPEG).decode("ascii")


# =============================================================================
# Health endpoint (no auth required)
# =============================================================================


class TestHealth:
    def test_health_ok(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"
        assert "c2pa_available" in data

    def test_health_no_auth_needed(self):
        """Health should work without any auth header."""
        resp = client.get("/health")
        assert resp.status_code == 200


# =============================================================================
# Auth rejection
# =============================================================================


class TestAuth:
    def test_sign_no_auth(self):
        resp = client.post("/sign", json={"image_base64": TINY_JPEG_B64, "did": "did:test:1", "display_name": "Test"})
        assert resp.status_code == 401

    def test_sign_bad_auth(self):
        resp = client.post(
            "/sign",
            json={"image_base64": TINY_JPEG_B64, "did": "did:test:1", "display_name": "Test"},
            headers=BAD_AUTH,
        )
        assert resp.status_code == 403

    def test_verify_no_auth(self):
        resp = client.post("/verify", json={"image_base64": TINY_JPEG_B64})
        assert resp.status_code == 401

    def test_verify_bad_auth(self):
        resp = client.post("/verify", json={"image_base64": TINY_JPEG_B64}, headers=BAD_AUTH)
        assert resp.status_code == 403


# =============================================================================
# Sign endpoint
# =============================================================================


class TestSign:
    def test_sign_invalid_base64(self):
        resp = client.post(
            "/sign",
            json={"image_base64": "not-valid-base64!!!", "did": "did:test:1", "display_name": "Test"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "base64" in data["error"].lower() or "invalid" in data["error"].lower()

    def test_sign_too_small(self):
        tiny = base64.b64encode(b"abc").decode()
        resp = client.post(
            "/sign",
            json={"image_base64": tiny, "did": "did:test:1", "display_name": "Test"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "small" in data["error"].lower()

    def test_sign_valid_image(self):
        """If C2PA is available, signing should succeed."""
        try:
            from vouch.media.c2pa import C2PA_AVAILABLE
        except (ImportError, SyntaxError):
            C2PA_AVAILABLE = False

        if not C2PA_AVAILABLE:
            pytest.skip("c2pa-python not available")

        # Create a real small PNG using Pillow
        try:
            from PIL import Image
            import io

            img = Image.new("RGB", (100, 100), color="red")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            png_b64 = base64.b64encode(buf.getvalue()).decode()
        except ImportError:
            pytest.skip("Pillow not available")

        resp = client.post(
            "/sign",
            json={
                "image_base64": png_b64,
                "did": "did:key:z6MkTest123",
                "display_name": "Test Signer",
                "credential_type": "FREE",
                "shortlink_domain": "https://example.com",
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["signed_image_base64"] is not None
        assert data["manifest_hash"] is not None
        assert data["timestamp"] is not None

    def test_sign_custom_shortlink_domain(self):
        """Shortlink domain override should propagate to verify_url."""
        try:
            from vouch.media.c2pa import C2PA_AVAILABLE
            from PIL import Image
        except (ImportError, SyntaxError):
            pytest.skip("c2pa-python or Pillow not available")

        if not C2PA_AVAILABLE:
            pytest.skip("c2pa-python not available")

        import io

        img = Image.new("RGB", (100, 100), color="blue")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_b64 = base64.b64encode(buf.getvalue()).decode()

        resp = client.post(
            "/sign",
            json={
                "image_base64": png_b64,
                "did": "did:key:z6MkTest456",
                "display_name": "Test User",
                "shortlink_domain": "https://example.com",
            },
            headers=AUTH_HEADER,
        )
        data = resp.json()
        if data["success"] and data["verify_url"]:
            assert "example.com" in data["verify_url"]


# =============================================================================
# Verify endpoint
# =============================================================================


class TestVerify:
    def test_verify_unsigned_image(self):
        """An unsigned image should not validate."""
        try:
            from vouch.media.c2pa import C2PA_AVAILABLE
        except (ImportError, SyntaxError):
            C2PA_AVAILABLE = False

        if not C2PA_AVAILABLE:
            pytest.skip("c2pa-python not available")

        try:
            from PIL import Image
            import io

            img = Image.new("RGB", (50, 50), color="green")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            png_b64 = base64.b64encode(buf.getvalue()).decode()
        except ImportError:
            pytest.skip("Pillow not available")

        resp = client.post(
            "/verify",
            json={"image_base64": png_b64},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_valid"] is False
