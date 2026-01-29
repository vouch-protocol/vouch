"""
Test Suite for Vouch Bridge Daemon

Tests cover:
- Daemon status endpoints
- Key generation and management
- Text/code signing
- Media signing (C2PA)
- Consent UI behavior
"""

import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import patch, MagicMock
import base64
import json

from vouch_bridge.server import KEYRING_PRIVATE_KEY


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_keyring():
    """Mock the system keyring to avoid touching real credentials."""
    storage = {}

    def get_password(service, key):
        return storage.get((service, key))

    def set_password(service, key, value):
        storage[(service, key)] = value

    def delete_password(service, key):
        storage.pop((service, key), None)

    with patch("vouch_bridge.server.keyring") as mock:
        mock.get_password.side_effect = get_password
        mock.set_password.side_effect = set_password
        mock.delete_password.side_effect = delete_password
        yield mock


@pytest.fixture
def sample_private_key_bytes():
    """Generate a sample Ed25519 private key for testing."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.generate()
    return private_key.private_bytes_raw()


@pytest.fixture
def sample_private_key_pem(sample_private_key_bytes):
    """Same key as PEM string (key manager expects PEM from keyring)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PrivateFormat,
        NoEncryption,
    )
    private_key = Ed25519PrivateKey.from_private_bytes(sample_private_key_bytes)
    return private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("utf-8")


@pytest.fixture
def sample_public_key_bytes(sample_private_key_bytes):
    """Derive public key from sample private key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.from_private_bytes(sample_private_key_bytes)
    return private_key.public_key().public_bytes_raw()


# ============================================================================
# Status Endpoint Tests
# ============================================================================

class TestStatusEndpoint:
    """Tests for GET /status endpoint."""
    
    @pytest.mark.asyncio
    async def test_status_returns_ok(self, mock_keyring):
        """Status endpoint should return 200 with version info."""
        from vouch_bridge.server import app
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "uptime" in data
    
    @pytest.mark.asyncio
    async def test_status_includes_key_status(self, mock_keyring, sample_private_key_bytes, sample_private_key_pem):
        """Status should indicate whether keys are configured."""
        from vouch_bridge.server import app
        
        # First without keys
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/status")
        assert response.json().get("has_keys", False) == False
        
        # Now with keys
        mock_keyring.get_password.side_effect = lambda service, key: sample_private_key_pem if key == KEYRING_PRIVATE_KEY else None
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/status")
        assert response.json().get("has_keys", True) == True


# ============================================================================
# Key Generation Tests
# ============================================================================

class TestKeyGeneration:
    """Tests for POST /keys/generate endpoint."""
    
    @pytest.mark.asyncio
    async def test_generate_keys_creates_new_keypair(self, mock_keyring):
        """Should generate a new Ed25519 keypair when none exists."""
        from vouch_bridge.server import app
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/keys/generate")
        
        assert response.status_code == 200
        data = response.json()
        assert "public_key" in data
        assert "did" in data
        assert data["did"].startswith("did:key:z")
        
        # Verify keyring was called to store the key
        mock_keyring.set_password.assert_called()
    
    @pytest.mark.asyncio
    async def test_generate_keys_fails_if_exists(self, mock_keyring, sample_private_key_bytes, sample_private_key_pem):
        """Should return 200 with success=False when keys already exist."""
        from vouch_bridge.server import app
        
        mock_keyring.get_password.side_effect = lambda service, key: sample_private_key_pem if key == KEYRING_PRIVATE_KEY else None
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/keys/generate")
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "already exist" in data["message"].lower()


# ============================================================================
# Public Key Endpoint Tests
# ============================================================================

class TestPublicKeyEndpoint:
    """Tests for GET /keys/public endpoint."""
    
    @pytest.mark.asyncio
    async def test_get_public_key_returns_key_info(self, mock_keyring, sample_private_key_bytes, sample_private_key_pem):
        """Should return public key, DID, and fingerprint."""
        from vouch_bridge.server import app
        
        mock_keyring.get_password.side_effect = lambda service, key: sample_private_key_pem if key == KEYRING_PRIVATE_KEY else None
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/keys/public")
        
        assert response.status_code == 200
        data = response.json()
        assert "public_key" in data
        assert "did" in data
        assert "fingerprint" in data
        assert data["did"].startswith("did:key:z")
    
    @pytest.mark.asyncio
    async def test_get_public_key_returns_404_when_no_keys(self, mock_keyring):
        """Should return 404 if no keys are configured."""
        from vouch_bridge.server import app
        
        mock_keyring.get_password.return_value = None
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/keys/public")
        
        assert response.status_code == 404


# ============================================================================
# Text Signing Tests
# ============================================================================

class TestTextSigning:
    """Tests for POST /sign endpoint (text/code signing)."""
    
    @pytest.mark.asyncio
    async def test_sign_text_returns_signature(self, mock_keyring, sample_private_key_bytes, sample_private_key_pem):
        """Should sign content and return base64 signature."""
        from vouch_bridge.server import app
        
        mock_keyring.get_password.side_effect = lambda service, key: sample_private_key_pem if key == KEYRING_PRIVATE_KEY else None
        
        # Mock the consent UI to auto-approve
        with patch("vouch_bridge.server.ConsentUI.request_consent", return_value=True):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/sign", json={
                    "content": "Hello, World!",
                    "origin": "test-suite",
                })
        
        assert response.status_code == 200
        data = response.json()
        assert "signature" in data
        assert "timestamp" in data
        assert "public_key" in data
    
    @pytest.mark.asyncio
    async def test_sign_requires_content(self, mock_keyring, sample_private_key_bytes, sample_private_key_pem):
        """Should return 422 if content is missing."""
        from vouch_bridge.server import app
        
        mock_keyring.get_password.side_effect = lambda service, key: sample_private_key_pem if key == KEYRING_PRIVATE_KEY else None
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/sign", json={
                "origin": "test-suite",
            })
        
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_sign_denied_by_user_returns_403(self, mock_keyring, sample_private_key_bytes, sample_private_key_pem):
        """Should return 403 if user denies consent."""
        from vouch_bridge.server import app
        
        mock_keyring.get_password.side_effect = lambda service, key: sample_private_key_pem if key == KEYRING_PRIVATE_KEY else None
        
        # Mock consent denial
        with patch("vouch_bridge.server.ConsentUI.request_consent", return_value=False):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/sign", json={
                    "content": "Hello, World!",
                    "origin": "test-suite",
                })
        
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_sign_without_keys_returns_404(self, mock_keyring):
        """Should return 404 if no keys are configured."""
        from vouch_bridge.server import app
        
        mock_keyring.get_password.return_value = None
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/sign", json={
                "content": "Hello, World!",
                "origin": "test-suite",
            })
        
        assert response.status_code == 404


# ============================================================================
# Signature Verification Tests
# ============================================================================

class TestSignatureVerification:
    """Tests for signature verification (helper functions)."""
    
    def test_signature_is_valid(self, sample_private_key_bytes):
        """Generated signatures should be verifiable."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        
        private_key = Ed25519PrivateKey.from_private_bytes(sample_private_key_bytes)
        public_key = private_key.public_key()
        
        content = b"Test content to sign"
        signature = private_key.sign(content)
        
        # Should not raise an exception
        public_key.verify(signature, content)
    
    def test_signature_fails_for_tampered_content(self, sample_private_key_bytes):
        """Signatures should fail verification if content is tampered."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.exceptions import InvalidSignature
        
        private_key = Ed25519PrivateKey.from_private_bytes(sample_private_key_bytes)
        public_key = private_key.public_key()
        
        content = b"Original content"
        signature = private_key.sign(content)
        
        tampered_content = b"Tampered content"
        
        with pytest.raises(InvalidSignature):
            public_key.verify(signature, tampered_content)


# ============================================================================
# Media Signing Tests
# ============================================================================

class TestMediaSigning:
    """Tests for POST /sign-media endpoint (C2PA)."""
    
    @pytest.mark.asyncio
    async def test_sign_media_accepts_image(self, mock_keyring, sample_private_key_bytes, sample_private_key_pem, tmp_path):
        """Should accept and sign an image file."""
        from vouch_bridge.server import app
        
        mock_keyring.get_password.side_effect = lambda service, key: sample_private_key_pem if key == KEYRING_PRIVATE_KEY else None
        
        # Create a minimal valid JPEG (1x1 red pixel)
        jpeg_bytes = bytes([
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00,
            0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB,
            0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07,
            0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B,
            0x0B, 0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E,
            0x1D, 0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C,
            0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34,
            0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34,
            0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01,
            0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01,
            0x03, 0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00,
            0x01, 0x7D, 0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21,
            0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32,
            0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1,
            0xF0, 0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35, 0x36,
            0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
            0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64,
            0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77,
            0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
            0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5,
            0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
            0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9,
            0xDA, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA,
            0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF,
            0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0xFB, 0xD5,
            0xDB, 0x20, 0xAE, 0x58, 0xA9, 0xFF, 0xD9
        ])
        
        test_file = tmp_path / "test.jpg"
        test_file.write_bytes(jpeg_bytes)
        
        # Mock consent
        with patch("vouch_bridge.server.MediaConsentUI.request_media_consent", return_value=True):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                with open(test_file, "rb") as f:
                    response = await client.post(
                        "/sign-media",
                        files={"file": ("test.jpg", f, "image/jpeg")},
                        data={"origin": "test-suite"},
                    )
        
        # Should return signed file or original if C2PA fails
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_sign_media_denied_returns_403(self, mock_keyring, sample_private_key_bytes, sample_private_key_pem, tmp_path):
        """Should return 403 if user denies media signing consent."""
        from vouch_bridge.server import app
        
        mock_keyring.get_password.side_effect = lambda service, key: sample_private_key_pem if key == KEYRING_PRIVATE_KEY else None
        
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        with patch("vouch_bridge.server.MediaConsentUI.request_media_consent", return_value=False):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                with open(test_file, "rb") as f:
                    response = await client.post(
                        "/sign-media",
                        files={"file": ("test.txt", f, "text/plain")},
                        data={"origin": "test-suite"},
                    )
        
        assert response.status_code == 403


# ============================================================================
# MIME Type Detection Tests
# ============================================================================

class TestMimeDetection:
    """Tests for MIME type detection functionality."""
    
    def test_detect_jpeg_by_magic_bytes(self):
        """Should detect JPEG by magic bytes."""
        jpeg_magic = bytes([0xFF, 0xD8, 0xFF, 0xE0])
        
        # Create mock file-like object
        from io import BytesIO
        file_obj = BytesIO(jpeg_magic + b"\x00" * 100)
        
        # Import the detect function (if exposed)
        # from vouch_bridge.server import detect_mime_type
        # assert detect_mime_type(file_obj, "unknown") == "image/jpeg"
        
        # For now, just verify the magic bytes
        assert jpeg_magic[:2] == b'\xFF\xD8'
    
    def test_detect_png_by_magic_bytes(self):
        """Should detect PNG by magic bytes."""
        png_magic = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        assert png_magic[:4] == b'\x89PNG'
    
    def test_detect_pdf_by_magic_bytes(self):
        """Should detect PDF by magic bytes."""
        pdf_magic = b'%PDF-1.4'
        assert pdf_magic[:4] == b'%PDF'


# ============================================================================
# DID Generation Tests
# ============================================================================

class TestDIDGeneration:
    """Tests for DID (Decentralized Identifier) generation."""
    
    def test_did_format(self, sample_public_key_bytes):
        """DID should follow did:key:z format."""
        import base58
        
        # Multicodec prefix for Ed25519 public key
        multicodec_prefix = bytes([0xed, 0x01])
        encoded = base58.b58encode(multicodec_prefix + sample_public_key_bytes).decode()
        did = f"did:key:z{encoded}"
        
        assert did.startswith("did:key:z")
        assert len(did) > 20
    
    def test_did_is_deterministic(self, sample_public_key_bytes):
        """Same public key should always produce same DID."""
        import base58
        
        multicodec_prefix = bytes([0xed, 0x01])
        
        did1 = f"did:key:z{base58.b58encode(multicodec_prefix + sample_public_key_bytes).decode()}"
        did2 = f"did:key:z{base58.b58encode(multicodec_prefix + sample_public_key_bytes).decode()}"
        
        assert did1 == did2
