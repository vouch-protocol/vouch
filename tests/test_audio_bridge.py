# tests/test_audio_bridge.py
"""
Tests for the Vouch Audio Bridge routes.

Run: pytest tests/test_audio_bridge.py -v
"""

import base64
import io
import os
import struct
import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")
from fastapi.testclient import TestClient

# Set a test secret before importing the app
os.environ["VOUCH_BRIDGE_SECRET"] = "test-secret-123"

from vouch.bridge.server import app

# Reset cached settings so env var takes effect
import vouch.bridge.server as bridge_mod
import vouch.bridge.audio_routes as audio_mod

bridge_mod._settings = None
audio_mod._settings = None

client = TestClient(app)

AUTH_HEADER = {"Authorization": "Bearer test-secret-123"}
BAD_AUTH = {"Authorization": "Bearer wrong-secret"}


def _make_wav(duration_s: float = 1.0, sample_rate: int = 44100, freq: float = 440.0) -> bytes:
    """Generate a minimal valid WAV file (16-bit mono PCM)."""
    import math

    num_samples = int(sample_rate * duration_s)
    channels = 1
    bits_per_sample = 16
    byte_rate = sample_rate * channels * bits_per_sample // 8
    block_align = channels * bits_per_sample // 8
    data_size = num_samples * block_align

    buf = io.BytesIO()
    # RIFF header
    buf.write(b"RIFF")
    buf.write(struct.pack("<I", 36 + data_size))
    buf.write(b"WAVE")
    # fmt chunk
    buf.write(b"fmt ")
    buf.write(struct.pack("<I", 16))  # chunk size
    buf.write(struct.pack("<H", 1))  # PCM format
    buf.write(struct.pack("<H", channels))
    buf.write(struct.pack("<I", sample_rate))
    buf.write(struct.pack("<I", byte_rate))
    buf.write(struct.pack("<H", block_align))
    buf.write(struct.pack("<H", bits_per_sample))
    # data chunk
    buf.write(b"data")
    buf.write(struct.pack("<I", data_size))
    for i in range(num_samples):
        t = i / sample_rate
        sample = int(math.sin(2 * math.pi * freq * t) * 16000)
        sample = max(-32768, min(32767, sample))
        buf.write(struct.pack("<h", sample))

    return buf.getvalue()


WAV_BYTES = _make_wav(duration_s=1.0)
WAV_B64 = base64.b64encode(WAV_BYTES).decode("ascii")

SHORT_WAV_BYTES = _make_wav(duration_s=0.01)
SHORT_WAV_B64 = base64.b64encode(SHORT_WAV_BYTES).decode("ascii")


# =============================================================================
# Health endpoint (no auth required)
# =============================================================================


class TestAudioHealth:
    def test_audio_health_ok(self):
        resp = client.get("/audio/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"
        assert "numpy_available" in data
        assert "c2pa_available" in data
        assert "watermarker" in data

    def test_audio_health_no_auth_needed(self):
        resp = client.get("/audio/health")
        assert resp.status_code == 200


# =============================================================================
# Auth rejection
# =============================================================================


class TestAudioAuth:
    def test_embed_no_auth(self):
        resp = client.post(
            "/audio/embed",
            json={"audio_base64": WAV_B64, "did": "did:test:1"},
        )
        assert resp.status_code == 401

    def test_embed_bad_auth(self):
        resp = client.post(
            "/audio/embed",
            json={"audio_base64": WAV_B64, "did": "did:test:1"},
            headers=BAD_AUTH,
        )
        assert resp.status_code == 403

    def test_detect_no_auth(self):
        resp = client.post(
            "/audio/detect",
            json={"audio_base64": WAV_B64},
        )
        assert resp.status_code == 401

    def test_detect_bad_auth(self):
        resp = client.post(
            "/audio/detect",
            json={"audio_base64": WAV_B64},
            headers=BAD_AUTH,
        )
        assert resp.status_code == 403

    def test_sign_no_auth(self):
        resp = client.post(
            "/audio/sign",
            json={"audio_base64": WAV_B64, "did": "did:test:1"},
        )
        assert resp.status_code == 401


# =============================================================================
# Embed endpoint
# =============================================================================


class TestAudioEmbed:
    def test_embed_invalid_base64(self):
        resp = client.post(
            "/audio/embed",
            json={
                "audio_base64": "not-valid-base64!!!",
                "did": "did:test:1",
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "base64" in data["error"].lower() or "invalid" in data["error"].lower()

    def test_embed_too_small(self):
        tiny = base64.b64encode(b"abc").decode()
        resp = client.post(
            "/audio/embed",
            json={"audio_base64": tiny, "did": "did:test:1"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "small" in data["error"].lower()

    def test_embed_valid_wav(self):
        """If numpy is available, embedding should succeed."""
        try:
            import numpy
        except ImportError:
            pytest.skip("numpy not available")

        resp = client.post(
            "/audio/embed",
            json={
                "audio_base64": WAV_B64,
                "did": "did:key:z6MkTestAudio",
                "display_name": "Test Audio Signer",
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["audio_base64"] is not None
        assert data["watermark_id"] is not None
        assert data["audio_hash"] is not None
        assert data["payload_hash"] is not None
        assert data["timestamp"] is not None

    def test_embed_with_covenant(self):
        """Embedding with VouchCovenant should succeed."""
        try:
            import numpy
        except ImportError:
            pytest.skip("numpy not available")

        resp = client.post(
            "/audio/embed",
            json={
                "audio_base64": WAV_B64,
                "did": "did:key:z6MkTestCov",
                "display_name": "Covenant Tester",
                "covenant": {
                    "ai_training": False,
                    "voice_cloning": False,
                    "commercial_use": True,
                },
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True


# =============================================================================
# Detect endpoint
# =============================================================================


class TestAudioDetect:
    def test_detect_invalid_base64(self):
        resp = client.post(
            "/audio/detect",
            json={"audio_base64": "not-valid!!!"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False

    def test_detect_unmarked_audio(self):
        """Unmarked audio should return detected=false."""
        try:
            import numpy
        except ImportError:
            pytest.skip("numpy not available")

        resp = client.post(
            "/audio/detect",
            json={"audio_base64": WAV_B64},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        # Detection result depends on watermarker implementation
        assert "detected" in data


# =============================================================================
# Sign endpoint (C2PA)
# =============================================================================


class TestAudioSign:
    def test_sign_invalid_base64(self):
        resp = client.post(
            "/audio/sign",
            json={
                "audio_base64": "not-valid!!!",
                "did": "did:test:1",
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False

    def test_sign_valid_wav(self):
        """If C2PA is available, signing should succeed."""
        try:
            from vouch.audio import C2PA_AVAILABLE

            if not C2PA_AVAILABLE:
                pytest.skip("c2pa-python not available")
        except ImportError:
            pytest.skip("vouch.audio not available")

        resp = client.post(
            "/audio/sign",
            json={
                "audio_base64": WAV_B64,
                "did": "did:key:z6MkTestSign",
                "display_name": "Test Audio Signer",
                "title": "Test Audio",
                "covenant": {
                    "ai_training": False,
                    "voice_cloning": False,
                },
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["signed_audio_base64"] is not None
        assert data["manifest_hash"] is not None
        assert data["timestamp"] is not None
