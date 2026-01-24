"""
Test Suite for Vouch Python SDK

Tests cover:
- VouchClient (synchronous)
- AsyncVouchClient (asynchronous)
- All SDK methods
- Error handling
- CLI commands
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from pathlib import Path
import json


# ============================================================================
# VouchClient Tests (Synchronous)
# ============================================================================

class TestVouchClient:
    """Tests for the synchronous VouchClient."""
    
    def test_client_initialization_default_url(self):
        """Client should use default daemon URL."""
        from vouch_sdk import VouchClient, DEFAULT_DAEMON_URL
        
        client = VouchClient()
        assert client.daemon_url == DEFAULT_DAEMON_URL
    
    def test_client_initialization_custom_url(self):
        """Client should accept custom daemon URL."""
        from vouch_sdk import VouchClient
        
        custom_url = "http://localhost:9999"
        client = VouchClient(daemon_url=custom_url)
        assert client.daemon_url == custom_url
    
    def test_connect_success(self):
        """Connect should return daemon status when online."""
        from vouch_sdk import VouchClient, DaemonStatus
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "ok",
            "version": "1.1.0",
            "has_keys": True,
        }
        
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.get.return_value = mock_response
            
            client = VouchClient()
            status = client.connect()
        
        assert status["status"] == "ok"
        assert status["version"] == "1.1.0"
    
    def test_connect_raises_connection_error(self):
        """Connect should raise VouchConnectionError when daemon is offline."""
        from vouch_sdk import VouchClient, VouchConnectionError
        import httpx
        
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.get.side_effect = httpx.ConnectError("Connection refused")
            
            client = VouchClient()
            with pytest.raises(VouchConnectionError) as exc_info:
                client.connect()
            
            assert "not running" in str(exc_info.value).lower() or "connection" in str(exc_info.value).lower()
    
    def test_sign_text_success(self):
        """Sign should return signature for text content."""
        from vouch_sdk import VouchClient
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "signature": "base64signature==",
            "timestamp": "2026-01-20T06:00:00Z",
            "public_key": "base64pubkey==",
            "did": "did:key:z123",
        }
        
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.post.return_value = mock_response
            
            client = VouchClient()
            result = client.sign("Hello, World!", origin="test")
        
        assert result["signature"] == "base64signature=="
        assert "timestamp" in result
    
    def test_sign_raises_no_keys_error(self):
        """Sign should raise NoKeysConfiguredError when daemon has no keys."""
        from vouch_sdk import VouchClient, NoKeysConfiguredError
        
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"detail": "No keys configured"}
        
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.post.return_value = mock_response
            
            client = VouchClient()
            with pytest.raises(NoKeysConfiguredError):
                client.sign("Hello", origin="test")
    
    def test_sign_raises_user_denied_error(self):
        """Sign should raise UserDeniedSignatureError when user denies consent."""
        from vouch_sdk import VouchClient, UserDeniedSignatureError
        
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {"detail": "User denied signature"}
        
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.post.return_value = mock_response
            
            client = VouchClient()
            with pytest.raises(UserDeniedSignatureError):
                client.sign("Hello", origin="test")
    
    def test_get_public_key_success(self):
        """GetPublicKey should return key info."""
        from vouch_sdk import VouchClient
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "public_key": "abcd1234",
            "did": "did:key:z123",
            "fingerprint": "SHA256:abcd",
        }
        
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.get.return_value = mock_response
            
            client = VouchClient()
            result = client.get_public_key()
        
        assert result["did"].startswith("did:key:")
        assert "fingerprint" in result


# ============================================================================
# AsyncVouchClient Tests
# ============================================================================

class TestAsyncVouchClient:
    """Tests for the asynchronous AsyncVouchClient."""
    
    @pytest.mark.asyncio
    async def test_async_client_initialization(self):
        """Async client should initialize properly."""
        from vouch_sdk import AsyncVouchClient, DEFAULT_DAEMON_URL
        
        client = AsyncVouchClient()
        assert client.daemon_url == DEFAULT_DAEMON_URL
    
    @pytest.mark.asyncio
    async def test_async_connect_success(self):
        """Async connect should return daemon status."""
        from vouch_sdk import AsyncVouchClient
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "ok",
            "version": "1.1.0",
        }
        
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            MockClient.return_value.__aenter__.return_value = mock_client
            
            client = AsyncVouchClient()
            status = await client.connect()
        
        assert status["status"] == "ok"
    
    @pytest.mark.asyncio
    async def test_async_sign_success(self):
        """Async sign should work properly."""
        from vouch_sdk import AsyncVouchClient
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "signature": "async_signature==",
            "timestamp": "2026-01-20T06:00:00Z",
        }
        
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            MockClient.return_value.__aenter__.return_value = mock_client
            
            client = AsyncVouchClient()
            result = await client.sign("Async content", origin="test")
        
        assert result["signature"] == "async_signature=="


# ============================================================================
# File Signing Tests
# ============================================================================

class TestFileSigning:
    """Tests for sign_file and sign_bytes methods."""
    
    def test_sign_file_success(self, tmp_path):
        """sign_file should send file to daemon."""
        from vouch_sdk import VouchClient
        
        # Create a test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("Test file content")
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"Signed file content"
        
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.post.return_value = mock_response
            
            client = VouchClient()
            result = client.sign_file(str(test_file), origin="test")
        
        assert result == b"Signed file content"
    
    def test_sign_file_not_found(self, tmp_path):
        """sign_file should raise error for missing file."""
        from vouch_sdk import VouchClient
        
        client = VouchClient()
        
        with pytest.raises(FileNotFoundError):
            client.sign_file(str(tmp_path / "nonexistent.txt"), origin="test")
    
    def test_sign_bytes_success(self):
        """sign_bytes should send binary data to daemon."""
        from vouch_sdk import VouchClient
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"Signed bytes"
        
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.post.return_value = mock_response
            
            client = VouchClient()
            result = client.sign_bytes(b"Binary data", filename="test.bin", origin="test")
        
        assert result == b"Signed bytes"


# ============================================================================
# Error Classes Tests
# ============================================================================

class TestErrorClasses:
    """Tests for custom exception classes."""
    
    def test_vouch_error_is_base_exception(self):
        """VouchError should be catchable."""
        from vouch_sdk import VouchError
        
        with pytest.raises(VouchError):
            raise VouchError("Test error")
    
    def test_connection_error_inherits_vouch_error(self):
        """VouchConnectionError should inherit from VouchError."""
        from vouch_sdk import VouchError, VouchConnectionError
        
        with pytest.raises(VouchError):
            raise VouchConnectionError("Connection failed")
    
    def test_user_denied_error_inherits_vouch_error(self):
        """UserDeniedSignatureError should inherit from VouchError."""
        from vouch_sdk import VouchError, UserDeniedSignatureError
        
        with pytest.raises(VouchError):
            raise UserDeniedSignatureError("User denied")
    
    def test_no_keys_error_inherits_vouch_error(self):
        """NoKeysConfiguredError should inherit from VouchError."""
        from vouch_sdk import VouchError, NoKeysConfiguredError
        
        with pytest.raises(VouchError):
            raise NoKeysConfiguredError("No keys")


# ============================================================================
# Data Classes Tests
# ============================================================================

class TestDataClasses:
    """Tests for data transfer objects."""
    
    def test_daemon_status_fields(self):
        """DaemonStatus should have expected fields."""
        from vouch_sdk import DaemonStatus
        
        status = DaemonStatus(
            status="ok",
            version="1.0.0",
            has_keys=True,
            uptime=3600,
        )
        
        assert status.status == "ok"
        assert status.version == "1.0.0"
        assert status.has_keys == True
    
    def test_sign_result_fields(self):
        """SignResult should have expected fields."""
        from vouch_sdk import SignResult
        
        result = SignResult(
            signature="base64sig==",
            timestamp="2026-01-20T06:00:00Z",
            public_key="pubkey",
            did="did:key:z123",
        )
        
        assert result.signature == "base64sig=="
        assert result.did.startswith("did:key:")
    
    def test_public_key_info_fields(self):
        """PublicKeyInfo should have expected fields."""
        from vouch_sdk import PublicKeyInfo
        
        info = PublicKeyInfo(
            public_key="abcd1234",
            did="did:key:z123",
            fingerprint="SHA256:abcd",
        )
        
        assert info.fingerprint.startswith("SHA256:")


# ============================================================================
# CLI Tests
# ============================================================================

class TestCLI:
    """Tests for the vouch CLI commands."""
    
    def test_cli_app_exists(self):
        """CLI app should be importable."""
        from vouch_sdk.cli import app
        assert app is not None
    
    def test_status_command_online(self):
        """Status command should show online when daemon is running."""
        from typer.testing import CliRunner
        from vouch_sdk.cli import app
        
        runner = CliRunner()
        
        with patch("vouch_sdk.cli.VouchClient") as MockClient:
            mock_client = MagicMock()
            mock_client.connect.return_value = {"status": "ok", "version": "1.0.0"}
            mock_client.get_public_key.return_value = {
                "did": "did:key:z123",
                "fingerprint": "SHA256:abcd",
            }
            MockClient.return_value = mock_client
            
            result = runner.invoke(app, ["status"])
        
        assert result.exit_code == 0
        assert "Online" in result.stdout or "ok" in result.stdout.lower()
    
    def test_status_command_offline(self):
        """Status command should show offline when daemon is not running."""
        from typer.testing import CliRunner
        from vouch_sdk.cli import app
        from vouch_sdk import VouchConnectionError
        
        runner = CliRunner()
        
        with patch("vouch_sdk.cli.VouchClient") as MockClient:
            mock_client = MagicMock()
            mock_client.connect.side_effect = VouchConnectionError("Not running")
            MockClient.return_value = mock_client
            
            result = runner.invoke(app, ["status"])
        
        assert result.exit_code != 0 or "Offline" in result.stdout or "not running" in result.stdout.lower()
    
    def test_version_command(self):
        """Version command should show version."""
        from typer.testing import CliRunner
        from vouch_sdk.cli import app
        
        runner = CliRunner()
        result = runner.invoke(app, ["version"])
        
        assert result.exit_code == 0
        assert "1.0.0" in result.stdout or "vouch" in result.stdout.lower()
    
    def test_sign_command_requires_file(self):
        """Sign command should require a file argument."""
        from typer.testing import CliRunner
        from vouch_sdk.cli import app
        
        runner = CliRunner()
        result = runner.invoke(app, ["sign"])
        
        # Should show missing argument error
        assert result.exit_code != 0
    
    def test_verify_requires_c2pa(self):
        """Verify command should handle missing c2pa gracefully."""
        from typer.testing import CliRunner
        from vouch_sdk.cli import app
        
        runner = CliRunner()
        
        # Create a temp file
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test content")
            temp_path = f.name
        
        try:
            result = runner.invoke(app, ["verify", temp_path])
            # Should either work or gracefully report no manifest/no c2pa
            assert result.exit_code in [0, 1]  # 0 for "no manifest", 1 for error
        finally:
            import os
            os.unlink(temp_path)


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests (require running daemon)."""
    
    @pytest.mark.skip(reason="Requires running daemon")
    def test_full_sign_verify_cycle(self, tmp_path):
        """Full cycle: connect -> sign -> verify (manual test)."""
        from vouch_sdk import VouchClient
        
        client = VouchClient()
        
        # Connect
        status = client.connect()
        assert status["status"] == "ok"
        
        # Sign text
        result = client.sign("Integration test content", origin="pytest")
        assert "signature" in result
        
        # Sign file
        test_file = tmp_path / "test.txt"
        test_file.write_text("File content for integration test")
        
        signed = client.sign_file(str(test_file), origin="pytest")
        assert len(signed) > 0
