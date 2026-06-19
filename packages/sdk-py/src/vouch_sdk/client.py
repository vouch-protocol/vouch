"""
Vouch SDK for Python

Official Python client library for the Vouch Protocol.
Provides both synchronous (VouchClient) and asynchronous (AsyncVouchClient)
clients for communicating with the Vouch Bridge Daemon.

Author: Ramprasad Anandam Gaddam
License: MIT
"""

from __future__ import annotations

import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

import httpx


# =============================================================================
# Configuration
# =============================================================================

DEFAULT_DAEMON_URL = "http://127.0.0.1:21000"
DEFAULT_TIMEOUT = 5.0  # seconds
DEFAULT_REQUEST_TIMEOUT = 120.0  # seconds for media signing


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class DaemonStatus:
    """Response from /status endpoint."""

    status: str
    version: str
    has_keys: bool
    public_key_fingerprint: str | None


@dataclass
class PublicKeyInfo:
    """Response from /keys/public endpoint."""

    public_key: str
    did: str
    fingerprint: str


@dataclass
class SignResult:
    """Response from /sign endpoint."""

    signature: str
    public_key: str
    did: str
    timestamp: str
    content_hash: str


@dataclass
class MediaSignResult:
    """Response from /sign-media endpoint."""

    data: bytes
    did: str
    timestamp: str
    hash: str
    filename: str
    mime_type: str


# =============================================================================
# Exceptions
# =============================================================================


class VouchError(Exception):
    """Base exception for Vouch SDK errors."""

    pass


class VouchConnectionError(VouchError):
    """Raised when the daemon is not available or connection fails."""

    def __init__(self, message: str = "Vouch Daemon is not available"):
        super().__init__(message)


class UserDeniedSignatureError(VouchError):
    """Raised when the user denies the signature request via consent popup."""

    def __init__(self, message: str = "User denied the signature request"):
        super().__init__(message)


class NoKeysConfiguredError(VouchError):
    """Raised when no keys are configured in the daemon."""

    def __init__(
        self, message: str = "No keys configured. Call /keys/generate first."
    ):
        super().__init__(message)


# =============================================================================
# Synchronous Client
# =============================================================================


class VouchClient:
    """
    Synchronous client for the Vouch Bridge Daemon.

    Example:
        ```python
        from vouch_sdk import VouchClient

        client = VouchClient()

        if client.connect():
            result = client.sign("Hello, World!", origin="my-app")
            print(f"Signature: {result.signature}")
        ```
    """

    def __init__(
        self,
        daemon_url: str = DEFAULT_DAEMON_URL,
        timeout: float = DEFAULT_TIMEOUT,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ):
        """
        Initialize the Vouch client.

        Args:
            daemon_url: URL of the Vouch daemon (default: http://127.0.0.1:21000)
            timeout: Connection timeout in seconds (default: 5.0)
            request_timeout: Request timeout for media signing (default: 120.0)
        """
        self.daemon_url = daemon_url.rstrip("/")
        self.timeout = timeout
        self.request_timeout = request_timeout
        self._is_connected = False
        self._daemon_status: DaemonStatus | None = None
        self._client = httpx.Client(timeout=httpx.Timeout(timeout))

    @property
    def is_connected(self) -> bool:
        """Whether the client is connected to the daemon."""
        return self._is_connected

    @property
    def daemon_status(self) -> DaemonStatus | None:
        """Last known daemon status."""
        return self._daemon_status

    def connect(self) -> bool:
        """
        Connect to the Vouch Daemon.

        Attempts to connect to http://127.0.0.1:21000/status.
        Sets is_connected based on success.

        Returns:
            True if connected, False if connection failed.
        """
        try:
            response = self._client.get(
                f"{self.daemon_url}/status",
                timeout=self.timeout,
            )

            if response.status_code != 200:
                self._is_connected = False
                return False

            data = response.json()

            if data.get("status") == "ok":
                self._is_connected = True
                self._daemon_status = DaemonStatus(
                    status=data.get("status", ""),
                    version=data.get("version", ""),
                    has_keys=data.get("has_keys", False),
                    public_key_fingerprint=data.get("public_key_fingerprint"),
                )
                return True

            self._is_connected = False
            return False

        except (httpx.ConnectError, httpx.TimeoutException):
            self._is_connected = False
            self._daemon_status = None
            return False

    def sign(
        self,
        content: str,
        origin: str = "vouch-sdk-py",
        **metadata: Any,
    ) -> SignResult:
        """
        Sign text content with the user's private key.

        IMPORTANT: This triggers a user consent popup in the daemon.

        Args:
            content: The content to sign.
            origin: The origin/application name (default: "vouch-sdk-py").
            **metadata: Additional metadata to include.

        Returns:
            SignResult with signature and metadata.

        Raises:
            VouchConnectionError: If not connected.
            UserDeniedSignatureError: If user denies via popup.
            NoKeysConfiguredError: If no keys are configured.
        """
        self._ensure_connected()

        body = {
            "content": content,
            "origin": origin,
            **metadata,
        }

        try:
            response = self._client.post(
                f"{self.daemon_url}/sign",
                json=body,
                timeout=self.request_timeout,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise VouchConnectionError(f"Connection failed: {e}")

        self._handle_error_status(response)

        data = response.json()
        return SignResult(
            signature=data["signature"],
            public_key=data["public_key"],
            did=data["did"],
            timestamp=data["timestamp"],
            content_hash=data["content_hash"],
        )

    def sign_file(
        self,
        file_path: str | Path,
        origin: str = "vouch-sdk-py",
    ) -> MediaSignResult:
        """
        Sign a file from disk using streaming multipart/form-data.

        IMPORTANT: This triggers a user consent popup with media preview.

        Args:
            file_path: Path to the file to sign.
            origin: The origin/application name (default: "vouch-sdk-py").

        Returns:
            MediaSignResult with signed file data and metadata.

        Raises:
            VouchConnectionError: If not connected.
            UserDeniedSignatureError: If user denies via popup.
            NoKeysConfiguredError: If no keys are configured.
            FileNotFoundError: If the file doesn't exist.
        """
        self._ensure_connected()

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        filename = path.name
        mime_type, _ = mimetypes.guess_type(filename)
        mime_type = mime_type or "application/octet-stream"

        # Stream the file to avoid loading large files into memory
        with open(path, "rb") as f:
            files = {"file": (filename, f, mime_type)}
            data = {"origin": origin}

            try:
                response = self._client.post(
                    f"{self.daemon_url}/sign-media",
                    files=files,
                    data=data,
                    timeout=self.request_timeout,
                )
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                raise VouchConnectionError(f"Connection failed: {e}")

        self._handle_error_status(response)

        # Extract metadata from headers
        headers = response.headers
        did = headers.get("x-vouch-did", "")
        timestamp = headers.get("x-vouch-timestamp", "")
        content_hash = headers.get("x-vouch-hash", "")
        content_disposition = headers.get("content-disposition", "")
        response_mime = headers.get("content-type", "application/octet-stream")

        # Parse filename from Content-Disposition
        signed_filename = filename
        if 'filename="' in content_disposition:
            start = content_disposition.index('filename="') + 10
            end = content_disposition.index('"', start)
            signed_filename = content_disposition[start:end]
        elif "filename=" in content_disposition:
            signed_filename = content_disposition.split("filename=")[1].strip()

        return MediaSignResult(
            data=response.content,
            did=did,
            timestamp=timestamp,
            hash=content_hash,
            filename=signed_filename,
            mime_type=response_mime,
        )

    def sign_bytes(
        self,
        data: bytes | BinaryIO,
        filename: str,
        origin: str = "vouch-sdk-py",
    ) -> MediaSignResult:
        """
        Sign binary data (bytes or file-like object).

        Args:
            data: The binary data or file-like object to sign.
            filename: The filename (used for MIME type detection).
            origin: The origin/application name.

        Returns:
            MediaSignResult with signed file data.
        """
        self._ensure_connected()

        mime_type, _ = mimetypes.guess_type(filename)
        mime_type = mime_type or "application/octet-stream"

        files = {"file": (filename, data, mime_type)}
        form_data = {"origin": origin}

        try:
            response = self._client.post(
                f"{self.daemon_url}/sign-media",
                files=files,
                data=form_data,
                timeout=self.request_timeout,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise VouchConnectionError(f"Connection failed: {e}")

        self._handle_error_status(response)

        headers = response.headers
        return MediaSignResult(
            data=response.content,
            did=headers.get("x-vouch-did", ""),
            timestamp=headers.get("x-vouch-timestamp", ""),
            hash=headers.get("x-vouch-hash", ""),
            filename=f"signed_{filename}",
            mime_type=headers.get("content-type", "application/octet-stream"),
        )

    def get_public_key(self) -> PublicKeyInfo:
        """
        Get the user's public key and DID.

        Returns:
            PublicKeyInfo with key details.

        Raises:
            VouchConnectionError: If not connected.
            NoKeysConfiguredError: If no keys are configured.
        """
        self._ensure_connected()

        try:
            response = self._client.get(
                f"{self.daemon_url}/keys/public",
                timeout=self.timeout,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise VouchConnectionError(f"Connection failed: {e}")

        self._handle_error_status(response)

        data = response.json()
        return PublicKeyInfo(
            public_key=data["public_key"],
            did=data["did"],
            fingerprint=data["fingerprint"],
        )

    def disconnect(self) -> None:
        """Disconnect from the daemon."""
        self._is_connected = False
        self._daemon_status = None

    def close(self) -> None:
        """Close the HTTP client and release resources."""
        self._client.close()
        self.disconnect()

    def __enter__(self) -> "VouchClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _ensure_connected(self) -> None:
        """Ensure the client is connected before making requests."""
        if not self._is_connected:
            raise VouchConnectionError("Not connected. Call connect() first.")

    def _handle_error_status(self, response: httpx.Response) -> None:
        """Handle error status codes from the daemon."""
        if response.status_code == 403:
            raise UserDeniedSignatureError()
        elif response.status_code == 404:
            raise NoKeysConfiguredError()
        elif response.status_code >= 400:
            try:
                detail = response.json().get("detail", "Unknown error")
            except Exception:
                detail = response.text or f"HTTP {response.status_code}"
            raise VouchError(f"Request failed: {detail}")


# =============================================================================
# Asynchronous Client
# =============================================================================


class AsyncVouchClient:
    """
    Asynchronous client for the Vouch Bridge Daemon.

    Designed for high-performance apps like FastAPI or Antigravity IDE.

    Example:
        ```python
        from vouch_sdk import AsyncVouchClient

        async with AsyncVouchClient() as client:
            if await client.connect():
                result = await client.sign("Hello, World!")
                print(f"Signature: {result.signature}")
        ```
    """

    def __init__(
        self,
        daemon_url: str = DEFAULT_DAEMON_URL,
        timeout: float = DEFAULT_TIMEOUT,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ):
        """
        Initialize the async Vouch client.

        Args:
            daemon_url: URL of the Vouch daemon.
            timeout: Connection timeout in seconds.
            request_timeout: Request timeout for media signing.
        """
        self.daemon_url = daemon_url.rstrip("/")
        self.timeout = timeout
        self.request_timeout = request_timeout
        self._is_connected = False
        self._daemon_status: DaemonStatus | None = None
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(timeout))

    @property
    def is_connected(self) -> bool:
        """Whether the client is connected to the daemon."""
        return self._is_connected

    @property
    def daemon_status(self) -> DaemonStatus | None:
        """Last known daemon status."""
        return self._daemon_status

    async def connect(self) -> bool:
        """
        Connect to the Vouch Daemon.

        Returns:
            True if connected, False if connection failed.
        """
        try:
            response = await self._client.get(
                f"{self.daemon_url}/status",
                timeout=self.timeout,
            )

            if response.status_code != 200:
                self._is_connected = False
                return False

            data = response.json()

            if data.get("status") == "ok":
                self._is_connected = True
                self._daemon_status = DaemonStatus(
                    status=data.get("status", ""),
                    version=data.get("version", ""),
                    has_keys=data.get("has_keys", False),
                    public_key_fingerprint=data.get("public_key_fingerprint"),
                )
                return True

            self._is_connected = False
            return False

        except (httpx.ConnectError, httpx.TimeoutException):
            self._is_connected = False
            self._daemon_status = None
            return False

    async def sign(
        self,
        content: str,
        origin: str = "vouch-sdk-py",
        **metadata: Any,
    ) -> SignResult:
        """
        Sign text content with the user's private key.

        Args:
            content: The content to sign.
            origin: The origin/application name.
            **metadata: Additional metadata.

        Returns:
            SignResult with signature and metadata.
        """
        self._ensure_connected()

        body = {
            "content": content,
            "origin": origin,
            **metadata,
        }

        try:
            response = await self._client.post(
                f"{self.daemon_url}/sign",
                json=body,
                timeout=self.request_timeout,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise VouchConnectionError(f"Connection failed: {e}")

        self._handle_error_status(response)

        data = response.json()
        return SignResult(
            signature=data["signature"],
            public_key=data["public_key"],
            did=data["did"],
            timestamp=data["timestamp"],
            content_hash=data["content_hash"],
        )

    async def sign_file(
        self,
        file_path: str | Path,
        origin: str = "vouch-sdk-py",
    ) -> MediaSignResult:
        """
        Sign a file from disk using streaming multipart/form-data.

        Args:
            file_path: Path to the file to sign.
            origin: The origin/application name.

        Returns:
            MediaSignResult with signed file data.
        """
        self._ensure_connected()

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        filename = path.name
        mime_type, _ = mimetypes.guess_type(filename)
        mime_type = mime_type or "application/octet-stream"

        # Read file for async upload
        file_data = path.read_bytes()
        files = {"file": (filename, file_data, mime_type)}
        data = {"origin": origin}

        try:
            response = await self._client.post(
                f"{self.daemon_url}/sign-media",
                files=files,
                data=data,
                timeout=self.request_timeout,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise VouchConnectionError(f"Connection failed: {e}")

        self._handle_error_status(response)

        headers = response.headers
        did = headers.get("x-vouch-did", "")
        timestamp = headers.get("x-vouch-timestamp", "")
        content_hash = headers.get("x-vouch-hash", "")

        return MediaSignResult(
            data=response.content,
            did=did,
            timestamp=timestamp,
            hash=content_hash,
            filename=f"signed_{filename}",
            mime_type=headers.get("content-type", "application/octet-stream"),
        )

    async def sign_bytes(
        self,
        data: bytes,
        filename: str,
        origin: str = "vouch-sdk-py",
    ) -> MediaSignResult:
        """
        Sign binary data (bytes).

        Args:
            data: The binary data to sign.
            filename: The filename for MIME detection.
            origin: The origin/application name.

        Returns:
            MediaSignResult with signed file data.
        """
        self._ensure_connected()

        mime_type, _ = mimetypes.guess_type(filename)
        mime_type = mime_type or "application/octet-stream"

        files = {"file": (filename, data, mime_type)}
        form_data = {"origin": origin}

        try:
            response = await self._client.post(
                f"{self.daemon_url}/sign-media",
                files=files,
                data=form_data,
                timeout=self.request_timeout,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise VouchConnectionError(f"Connection failed: {e}")

        self._handle_error_status(response)

        headers = response.headers
        return MediaSignResult(
            data=response.content,
            did=headers.get("x-vouch-did", ""),
            timestamp=headers.get("x-vouch-timestamp", ""),
            hash=headers.get("x-vouch-hash", ""),
            filename=f"signed_{filename}",
            mime_type=headers.get("content-type", "application/octet-stream"),
        )

    async def get_public_key(self) -> PublicKeyInfo:
        """Get the user's public key and DID."""
        self._ensure_connected()

        try:
            response = await self._client.get(
                f"{self.daemon_url}/keys/public",
                timeout=self.timeout,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise VouchConnectionError(f"Connection failed: {e}")

        self._handle_error_status(response)

        data = response.json()
        return PublicKeyInfo(
            public_key=data["public_key"],
            did=data["did"],
            fingerprint=data["fingerprint"],
        )

    def disconnect(self) -> None:
        """Disconnect from the daemon."""
        self._is_connected = False
        self._daemon_status = None

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        await self._client.aclose()
        self.disconnect()

    async def __aenter__(self) -> "AsyncVouchClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def _ensure_connected(self) -> None:
        """Ensure the client is connected."""
        if not self._is_connected:
            raise VouchConnectionError("Not connected. Call connect() first.")

    def _handle_error_status(self, response: httpx.Response) -> None:
        """Handle error status codes."""
        if response.status_code == 403:
            raise UserDeniedSignatureError()
        elif response.status_code == 404:
            raise NoKeysConfiguredError()
        elif response.status_code >= 400:
            try:
                detail = response.json().get("detail", "Unknown error")
            except Exception:
                detail = response.text or f"HTTP {response.status_code}"
            raise VouchError(f"Request failed: {detail}")
