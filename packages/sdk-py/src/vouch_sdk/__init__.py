"""
Vouch SDK for Python

Official client library for the Vouch Protocol.
"""

from vouch_sdk.client import (
    # Clients
    VouchClient,
    AsyncVouchClient,
    # Data classes
    DaemonStatus,
    PublicKeyInfo,
    SignResult,
    MediaSignResult,
    # Exceptions
    VouchError,
    VouchConnectionError,
    UserDeniedSignatureError,
    NoKeysConfiguredError,
    # Constants
    DEFAULT_DAEMON_URL,
)

__all__ = [
    # Clients
    "VouchClient",
    "AsyncVouchClient",
    # Data classes
    "DaemonStatus",
    "PublicKeyInfo",
    "SignResult",
    "MediaSignResult",
    # Exceptions
    "VouchError",
    "VouchConnectionError",
    "UserDeniedSignatureError",
    "NoKeysConfiguredError",
    # Constants
    "DEFAULT_DAEMON_URL",
]

__version__ = "1.0.0"
__author__ = "Ramprasad Anandam Gaddam"
