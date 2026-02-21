"""
Vouch Shield - Runtime Security Middleware for AI Agents.

This module provides runtime protection for AI agents by:
- Verifying cryptographic signatures on tool calls
- Enforcing allowlist/blocklist policies
- Managing capability-based permissions
- Recording all actions for audit compliance

Example:
    >>> from vouch.shield import Shield
    >>> shield = Shield()
    >>> shield.trust_did("did:vouch:trusted-publisher")
    >>> result = shield.intercept(tool="read_file", args={...}, token="...")
    >>> if result.allowed:
    ...     execute_tool()
"""

from .shield import Shield, ShieldConfig, InterceptResult
from .permissions import PermissionManager, Capabilities
from .flight_recorder import FlightRecorder, LogEntry
from .trust_registry import TrustRegistry, TrustStatus

__all__ = [
    "Shield",
    "ShieldConfig",
    "InterceptResult",
    "PermissionManager",
    "Capabilities",
    "FlightRecorder",
    "LogEntry",
    "TrustRegistry",
    "TrustStatus",
]
