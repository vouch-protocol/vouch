"""
Vouch Shield - Main Shield Class.

Runtime security middleware that intercepts tool calls and enforces
signature verification, trust policies, and capability-based permissions.
"""

import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass

from vouch.verifier import Verifier
from vouch.signer import Signer
from vouch.shield.trust_registry import TrustRegistry, TrustStatus
from vouch.shield.permissions import PermissionManager, Capabilities
from vouch.shield.flight_recorder import FlightRecorder

logger = logging.getLogger(__name__)


@dataclass
class ShieldConfig:
    """Configuration for Shield."""

    trust_config_path: Optional[str] = None
    capabilities_config_path: Optional[str] = None
    log_path: Optional[str] = None
    strict_mode: bool = True  # Block unknown DIDs
    require_signature: bool = True  # Require signed requests


@dataclass
class InterceptResult:
    """Result of intercepting a tool call."""

    allowed: bool
    reason: Optional[str] = None
    did: Optional[str] = None
    warnings: Optional[list] = None


class Shield:
    """
    Runtime security middleware for AI agents.

    Intercepts tool calls and enforces:
    - Cryptographic signature verification (using vouch.Verifier)
    - Trust policies (using TrustRegistry built on vouch.revocation)
    - Capability-based permissions
    - Complete audit trail

    Example:
        >>> from vouch.shield import Shield
        >>>
        >>> shield = Shield()
        >>> shield.trust_did("did:vouch:trusted-publisher")
        >>> shield.set_capabilities("did:vouch:trusted-publisher", Capabilities(
        ...     filesystem=PermissionLevel.READ,
        ...     network=NetworkLevel.OUTBOUND
        ... ))
        >>>
        >>> result = shield.intercept(
        ...     tool="read_file",
        ...     args={"path": "/data/file.txt"},
        ...     token="eyJhbGc..."
        ... )
        >>> if result.allowed:
        ...     execute_tool()
    """

    def __init__(self, config: Optional[ShieldConfig] = None):
        """
        Initialize the Shield.

        Args:
            config: Shield configuration.
        """
        self._config = config or ShieldConfig()

        # Initialize components
        self._verifier = Verifier(allow_did_resolution=True)
        self._trust_registry = TrustRegistry(
            config_path=self._config.trust_config_path,
            strict_mode=self._config.strict_mode,
        )
        self._permissions = PermissionManager(config_path=self._config.capabilities_config_path)
        self._flight_recorder = FlightRecorder(log_path=self._config.log_path)

        # Log session start
        self._flight_recorder.session_start()
        logger.info("Vouch Shield initialized")

    def intercept(
        self,
        tool: str,
        args: Dict[str, Any],
        token: Optional[str] = None,
        did: Optional[str] = None,
    ) -> InterceptResult:
        """
        Intercept and verify a tool call.

        This is the main entry point. Call before executing any tool.

        Args:
            tool: Name of the tool being called.
            args: Arguments to the tool.
            token: Vouch-Token (JWS) for verification.
            did: DID of the caller (extracted from token if not provided).

        Returns:
            InterceptResult with allowed status and reason if denied.
        """
        warnings = []

        # Step 1: Check signature if required
        if self._config.require_signature:
            if not token:
                reason = "Tool call is not signed (no Vouch-Token)"
                self._flight_recorder.blocked("unknown", tool, reason, args)
                return InterceptResult(allowed=False, reason=reason)

            # Verify the token
            is_valid, passport = self._verifier.check_vouch(token)
            if not is_valid or passport is None:
                reason = "Invalid Vouch-Token signature"
                self._flight_recorder.blocked("unknown", tool, reason, args)
                return InterceptResult(allowed=False, reason=reason)

            did = passport.iss  # Use issuer from token
        elif not did:
            reason = "No DID provided and signature not required"
            self._flight_recorder.blocked("unknown", tool, reason, args)
            return InterceptResult(allowed=False, reason=reason)

        # Step 2: Check trust status
        trust_status = self._trust_registry.get_status(did)

        if trust_status == TrustStatus.BLOCKED:
            reason = f"DID is blocked: {did}"
            self._flight_recorder.blocked(did, tool, reason, args)
            return InterceptResult(allowed=False, reason=reason, did=did)

        if trust_status == TrustStatus.UNKNOWN:
            if self._config.strict_mode:
                reason = f"DID is not in allowlist: {did}"
                self._flight_recorder.blocked(did, tool, reason, args)
                return InterceptResult(allowed=False, reason=reason, did=did)
            else:
                warnings.append(f"DID not in allowlist: {did}")

        # Step 3: Check permissions
        allowed, perm_reason = self._permissions.check_permission(did, tool)
        if not allowed:
            self._flight_recorder.blocked(did, tool, perm_reason, args)
            return InterceptResult(allowed=False, reason=perm_reason, did=did)

        # Step 4: Success - log and allow
        self._flight_recorder.allowed(did, tool, args)
        return InterceptResult(
            allowed=True,
            did=did,
            warnings=warnings if warnings else None,
        )

    def trust_did(self, did: str, public_key_jwk: Optional[str] = None) -> None:
        """Add a DID to the trusted list."""
        self._trust_registry.trust(did)
        if public_key_jwk:
            self._verifier.add_trusted_root(did, public_key_jwk)

    def register_key(self, did: str, public_key_jwk: str) -> None:
        """Register a public key for signature verification without trusting."""
        self._verifier.add_trusted_root(did, public_key_jwk)

    def block_did(self, did: str, reason: str = "Manually blocked") -> None:
        """Block a DID."""
        self._trust_registry.block(did, reason)

    def set_capabilities(self, did: str, capabilities: Capabilities) -> None:
        """Set capabilities for a DID."""
        self._permissions.set_capabilities(did, capabilities)

    def get_trust_status(self, did: str) -> TrustStatus:
        """Get trust status for a DID."""
        return self._trust_registry.get_status(did)

    def get_capabilities(self, did: str) -> Capabilities:
        """Get capabilities for a DID."""
        return self._permissions.get_capabilities(did)

    def get_stats(self) -> Dict[str, int]:
        """Get audit statistics."""
        return self._flight_recorder.get_stats()

    def save_config(self) -> None:
        """Save all configuration to disk."""
        self._trust_registry.save_config()
        self._permissions.save_config()

    def shutdown(self) -> None:
        """Shutdown the shield (flush logs)."""
        self._flight_recorder.shutdown()
        logger.info("Vouch Shield shutdown")
