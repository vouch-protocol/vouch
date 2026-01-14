"""
Vouch Protocol Google ADK Integration.

Provides a Security Sidecar for Google Agent Development Kit (ADK) agents.
Handles cryptographic signing of tool calls, risk analysis, and immutable
audit logging to Google Cloud Logging.

Example:
    >>> from vouch.integrations.adk import VouchIntegrator, RiskPolicy
    >>>
    >>> integrator = VouchIntegrator()
    >>> protected_tools = integrator.protect([transfer_funds, get_balance])
    >>>
    >>> # Now use protected_tools with your ADK agent
"""

from __future__ import annotations

import functools
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

from vouch.signer import Signer

# Configure module logger
logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk classification for tool calls.

    Attributes:
        LOW: Read-only operations (get, search, read)
        MEDIUM: Standard state changes (default)
        HIGH: Financial or destructive operations
        BLOCKED: Zero-tolerance actions that should never execute
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"


@dataclass
class RiskEvaluation:
    """Result of risk policy evaluation.

    Attributes:
        level: The assessed risk level
        reason: Human-readable explanation
        cooldown_remaining: Seconds until action is allowed (for rate-limited)
    """

    level: RiskLevel
    reason: str
    cooldown_remaining: float = 0.0


class RiskPolicy:
    """Configurable risk evaluation engine for tool calls.

    Evaluates tool names and arguments against configurable rules
    to determine the risk level of any given action.

    Example:
        >>> policy = RiskPolicy(
        ...     custom_rules={"delete_account": RiskLevel.BLOCKED},
        ...     high_patterns=[r".*password.*", r".*credential.*"],
        ... )
        >>> result = policy.evaluate("delete_account", {})
        >>> assert result.level == RiskLevel.BLOCKED
    """

    # Default patterns for risk classification
    LOW_PATTERNS = [
        r"^get_.*",
        r"^read_.*",
        r"^search_.*",
        r"^list_.*",
        r"^fetch_.*",
        r"^query_.*",
        r"^check_.*",
        r"^verify_.*",
    ]

    HIGH_PATTERNS = [
        r".*transfer.*",
        r".*payment.*",
        r".*pay_.*",
        r".*delete.*",
        r".*remove.*",
        r".*update.*",
        r".*modify.*",
        r".*create_.*(?:user|account|admin).*",
        r".*send_(?:money|funds|crypto).*",
        r".*withdraw.*",
    ]

    BLOCKED_PATTERNS = [
        r".*drop_database.*",
        r".*truncate.*",
        r".*format_disk.*",
        r".*rm_rf.*",
        r".*sudo.*",
        r".*exec_shell.*",
    ]

    def __init__(
        self,
        custom_rules: Optional[dict[str, RiskLevel]] = None,
        low_patterns: Optional[list[str]] = None,
        high_patterns: Optional[list[str]] = None,
        blocked_patterns: Optional[list[str]] = None,
        cooldown_seconds: float = 60.0,
        enable_cooldown: bool = True,
    ):
        """Initialize the risk policy.

        Args:
            custom_rules: Explicit tool_name -> RiskLevel mappings
            low_patterns: Additional regex patterns for LOW risk
            high_patterns: Additional regex patterns for HIGH risk
            blocked_patterns: Additional regex patterns for BLOCKED
            cooldown_seconds: Cooldown period for HIGH risk actions
            enable_cooldown: Whether to enforce cooldowns
        """
        self.custom_rules = custom_rules or {}
        self.cooldown_seconds = cooldown_seconds
        self.enable_cooldown = enable_cooldown

        # Compile regex patterns
        self._low_patterns = [
            re.compile(p, re.IGNORECASE) for p in (self.LOW_PATTERNS + (low_patterns or []))
        ]
        self._high_patterns = [
            re.compile(p, re.IGNORECASE) for p in (self.HIGH_PATTERNS + (high_patterns or []))
        ]
        self._blocked_patterns = [
            re.compile(p, re.IGNORECASE) for p in (self.BLOCKED_PATTERNS + (blocked_patterns or []))
        ]

        # Track last execution time for HIGH risk tools (for rate limiting)
        self._last_high_risk_call: dict[str, float] = {}

    def evaluate(self, tool_name: str, args: dict[str, Any]) -> RiskEvaluation:
        """Evaluate the risk level of a tool call.

        Args:
            tool_name: Name of the tool being called
            args: Arguments passed to the tool

        Returns:
            RiskEvaluation with level, reason, and cooldown info
        """
        # Check custom rules first (highest priority)
        if tool_name in self.custom_rules:
            level = self.custom_rules[tool_name]
            return RiskEvaluation(
                level=level,
                reason=f"Custom rule: {tool_name} -> {level.value}",
            )

        # Check BLOCKED patterns
        for pattern in self._blocked_patterns:
            if pattern.match(tool_name):
                return RiskEvaluation(
                    level=RiskLevel.BLOCKED,
                    reason=f"Blocked pattern match: {pattern.pattern}",
                )

        # Check HIGH patterns
        for pattern in self._high_patterns:
            if pattern.match(tool_name):
                # Check cooldown
                cooldown_remaining = self._check_cooldown(tool_name)
                if cooldown_remaining > 0:
                    return RiskEvaluation(
                        level=RiskLevel.HIGH,
                        reason=f"High-risk pattern match: {pattern.pattern} (cooldown active)",
                        cooldown_remaining=cooldown_remaining,
                    )
                return RiskEvaluation(
                    level=RiskLevel.HIGH,
                    reason=f"High-risk pattern match: {pattern.pattern}",
                )

        # Check arguments for sensitive data patterns
        args_str = str(args).lower()
        sensitive_patterns = ["password", "secret", "token", "credential", "api_key"]
        for sensitive in sensitive_patterns:
            if sensitive in args_str:
                return RiskEvaluation(
                    level=RiskLevel.HIGH,
                    reason=f"Sensitive argument detected: {sensitive}",
                )

        # Check LOW patterns
        for pattern in self._low_patterns:
            if pattern.match(tool_name):
                return RiskEvaluation(
                    level=RiskLevel.LOW,
                    reason=f"Low-risk pattern match: {pattern.pattern}",
                )

        # Default to MEDIUM
        return RiskEvaluation(
            level=RiskLevel.MEDIUM,
            reason="Default classification",
        )

    def _check_cooldown(self, tool_name: str) -> float:
        """Check if a tool is in cooldown period.

        Returns:
            Remaining cooldown seconds, or 0 if not in cooldown
        """
        if not self.enable_cooldown:
            return 0.0

        last_call = self._last_high_risk_call.get(tool_name, 0)
        elapsed = time.time() - last_call

        if elapsed < self.cooldown_seconds:
            return self.cooldown_seconds - elapsed
        return 0.0

    def record_high_risk_call(self, tool_name: str) -> None:
        """Record that a HIGH risk tool was executed (for cooldown tracking)."""
        self._last_high_risk_call[tool_name] = time.time()


@dataclass
class AuditLogEntry:
    """Structured audit log entry for tool calls."""

    tool_name: str
    args: dict[str, Any]
    risk_level: str
    risk_reason: str
    timestamp: str
    agent_id: str
    vouch_signature: str
    execution_allowed: bool
    error: Optional[str] = None


class VouchIntegrator:
    """Security middleware for Google ADK agents.

    Wraps tool functions to provide:
    - Cryptographic signing of every tool call
    - Risk-based policy enforcement
    - Immutable audit logging to Google Cloud Logging

    Example:
        >>> integrator = VouchIntegrator(
        ...     risk_policy=RiskPolicy(cooldown_seconds=30),
        ... )
        >>>
        >>> @tool
        >>> def transfer_funds(amount: int, to_account: str) -> str:
        ...     return f"Transferred ${amount} to {to_account}"
        >>>
        >>> protected = integrator.protect([transfer_funds])
    """

    def __init__(
        self,
        private_key: Optional[str] = None,
        did: Optional[str] = None,
        risk_policy: Optional[RiskPolicy] = None,
        log_name: str = "agent-audit-log",
        enable_cloud_logging: bool = True,
        block_high_risk: bool = False,
    ):
        """Initialize the Vouch integrator.

        Args:
            private_key: JWK JSON string. Falls back to VOUCH_PRIVATE_KEY env var.
            did: Agent DID. Falls back to VOUCH_DID env var.
            risk_policy: Custom risk policy. Uses default if not provided.
            log_name: Google Cloud Logging log name.
            enable_cloud_logging: Whether to send logs to GCP.
            block_high_risk: If True, HIGH risk actions are blocked (not just logged).
        """
        self._private_key = private_key or os.getenv("VOUCH_PRIVATE_KEY")
        self._did = did or os.getenv("VOUCH_DID", "did:vouch:unknown")
        self._policy = risk_policy or RiskPolicy()
        self._log_name = log_name
        self._enable_cloud_logging = enable_cloud_logging
        self._block_high_risk = block_high_risk

        # Initialize signer
        self._signer: Optional[Signer] = None
        if self._private_key and self._did:
            try:
                self._signer = Signer(private_key=self._private_key, did=self._did)
            except Exception as e:
                logger.warning(f"Failed to initialize Vouch signer: {e}")

        # Initialize Google Cloud Logging (lazy)
        self._cloud_logger = None

    def _get_cloud_logger(self):
        """Lazily initialize Google Cloud Logging client."""
        if self._cloud_logger is not None:
            return self._cloud_logger

        if not self._enable_cloud_logging:
            return None

        try:
            from google.cloud import logging as cloud_logging

            client = cloud_logging.Client()
            self._cloud_logger = client.logger(self._log_name)
            return self._cloud_logger
        except ImportError:
            logger.warning(
                "google-cloud-logging not installed. Install with: pip install google-cloud-logging"
            )
            return None
        except Exception as e:
            logger.warning(f"Failed to initialize Cloud Logging: {e}")
            return None

    def protect(self, tools: list[Callable]) -> list[Callable]:
        """Wrap a list of tool functions with Vouch security.

        Args:
            tools: List of tool functions to protect

        Returns:
            List of wrapped tool functions with same signatures
        """
        return [self._wrap_tool(tool) for tool in tools]

    def _wrap_tool(self, tool: Callable) -> Callable:
        """Wrap a single tool function with security middleware."""

        @functools.wraps(tool)
        def wrapper(*args, **kwargs) -> Any:
            tool_name = tool.__name__

            # Combine positional and keyword args for logging
            # (positional args are harder to log meaningfully)
            call_args = {
                "_positional": list(args) if args else [],
                **kwargs,
            }

            # Step 1: Evaluate risk
            risk_eval = self._policy.evaluate(tool_name, call_args)

            # Step 2: Check if action is allowed
            execution_allowed = True
            error_msg = None

            if risk_eval.level == RiskLevel.BLOCKED:
                execution_allowed = False
                error_msg = f"Action blocked by policy: {risk_eval.reason}"
            elif risk_eval.level == RiskLevel.HIGH:
                if self._block_high_risk:
                    execution_allowed = False
                    error_msg = f"High-risk action blocked: {risk_eval.reason}"
                elif risk_eval.cooldown_remaining > 0:
                    execution_allowed = False
                    error_msg = (
                        f"High-risk action in cooldown. Wait {risk_eval.cooldown_remaining:.0f}s"
                    )

            # Step 3: Build and sign payload
            timestamp = datetime.now(timezone.utc).isoformat()
            payload = {
                "type": "tool_call",
                "tool": tool_name,
                "args_hash": hash(str(call_args)) & 0xFFFFFFFF,  # Don't log full args
                "risk_level": risk_eval.level.value,
                "timestamp": timestamp,
                "agent_id": self._did,
            }

            vouch_signature = "unsigned"
            if self._signer:
                try:
                    vouch_signature = self._signer.sign(payload)
                except Exception as e:
                    logger.warning(f"Failed to sign payload: {e}")

            # Step 4: Create audit log entry
            log_entry = AuditLogEntry(
                tool_name=tool_name,
                args=self._sanitize_args(call_args),
                risk_level=risk_eval.level.value,
                risk_reason=risk_eval.reason,
                timestamp=timestamp,
                agent_id=self._did,
                vouch_signature=vouch_signature,
                execution_allowed=execution_allowed,
                error=error_msg,
            )

            # Step 5: Send to Cloud Logging
            self._log_to_cloud(log_entry, risk_eval.level)

            # Step 6: Execute or block
            if not execution_allowed:
                raise PermissionError(error_msg)

            # Record high-risk execution for cooldown
            if risk_eval.level == RiskLevel.HIGH:
                self._policy.record_high_risk_call(tool_name)

            # Step 7: Inject signature into kwargs for downstream use
            kwargs["_vouch_signature"] = vouch_signature
            kwargs["_vouch_risk_level"] = risk_eval.level.value

            # Execute the actual tool
            return tool(*args, **kwargs)

        return wrapper

    def _sanitize_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Remove sensitive data from args before logging."""
        sanitized = {}
        sensitive_keys = {"password", "secret", "token", "api_key", "credential", "key"}

        for key, value in args.items():
            if any(s in key.lower() for s in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, str) and len(value) > 100:
                sanitized[key] = value[:100] + "...[truncated]"
            else:
                sanitized[key] = value

        return sanitized

    def _log_to_cloud(self, entry: AuditLogEntry, risk_level: RiskLevel) -> None:
        """Send structured log to Google Cloud Logging with retry."""
        cloud_logger = self._get_cloud_logger()
        if not cloud_logger:
            # Fall back to standard logging
            logger.info(f"Audit: {entry.tool_name} | Risk: {entry.risk_level}")
            return

        # Map risk level to GCP severity
        severity_map = {
            RiskLevel.LOW: "INFO",
            RiskLevel.MEDIUM: "NOTICE",
            RiskLevel.HIGH: "CRITICAL",
            RiskLevel.BLOCKED: "ALERT",
        }
        severity = severity_map.get(risk_level, "DEFAULT")

        # Prepare structured log
        struct = {
            "tool_name": entry.tool_name,
            "risk_level": entry.risk_level,
            "risk_reason": entry.risk_reason,
            "timestamp": entry.timestamp,
            "agent_id": entry.agent_id,
            "vouch_signature": entry.vouch_signature,
            "execution_allowed": entry.execution_allowed,
        }
        if entry.error:
            struct["error"] = entry.error

        # Retry logic for transient failures
        max_retries = 3
        for attempt in range(max_retries):
            try:
                cloud_logger.log_struct(struct, severity=severity)
                return
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(
                        f"Failed to log to Cloud Logging after {max_retries} attempts: {e}"
                    )
                else:
                    time.sleep(0.1 * (attempt + 1))  # Exponential backoff


# Convenience function for quick setup
def protect_tools(
    tools: list[Callable],
    block_high_risk: bool = False,
) -> list[Callable]:
    """Quick helper to protect a list of tools with default settings.

    Args:
        tools: List of tool functions
        block_high_risk: Whether to block HIGH risk actions

    Returns:
        Protected tool list ready for ADK agent

    Example:
        >>> from vouch.integrations.adk import protect_tools
        >>> protected = protect_tools([my_tool_1, my_tool_2])
    """
    integrator = VouchIntegrator(block_high_risk=block_high_risk)
    return integrator.protect(tools)
