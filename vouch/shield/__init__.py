"""
Vouch Shield - Runtime Security Middleware for AI Agents.

This module provides runtime protection for AI agents by:
- Verifying cryptographic signatures on tool calls
- Enforcing allowlist/blocklist policies
- Applying action / target / resource rules, with globs on resource
- Recording all actions for audit compliance

Shield matches on the same three fields a Vouch credential binds in
``credentialSubject.intent``, so the policy asks the question the evidence
answers. See ``vouch.shield.rules`` for the rule format and glob semantics.

Example:
    >>> from vouch.shield import Shield, ShieldConfig
    >>> shield = Shield(ShieldConfig(rules_path="rules.yaml"))
    >>> decision = shield.check(
    ...     "did:web:agent.example.com",
    ...     action="read_file", target="filesystem", resource="reports/q3.txt",
    ... )
    >>> if decision.allow:
    ...     execute_tool()
"""

from .shield import Shield, ShieldConfig, InterceptResult
from .rules import (
    Decision,
    Rule,
    RuleError,
    RuleSet,
    load_rules,
    load_rules_file,
    normalize_resource,
    resource_matches,
)
from .flight_recorder import FlightRecorder, LogEntry
from .trust_registry import TrustRegistry, TrustStatus

__all__ = [
    "Shield",
    "ShieldConfig",
    "InterceptResult",
    "Decision",
    "Rule",
    "RuleError",
    "RuleSet",
    "load_rules",
    "load_rules_file",
    "normalize_resource",
    "resource_matches",
    "FlightRecorder",
    "LogEntry",
    "TrustRegistry",
    "TrustStatus",
]
