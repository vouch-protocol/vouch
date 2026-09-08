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
from vouch.shield.rules import (
    Decision,
    RuleSet,
    load_rules_file,
    REASON_MALFORMED_RULES,
)
from vouch.shield.flight_recorder import FlightRecorder

logger = logging.getLogger(__name__)


@dataclass
class ShieldConfig:
    """Configuration for Shield."""

    trust_config_path: Optional[str] = None
    rules_path: Optional[str] = None
    log_path: Optional[str] = None
    strict_mode: bool = True  # Block unknown DIDs
    require_signature: bool = True  # Require signed requests
    # `intent.target` assumed when a caller does not supply one. Rules match
    # target exactly, so this has to be stated rather than guessed per call.
    default_target: str = "tool"


@dataclass
class InterceptResult:
    """Result of intercepting a tool call."""

    allowed: bool
    reason: Optional[str] = None
    did: Optional[str] = None
    warnings: Optional[list] = None
    rule_id: Optional[str] = None


class Shield:
    """
    Runtime security middleware for AI agents.

    Intercepts tool calls and enforces:
    - Cryptographic signature verification (using vouch.Verifier)
    - Trust policies (using TrustRegistry built on vouch.revocation)
    - action / target / resource rules, with globs on resource
    - Complete audit trail

    Rules match the same three fields a Vouch credential binds in
    ``credentialSubject.intent``, so policy and evidence ask the same question.

    Example:
        >>> from vouch.shield import Shield, ShieldConfig
        >>>
        >>> shield = Shield(ShieldConfig(rules_path="rules.yaml"))
        >>> shield.trust_did("did:web:agent.example.com")
        >>>
        >>> decision = shield.check(
        ...     "did:web:agent.example.com",
        ...     action="read_file",
        ...     target="filesystem",
        ...     resource="reports/q3.txt",
        ... )
        >>> if decision.allow:
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
        # No rules path means no authority: an empty RuleSet denies everything.
        # Shield never starts in a state that is laxer than its configuration.
        if self._config.rules_path:
            self._rules = load_rules_file(self._config.rules_path)
        else:
            self._rules = RuleSet()
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
        target: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> InterceptResult:
        """
        Intercept and verify a tool call.

        This is the main entry point. Call before executing any tool.

        Args:
            tool: Name of the tool being called. Used as the rule `action`.
            args: Arguments to the tool.
            token: Vouch-Token (JWS) for verification.
            did: DID of the caller (extracted from token if not provided).
            target: Rule `target`. Defaults to the config's `default_target`.
            resource: Rule `resource`. Defaults to the JCS canonicalisation of
                `args`, which binds the decision to these exact arguments. Pass
                it explicitly when a coarser resource is the right policy unit
                (a path, a table name), so rules can glob over something
                meaningful.

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

            # Verify the credential, resolving the issuer key from trusted
            # roots, from did:key offline, or via did:web resolution.
            is_valid, passport = self._verifier.check_vouch_credential(token)
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

        # Step 3: Check the rules. The tool name is the action; the resource is
        # what the call actually touches, so this is the step that can tell
        # 'reports/q3.txt' apart from '/etc/passwd'.
        decision = self.check(
            did,
            action=tool,
            target=target or self._config.default_target,
            resource=resource if resource is not None else _resource_from_args(args),
        )
        if not decision.allow:
            self._flight_recorder.blocked(did, tool, decision.reason, args)
            return InterceptResult(
                allowed=False, reason=decision.reason, did=did, rule_id=decision.rule_id
            )

        # Step 4: Success - log and allow
        self._flight_recorder.allowed(did, tool, args)
        return InterceptResult(
            allowed=True,
            did=did,
            warnings=warnings if warnings else None,
            rule_id=decision.rule_id,
        )

    def check(self, did: str, action: str, target: str, resource: str) -> Decision:
        """Decide whether a DID may take one action on one resource.

        This is Shield's primary API. It matches on the same three fields a
        Vouch credential binds in ``credentialSubject.intent``, so the policy
        asks exactly the question the evidence answers.

        Args:
            did: The caller's DID.
            action: The verb, e.g. 'read_file'. Matched exactly.
            target: The service or surface, e.g. 'filesystem'. Matched exactly.
            resource: The specific object. Glob-matched; see
                :mod:`vouch.shield.rules` for the segment semantics.

        Returns:
            A :class:`~vouch.shield.rules.Decision`. ``reason`` is one of a
            small set of stable strings that callers may branch on.
        """
        return self._rules.check(did, action, target, resource)

    @property
    def rules(self) -> RuleSet:
        """The loaded rule set. Denies everything if the file failed to load."""
        return self._rules

    def load_rules(self, path: str) -> RuleSet:
        """Replace the rule set from a file. A bad file denies everything."""
        self._rules = load_rules_file(path)
        if not self._rules.ok:
            logger.error("Vouch Shield: %s", self._rules.malformed_reason)
        return self._rules

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

    def allow(self, did: str, action: str, target: str, resource: str) -> None:
        """Add one allow rule in memory, without a rules file.

        For tests and small scripts. Production deployments should keep rules
        in a file so the policy is reviewable and diffable.
        """
        from vouch.shield.rules import Rule, normalize_pattern

        rules = self._rules.by_did.setdefault(did, [])
        rules.append(
            Rule(
                action=action,
                target=target,
                resource=normalize_pattern(resource),
                id=f"{did}#{len(rules)}",
            )
        )

    def get_trust_status(self, did: str) -> TrustStatus:
        """Get trust status for a DID."""
        return self._trust_registry.get_status(did)

    def rules_for(self, did: str) -> list:
        """The allow rules in force for a DID. Empty means it may do nothing."""
        return list(self._rules.by_did.get(did, []))

    def get_stats(self) -> Dict[str, int]:
        """Get audit statistics."""
        return self._flight_recorder.get_stats()

    def save_config(self) -> None:
        """Save trust configuration to disk.

        Rules are not written back: a rules file is authored and reviewed, not
        mutated by the process it governs.
        """
        self._trust_registry.save_config()

    def shutdown(self) -> None:
        """Shutdown the shield (flush logs)."""
        self._flight_recorder.shutdown()
        logger.info("Vouch Shield shutdown")

    # ------------------------------------------------------------------
    # Zero-config protection
    # ------------------------------------------------------------------

    @classmethod
    def guard(
        cls,
        tools,
        *,
        sign: bool = True,
        allow: Optional[list] = None,
        audit_log_path: Optional[str] = None,
        signer=None,
        on_block: str = "raise",
    ) -> list:
        """Protect a list of agent tools with zero configuration.

        No trust-registry file, no capability config, no per-call token
        threading. Wraps each tool so that on every call it:

          1. is **signed** (outbound identity) via the autosign layer, unless
             ``sign=False``;
          2. is checked against a **tool allowlist** - by default exactly the
             tools you pass, so the agent cannot be steered into calling a tool
             you never granted (the most common real attack);
          3. is written to a tamper-evident **audit log** (the flight recorder).

        This is the batteries-included counterpart to the fully-configurable
        :class:`Shield`. Returns wrapped plain callables.

        Args:
            tools: plain callables to protect.
            sign: sign each call before it runs (default True).
            allow: explicit allowlist of tool names. Defaults to the names of
                the tools passed in.
            audit_log_path: where to write the audit log (default: the flight
                recorder's default path).
            signer: explicit Signer; otherwise resolved automatically.
            on_block: "raise" a PermissionError on a disallowed call (default),
                or "skip" to return None without running it.

        Example::

            from vouch.shield import Shield
            agent.tools = Shield.guard([charge_invoice, send_email])
        """
        import functools

        from vouch.autosign import current_credential, signed

        recorder = FlightRecorder(log_path=audit_log_path)
        allowed = set(allow) if allow is not None else {_tool_name(t) for t in tools}

        wrapped = []
        for tool in tools:
            name = _tool_name(tool)
            inner = signed(tool, signer=signer) if sign else tool

            def make(name, inner):
                @functools.wraps(inner)
                def guarded(*args, **kwargs):
                    if name not in allowed:
                        recorder.blocked("unknown", name, "tool not in allowlist", None)
                        if on_block == "skip":
                            return None
                        raise PermissionError(f"Tool '{name}' is not in the Shield allowlist")
                    result = inner(*args, **kwargs)
                    cred = current_credential()
                    did = (cred or {}).get("issuer", "unsigned") if sign else "unsigned"
                    recorder.allowed(did, name, None)
                    return result

                guarded.__vouch_guarded__ = True
                return guarded

            wrapped.append(make(name, inner))
        return wrapped


def _resource_from_args(args: Optional[Dict[str, Any]]) -> str:
    """Default resource for a call: the JCS canonicalisation of its arguments.

    This is the strict binding. A decision made for these arguments does not
    carry to any other arguments, because the resource string differs.

    Callers that want a coarser policy unit - a path, a table name - should pass
    `resource` explicitly, so rules can glob over something meaningful. That is a
    deliberate loosening, and it should be visible at the call site.
    """
    from vouch import jcs

    try:
        return jcs.canonicalize_str(args or {})
    except Exception:
        # An unserialisable argument cannot be bound to, so it cannot be
        # authorised. Return a resource no rule can match.
        return "\x00"


def _tool_name(tool) -> str:
    """Best-effort display name for a tool callable or object."""
    for attr in ("name", "__name__"):
        value = getattr(tool, attr, None)
        if isinstance(value, str) and value:
            return value
    return repr(tool)
