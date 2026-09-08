"""Translate a verified AAT leaf into Vouch Shield rules, and enforce them.

Only the **leaf** matters for enforcement. A derived AAT already states its own
narrowed authority, so there is nothing to intersect: the chain is verified for
provenance, the leaf is what is enforced. See ``DESIGN.md``.

Shield v2 matches on ``action`` / ``target`` / ``resource`` with globs on
``resource``, so a leaf's path constraint now has a home in Shield itself. Tool
scope becomes the rule's ``action``; a path-shaped argument constraint becomes
its ``resource`` glob.

Two properties this module holds to:

1. **A Shield rule is never wider than the Tenuo constraint it came from.**
   Where an exact translation is not possible the rule falls back to ``**`` and
   the constraint stays with Tenuo's evaluator alone. Narrower is safe here,
   because both gates must allow; wider would not be.
2. **Shield never replaces Tenuo.** The reference implementation still evaluates
   every constraint on every call. Shield is a second, independent refusal
   point for the subset it can express, not a substitute for the first.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from vouch.shield.rules import (
    Decision,
    Rule,
    RuleSet,
    normalize_pattern,
)

from .aat_chain import VerifiedChain

try:
    from tenuo import exceptions as _tex
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The AAT adapter needs the AAT reference implementation. Install it with: pip install tenuo"
    ) from exc


__all__ = [
    "ShieldRules",
    "AatDecision",
    "AatGate",
    "leaf_to_shield_rules",
    "tenuo_glob_to_shield",
    "DEFAULT_TARGET",
    "RESOURCE_ARG_NAMES",
]

#: Rule ``target`` used for AAT-derived rules unless the caller says otherwise.
DEFAULT_TARGET = "filesystem"

#: Argument names treated as carrying the call's resource, most specific first.
#: Used when a tool constrains several arguments and we must choose which one
#: Shield's ``resource`` represents.
RESOURCE_ARG_NAMES = ("path", "file", "filename", "resource", "url", "uri", "table")


# ---------------------------------------------------------------------------
# Constraint translation
# ---------------------------------------------------------------------------


def tenuo_glob_to_shield(pattern: str) -> Optional[str]:
    """Translate a Tenuo glob into an equal-or-narrower Shield glob.

    The two do not share semantics. Tenuo's ``*`` is a plain glob whose ``*``
    crosses ``/``; Shield's ``*`` is one path segment and never crosses ``/``.
    So ``reports/*`` means different things to each, and copying the string
    across would produce a Shield rule that wrongly denies ``reports/2026/q3.txt``.

    Translatable shapes, verified against the reference implementation by the
    differential test in ``tests/``:

    ============================  ==========================
    Tenuo                         Shield
    ============================  ==========================
    ``reports/q3.txt`` (literal)  ``reports/q3.txt``
    ``reports/*``                 ``reports/*/**``
    ``reports/**``                ``reports/*/**``
    ``*`` / ``**``                ``**``
    ============================  ==========================

    Anything else returns None, meaning "no faithful Shield rule exists for
    this"; the caller then falls back to ``**`` and leaves the constraint to
    Tenuo. A mid-string ``*`` such as ``rep*ts`` is the common example: Tenuo
    matches ``rep/or/ts`` through it, and Shield has no way to say that.
    """
    if not isinstance(pattern, str) or not pattern:
        return None

    if pattern in ("*", "**"):
        return "**"

    if "*" not in pattern:
        # A literal. Reject '.'/'..' segments rather than resolving them,
        # matching normalize_pattern's stance.
        segments = [s for s in pattern.split("/") if s]
        if not segments or any(s in (".", "..") for s in segments):
            return None
        return "/".join(segments)

    # Only a single trailing '/*' or '/**' is translatable.
    for suffix in ("/**", "/*"):
        if pattern.endswith(suffix):
            prefix = pattern[: -len(suffix)]
            if "*" in prefix:
                return None
            segments = [s for s in prefix.split("/") if s]
            if not segments or any(s in (".", "..") for s in segments):
                return None
            # '*/**' is "one or more segments below the prefix", which is what
            # Tenuo's trailing '*' means. A bare '**' here would also match the
            # prefix itself, which would be wider than Tenuo.
            return "/".join(segments) + "/*/**"

    return None


def _constraint_to_globs(constraint: Any) -> Optional[List[str]]:
    """Shield globs equivalent to one Tenuo constraint, or None if untranslatable."""
    name = type(constraint).__name__

    if name == "Pattern":
        translated = tenuo_glob_to_shield(str(constraint.pattern))
        return [translated] if translated else None

    if name == "Exact":
        value = constraint.value
        if not isinstance(value, str) or "*" in value:
            return None
        translated = tenuo_glob_to_shield(value)
        return [translated] if translated else None

    if name == "OneOf":
        globs: List[str] = []
        for value in constraint.values:
            text = getattr(value, "value", value)
            if not isinstance(text, str) or "*" in text:
                return None
            translated = tenuo_glob_to_shield(text)
            if translated is None:
                return None
            globs.append(translated)
        return globs or None

    # Wildcard, Range, Regex, CEL, Cidr, Url*, Cmd, Shlex, Not, NotOneOf, ...
    return None


def _pick_resource_arg(constraints: Dict[str, Any]) -> Optional[str]:
    """Choose which constrained argument Shield's ``resource`` stands for."""
    if not constraints:
        return None
    if len(constraints) == 1:
        return next(iter(constraints))
    for candidate in RESOURCE_ARG_NAMES:
        if candidate in constraints:
            return candidate
    return None


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ShieldRules:
    """Shield v2 rules derived from an AAT leaf."""

    did: str
    target: str
    rules: Tuple[Rule, ...]
    allowed_tools: frozenset
    #: Tools whose argument constraint became a real resource glob.
    mapped_tools: Tuple[str, ...] = ()
    #: Tools whose constraints Shield cannot express; Tenuo alone gates their
    #: arguments, and their rule is ``resource: "**"``.
    unmapped_tools: Tuple[str, ...] = ()
    #: The argument each mapped tool's resource was taken from.
    resource_args: Optional[Dict[str, str]] = None
    leaf_jti: str = ""
    root_jti: str = ""

    def permits_tool(self, tool: str) -> bool:
        """Exact-string match, per draft Section 3.3.1 - no normalization."""
        return tool in self.allowed_tools

    def as_rule_set(self) -> RuleSet:
        by_did: Dict[str, List[Rule]] = {self.did: list(self.rules)}
        return RuleSet(by_did=by_did)

    def as_document(self) -> Dict[str, Any]:
        """The rules as a v2 rules document, for writing to a file."""
        return {
            "version": 2,
            "rules": [
                {
                    "did": self.did,
                    "allow": [
                        {
                            "id": r.id,
                            "action": r.action,
                            "target": r.target,
                            "resource": r.resource,
                        }
                        for r in self.rules
                    ],
                }
            ],
            "deny_default": True,
        }


def leaf_to_shield_rules(
    chain: VerifiedChain,
    *,
    did: str,
    target: str = DEFAULT_TARGET,
    resource_arg: Optional[str] = None,
) -> ShieldRules:
    """Derive Shield v2 rules from a verified chain's leaf.

    Each tool the leaf authorises becomes one or more allow rules: the tool name
    is the ``action``, and its path-shaped argument constraint becomes the
    ``resource`` glob. Constraints Shield cannot express fall back to ``**`` and
    are reported in ``unmapped_tools``; Tenuo still gates them.

    Args:
        chain: A verified chain. Only its leaf is used.
        did: The DID these rules apply to.
        target: Rule ``target``. AAT has no target concept, so it is supplied.
        resource_arg: Force which argument carries the resource. By default it
            is inferred (see :data:`RESOURCE_ARG_NAMES`).
    """
    capabilities = chain.capabilities()
    rules: List[Rule] = []
    mapped: List[str] = []
    unmapped: List[str] = []
    chosen_args: Dict[str, str] = {}

    for tool in sorted(capabilities):
        constraints = capabilities[tool] or {}
        arg = resource_arg or _pick_resource_arg(constraints)
        globs = _constraint_to_globs(constraints[arg]) if arg in constraints else None

        if globs:
            mapped.append(tool)
            chosen_args[tool] = arg
        else:
            # No faithful translation. Shield allows the tool at any resource
            # and Tenuo remains the only gate on its arguments.
            globs = ["**"]
            unmapped.append(tool)

        for index, glob in enumerate(globs):
            rules.append(
                Rule(
                    action=tool,
                    target=target,
                    resource=normalize_pattern(glob),
                    id=f"aat:{chain.leaf_jti}:{tool}:{index}",
                )
            )

    return ShieldRules(
        did=did,
        target=target,
        rules=tuple(rules),
        allowed_tools=frozenset(capabilities),
        mapped_tools=tuple(mapped),
        unmapped_tools=tuple(unmapped),
        resource_args=chosen_args,
        leaf_jti=chain.leaf_jti,
        root_jti=chain.root_jti,
    )


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AatDecision:
    """The outcome of a pre-execution check. ``allowed`` is the whole answer."""

    allowed: bool
    tool: str
    reason: Optional[str] = None
    leaf_jti: str = ""
    root_jti: str = ""
    failure: Optional[str] = None
    #: Which layer refused: "shield" or "tenuo". None when allowed.
    refused_by: Optional[str] = None

    def __bool__(self) -> bool:
        return self.allowed


class AatGate:
    """Pre-execution gate combining AAT authority with Vouch Shield.

    Every decision happens before the tool runs. There is no path through this
    class that executes a tool and then checks it.

    Usage::

        chain = verify_chain_file("leaf.json")
        gate = AatGate(chain, holder_key=key, did="did:web:agent.example.com")
        decision = gate.check("read_file", {"path": "reports/q3.txt"})
        if decision.allowed:
            run_tool()
    """

    #: DID used for AAT-derived rules when the caller does not supply one. The
    #: rules are scoped to this leaf, so the identifier only has to be stable.
    DEFAULT_DID = "did:vouch:aat-holder"

    def __init__(
        self,
        chain: VerifiedChain,
        *,
        holder_key: Any = None,
        shield: Any = None,
        did: Optional[str] = None,
        target: str = DEFAULT_TARGET,
        resource_arg: Optional[str] = None,
    ) -> None:
        """
        Args:
            chain: A chain already verified by ``aat_chain.verify_chain``.
            holder_key: Optional signing key matching the leaf's authorized
                holder. Supplied, the gate mints the proof-of-possession for
                each call itself. That is a convenience for local and demo use:
                in a real deployment the PoP is produced by the caller holding
                the key and passed to ``check`` as ``signature``.
            shield: Optional external ``vouch.shield.Shield``. When given, its
                verdict is combined with the others and all must allow.
            did: DID the AAT-derived rules are written for.
            target: Rule ``target`` for the derived rules.
            resource_arg: Force which argument carries the resource.
        """
        self._chain = chain
        self._holder_key = holder_key
        self._shield = shield
        self._did = did or self.DEFAULT_DID
        self.rules = leaf_to_shield_rules(
            chain, did=self._did, target=target, resource_arg=resource_arg
        )
        self._rule_set = self.rules.as_rule_set()

    @property
    def chain(self) -> VerifiedChain:
        return self._chain

    def shield_check(self, tool: str, args: Dict[str, Any]) -> Decision:
        """Shield's verdict alone, using the AAT-derived rules."""
        return self._rule_set.check(
            self._did,
            action=tool,
            target=self.rules.target,
            resource=self._resource_for(tool, args),
        )

    def _resource_for(self, tool: str, args: Dict[str, Any]) -> str:
        """The resource string Shield matches for this call."""
        arg = (self.rules.resource_args or {}).get(tool)
        if arg is None:
            arg = _pick_resource_arg(args) or ""
        value = args.get(arg)
        if isinstance(value, str) and value:
            return value
        # Nothing resource-shaped to match on. Tools in this position are
        # unmapped and carry a '**' rule, so Shield defers to Tenuo.
        return "\x00" if tool in self.rules.mapped_tools else "unspecified"

    def check(
        self,
        tool: str,
        args: Optional[Dict[str, Any]] = None,
        *,
        signature: Optional[bytes] = None,
        as_of: Optional[datetime] = None,
    ) -> AatDecision:
        """Decide whether a call may proceed. Never executes anything.

        Order: tool scope, then Shield against the AAT-derived rules, then any
        external Shield, then the AAT reference implementation (which re-checks
        tool scope, evaluates every argument constraint, enforces expiry, and
        verifies proof-of-possession). Any failure is fail-closed.
        """
        args = dict(args or {})

        def deny(
            reason: str, failure: Optional[str] = None, by: Optional[str] = None
        ) -> AatDecision:
            return AatDecision(
                allowed=False,
                tool=tool,
                reason=reason,
                leaf_jti=self.rules.leaf_jti,
                root_jti=self.rules.root_jti,
                failure=failure,
                refused_by=by,
            )

        # 1. Tool scope from the leaf.
        if not self.rules.permits_tool(tool):
            return deny(
                f"Tool '{tool}' is not in the AAT leaf's authority "
                f"(leaf permits: {', '.join(sorted(self.rules.allowed_tools)) or 'nothing'})",
                failure="ToolNotAuthorized",
                by="shield",
            )

        # 2. Shield, using rules derived from the leaf's own constraints. For a
        #    path-shaped constraint this is a real, independent refusal point:
        #    it denies 'read_file /etc/passwd' under a 'reports/*' leaf without
        #    consulting Tenuo at all.
        shield_decision = self.shield_check(tool, args)
        if not shield_decision.allow:
            return deny(
                f"Shield denied: {shield_decision.reason}",
                failure="ShieldDenied",
                by="shield",
            )

        # 3. An externally supplied Shield, when configured. All layers must allow.
        if self._shield is not None:
            result = self._shield.intercept(
                tool=tool,
                args=args,
                did=self._did,
                target=self.rules.target,
                resource=self._resource_for(tool, args),
            )
            if not result.allowed:
                return deny(f"Shield denied: {result.reason}", failure="ShieldDenied", by="shield")

        # 4. The AAT reference implementation: every argument constraint,
        #    expiry, and proof-of-possession. Shield never replaces this.
        pop = signature
        if pop is None and self._holder_key is not None:
            try:
                pop = self._chain.leaf.sign(self._holder_key, tool, args, int(time.time()))
            except Exception as exc:
                return deny(
                    f"Could not produce proof-of-possession: {exc}",
                    failure="PopError",
                    by="tenuo",
                )

        try:
            self._chain._authorizer.check_chain(self._chain.warrants, tool, args, signature=pop)
        except _tex.TenuoError as exc:
            return deny(f"{type(exc).__name__}: {exc}", failure=type(exc).__name__, by="tenuo")
        except Exception as exc:  # unknown means deny
            return deny(f"AAT check failed: {exc}", failure=type(exc).__name__, by="tenuo")

        return AatDecision(
            allowed=True,
            tool=tool,
            leaf_jti=self.rules.leaf_jti,
            root_jti=self.rules.root_jti,
        )
