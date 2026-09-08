"""Translate a verified AAT leaf into Vouch Shield rules, and enforce them.

Only the **leaf** matters for enforcement. A derived AAT already states its own
narrowed authority, so there is nothing to intersect: the chain is verified for
provenance, the leaf is what is enforced. See ``DESIGN.md``.

The mapping is deliberately partial, and the partiality is the interesting part.

- **Tool scope** becomes Shield rules: one allow rule per tool the leaf names.
- **Argument constraints** stay with the AAT reference implementation, and are
  evaluated by ``Authorizer.check_chain`` in the same pre-execution step. Every
  derived rule therefore carries ``resource: "**"``; Shield does not yet claim
  to express what the token says about a call's arguments.

Both must allow. Either refusing means the tool does not run.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from vouch.shield.rules import Rule, RuleSet, normalize_pattern

from .aat_chain import VerifiedChain

try:
    from tenuo import exceptions as _tex
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The AAT adapter needs the AAT reference implementation. Install it with: pip install tenuo"
    ) from exc


__all__ = ["ShieldRules", "AatDecision", "AatGate", "leaf_to_shield_rules"]


#: Rule ``target`` used for AAT-derived rules unless the caller says otherwise.
DEFAULT_TARGET = "filesystem"


@dataclass(frozen=True)
class ShieldRules:
    """Shield rules sourced from an AAT leaf.

    Tool scope maps directly: each tool the leaf authorises becomes one allow
    rule. Argument constraints do not map yet, so every rule carries
    ``resource: "**"`` and the reference implementation's evaluator remains the
    only gate on a call's arguments. Both must allow.
    """

    did: str
    target: str
    rules: tuple
    allowed_tools: frozenset
    unmapped_tools: tuple = ()
    leaf_jti: str = ""
    root_jti: str = ""

    def permits_tool(self, tool: str) -> bool:
        """Exact-string match, per draft Section 3.3.1 -- no normalization."""
        return tool in self.allowed_tools

    def as_rule_set(self) -> RuleSet:
        return RuleSet(by_did={self.did: list(self.rules)})


def leaf_to_shield_rules(
    chain: VerifiedChain,
    *,
    did: str = "did:vouch:aat-holder",
    target: str = DEFAULT_TARGET,
) -> ShieldRules:
    """Derive Shield rules from a verified chain's leaf.

    Each authorised tool becomes one allow rule. The resource is ``**``, because
    Shield cannot yet express the leaf's argument constraints; those stay with
    the reference implementation.
    """
    tools = sorted(chain.capabilities())
    rules = tuple(
        Rule(
            action=tool,
            target=target,
            resource=normalize_pattern("**"),
            id=f"aat:{chain.leaf_jti}:{tool}",
        )
        for tool in tools
    )
    return ShieldRules(
        did=did,
        target=target,
        rules=rules,
        allowed_tools=frozenset(tools),
        unmapped_tools=tuple(tools),
        leaf_jti=chain.leaf_jti,
        root_jti=chain.root_jti,
    )


@dataclass(frozen=True)
class AatDecision:
    """The outcome of a pre-execution check. ``allowed`` is the whole answer."""

    allowed: bool
    tool: str
    reason: Optional[str] = None
    leaf_jti: str = ""
    root_jti: str = ""
    failure: Optional[str] = None

    def __bool__(self) -> bool:
        return self.allowed


class AatGate:
    """Pre-execution gate combining AAT authority with Vouch Shield.

    Every decision happens before the tool runs. There is no path through this
    class that executes a tool and then checks it.

    Usage::

        chain = verify_chain_file("leaf.json")
        gate = AatGate(chain, holder_key=key)
        decision = gate.check("read_file", {"path": "reports/q3.txt"})
        if decision.allowed:
            run_tool()
    """

    def __init__(
        self,
        chain: VerifiedChain,
        *,
        holder_key: Any = None,
        shield: Any = None,
        did: Optional[str] = None,
    ) -> None:
        """
        Args:
            chain: A chain already verified by ``aat_chain.verify_chain``.
            holder_key: Optional signing key matching the leaf's authorized
                holder. Supplied, the gate mints the proof-of-possession for
                each call itself. That is a convenience for local and demo use:
                in a real deployment the PoP is produced by the caller holding
                the key and passed to ``check`` as ``signature``.
            shield: Optional ``vouch.shield.Shield``. When given, its verdict is
                combined with the AAT verdict and both must allow.
            did: DID to check Shield permissions against, when ``shield`` is set.
        """
        self._chain = chain
        self._holder_key = holder_key
        self._shield = shield
        self._did = did or "did:vouch:aat-holder"
        self.rules = leaf_to_shield_rules(chain, did=self._did)

    @property
    def chain(self) -> VerifiedChain:
        return self._chain

    def check(
        self,
        tool: str,
        args: Optional[Dict[str, Any]] = None,
        *,
        signature: Optional[bytes] = None,
        as_of: Optional[datetime] = None,
    ) -> AatDecision:
        """Decide whether a call may proceed. Never executes anything.

        Order: tool scope, then Shield, then the AAT reference implementation
        (which re-checks tool scope, evaluates argument constraints, enforces
        expiry, and verifies proof-of-possession). Any failure is fail-closed.
        """
        args = dict(args or {})

        def deny(reason: str, failure: Optional[str] = None) -> AatDecision:
            return AatDecision(
                allowed=False,
                tool=tool,
                reason=reason,
                leaf_jti=self.rules.leaf_jti,
                root_jti=self.rules.root_jti,
                failure=failure,
            )

        # 1. Tool scope from the leaf.
        if not self.rules.permits_tool(tool):
            return deny(
                f"Tool '{tool}' is not in the AAT leaf's authority "
                f"(leaf permits: {', '.join(sorted(self.rules.allowed_tools)) or 'nothing'})",
                failure="ToolNotAuthorized",
            )

        # 2. Shield, when configured. Both layers must allow.
        if self._shield is not None:
            result = self._shield.intercept(tool=tool, args=args, did=self._did)
            if not result.allowed:
                return deny(f"Shield denied: {result.reason}", failure="ShieldDenied")

        # 3. The AAT reference implementation: argument constraints, expiry, PoP.
        pop = signature
        if pop is None and self._holder_key is not None:
            try:
                pop = self._chain.leaf.sign(self._holder_key, tool, args, int(time.time()))
            except Exception as exc:
                return deny(f"Could not produce proof-of-possession: {exc}", failure="PopError")

        try:
            self._chain._authorizer.check_chain(self._chain.warrants, tool, args, signature=pop)
        except _tex.TenuoError as exc:
            return deny(f"{type(exc).__name__}: {exc}", failure=type(exc).__name__)
        except Exception as exc:  # unknown means deny
            return deny(f"AAT check failed: {exc}", failure=type(exc).__name__)

        return AatDecision(
            allowed=True,
            tool=tool,
            leaf_jti=self.rules.leaf_jti,
            root_jti=self.rules.root_jti,
        )
