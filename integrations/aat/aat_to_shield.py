"""Translate a verified AAT leaf into Vouch Shield rules, and enforce them.

Only the **leaf** matters for enforcement. A derived AAT already states its own
narrowed authority, so there is nothing to intersect: the chain is verified for
provenance, the leaf is what is enforced. See ``DESIGN.md``.

The mapping is deliberately partial, and the partiality is the interesting part.
Shield's permission check has the signature ``check_permission(did, tool)`` --
it never sees the call's arguments, so it structurally cannot express an AAT
argument constraint such as ``path`` matching ``reports/*``. Flattening those
constraints into Shield's capability levels would silently widen authority: a
leaf restricted to ``reports/*`` would become a blanket filesystem-read grant,
and ``read_file /etc/passwd`` would pass. So this module does not flatten them.

Instead:

- **Tool scope** becomes Shield rules -- an explicit allowlist plus the least
  capability set that admits exactly those tools.
- **Argument constraints** stay with the AAT reference implementation, and are
  evaluated by ``Authorizer.check_chain`` in the same pre-execution step.

Both must allow. Either refusing means the tool does not run.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from vouch.shield.permissions import (
    TOOL_REQUIREMENTS,
    Capabilities,
    NetworkLevel,
    PermissionLevel,
    ShellLevel,
)

from .aat_chain import VerifiedChain

try:
    from tenuo import exceptions as _tex
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The AAT adapter needs the AAT reference implementation. Install it with: pip install tenuo"
    ) from exc


__all__ = ["ShieldRules", "AatDecision", "AatGate", "leaf_to_shield_rules"]


# Ordered weakest -> strongest, matching vouch.shield.permissions.
_LEVELS = {
    "filesystem": (["none", "read", "write", "full"], PermissionLevel),
    "network": (["none", "internal", "outbound", "full"], NetworkLevel),
    "shell": (["none", "sandboxed", "full"], ShellLevel),
}


@dataclass(frozen=True)
class ShieldRules:
    """Shield rules sourced from an AAT leaf.

    ``allowed_tools`` is authoritative. ``capabilities`` alone would be too
    permissive: Shield's capability levels are per-resource, not per-tool, so a
    leaf granting ``read_file`` yields ``filesystem=read``, which would also
    admit ``list_directory``. The allowlist is what pins enforcement to exactly
    the tools the leaf names.
    """

    allowed_tools: frozenset
    capabilities: Capabilities
    unmapped_tools: tuple = ()
    leaf_jti: str = ""
    root_jti: str = ""

    def permits_tool(self, tool: str) -> bool:
        """Exact-string match, per draft Section 3.3.1 -- no normalization."""
        return tool in self.allowed_tools


def leaf_to_shield_rules(chain: VerifiedChain) -> ShieldRules:
    """Derive Shield rules from a verified chain's leaf.

    The capability set is the least one that admits exactly the leaf's tools:
    the per-resource maximum over each tool's entry in ``TOOL_REQUIREMENTS``.
    Tools with no entry are reported in ``unmapped_tools`` -- Shield denies
    unknown tools by default, which is the fail-closed behaviour we want, so
    they are surfaced rather than silently granted a capability.
    """
    tools = list(chain.tools)

    levels: Dict[str, str] = {"filesystem": "none", "network": "none", "shell": "none"}
    unmapped: List[str] = []

    for tool in tools:
        requirements = TOOL_REQUIREMENTS.get(tool.lower())
        if requirements is None:
            unmapped.append(tool)
            continue
        for resource, required in requirements.items():
            order, _ = _LEVELS.get(resource, (None, None))
            if order is None:
                # An unrecognised resource dimension. Do not guess -- treat the
                # tool as unmapped so it shows up rather than being waved through.
                unmapped.append(tool)
                continue
            if order.index(required) > order.index(levels[resource]):
                levels[resource] = required

    capabilities = Capabilities(
        filesystem=PermissionLevel(levels["filesystem"]),
        network=NetworkLevel(levels["network"]),
        shell=ShellLevel(levels["shell"]),
    )

    return ShieldRules(
        allowed_tools=frozenset(tools),
        capabilities=capabilities,
        unmapped_tools=tuple(sorted(set(unmapped))),
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
        self._did = did
        self.rules = leaf_to_shield_rules(chain)

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
