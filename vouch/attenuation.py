"""
Capability attenuation for delegation chains.

Specification v1.7, Sections 9.3 to 9.5 (see docs/specs/w3c-cg-report-v1.7-draft.md).

Core rule (settled): every delegated capability MUST be a proper subset of its
parent across at least one of {action, target, resource, time, rate, policy},
and MUST NOT be broader on any dimension. A chain ends naturally when nothing
remains to narrow; there is no fixed maximum depth (the v1.6.2 depth cap is
removed). Cost control moves to optional, verifier-local budgets.

This module is the cross-language reference. The TypeScript and Go SDKs mirror
its behavior byte-for-byte: identical accept/reject decisions and identical
rejection-reason strings on every shared interop vector.

Three edge policies are intentionally left open (pending Alan Karp's input),
exposed here as configuration hooks rather than hardcoded rules:
  - meaningful-narrowing threshold (CH-001 open question 1): see ``meaningful_narrowing``.
  - leaf/termination wording (CH-001 open question 2): falls out of the subset rule.
  - chain-cascade revocation (CH-003): see ``cascade_revocation_hook``.
Do not freeze these as final behavior until the open questions resolve.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Structured rejection reasons (stable strings, shared across the three SDKs).
# ---------------------------------------------------------------------------

REASON_CAPABILITY_NOT_ATTENUATED = "capability_not_attenuated"
REASON_RESOURCE_NOT_NARROWED = "resource_not_narrowed"
REASON_VERIFIER_BUDGET_EXCEEDED = "verifier_budget_exceeded"

# NOTE: "chain_depth_exceeded" is removed as a protocol-level hard error in
# v1.7. Depth is now a verifier-budget concern and surfaces, when a verifier
# chooses to cap it, as REASON_VERIFIER_BUDGET_EXCEEDED with limit "max_depth".

ATTENUATION_DIMENSIONS = ("action", "target", "resource", "time", "rate", "policy")


@dataclass
class VerifierBudget:
    """
    Optional, verifier-local cost cap (Specification v1.7 Section 9.4).

    None on every field means unlimited: there is NO protocol-level cap. A
    verifier MAY set any subset of these to bound the work it spends on a
    chain. Exceeding a set limit yields REASON_VERIFIER_BUDGET_EXCEEDED with the
    specific limit named, so the delegating agent narrows earlier instead of
    routing around the block.
    """

    max_depth: Optional[int] = None
    max_verification_seconds: Optional[float] = None
    max_cumulative_ttl_seconds: Optional[int] = None


@dataclass
class AttenuationResult:
    """Outcome of an attenuation/budget check."""

    ok: bool
    reason: Optional[str] = None
    detail: Optional[str] = None
    # Dimensions on which the child was strictly narrower than its parent.
    narrowed_on: List[str] = field(default_factory=list)


# A capability is a plain dict with any of:
#   action: str | list[str]
#   target: str | list[str]
#   resource: str
#   validFrom / validUntil: ISO-8601 str (the time dimension)
#   rate: {"limit": int, "window": ISO-8601 duration or seconds}
#   policy: dict
Capability = Dict[str, Any]

# Optional hook: meaningful-narrowing threshold (CH-001 open question 1).
# Receives (parent, child, narrowed_on) and returns True if the narrowing is
# "meaningful" per verifier policy. Default (None) accepts any proper subset on
# at least one dimension (the permissive rule). A verifier MAY supply a stricter
# hook, for example requiring narrowing on action/target/resource rather than a
# trivial rate 100 -> 99. TODO(CH-001 Q1): do not hardcode a final threshold.
MeaningfulNarrowingHook = Callable[[Capability, Capability, List[str]], bool]

# Optional hook: policy-dimension comparator. Returns one of "narrower",
# "equal", "broader", "incomparable". Default comparator is conservative
# (see _compare_policy). Supplied so deployments with domain-specific policy
# fields can define strictness without changing this module.
PolicyComparator = Callable[[Dict[str, Any], Dict[str, Any]], str]

# Optional extension point: chain-cascade revocation (CH-003). Receives the full
# ordered capability chain and returns an AttenuationResult; return ok=True to
# accept. Default (None) performs NO cascade check. TODO(CH-003): the cascade
# semantics (does revoking/rotating a mid-chain link invalidate everything
# downstream) are not yet specified. Do not assume a final rule here.
CascadeRevocationHook = Callable[[List[Capability]], AttenuationResult]


# ---------------------------------------------------------------------------
# Per-dimension subset tests. Each returns (is_subset, is_strict_subset).
# "is_subset" means the child does NOT broaden this dimension.
# "is_strict_subset" means the child is strictly narrower on this dimension.
# A dimension absent on the child is inherited unchanged (subset, not strict).
# ---------------------------------------------------------------------------


def _as_set(value: Any) -> Optional[set]:
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return set(value)
    return {value}


def _check_action(parent: Capability, child: Capability) -> Tuple[bool, bool]:
    p = _as_set(parent.get("action"))
    c = _as_set(child.get("action"))
    if c is None or c == p:
        return True, False  # inherited or unchanged
    if p is None:
        # Parent unconstrained, child constrains: narrower.
        return True, True
    if c <= p:
        return True, c < p
    return False, False  # child has actions the parent lacks: broader


def _check_target(parent: Capability, child: Capability) -> Tuple[bool, bool]:
    p = _as_set(parent.get("target"))
    c = _as_set(child.get("target"))
    if c is None or c == p:
        return True, False
    if p is None:
        return True, True
    if c <= p:
        return True, c < p
    return False, False


def is_sub_resource(child: str, parent: str) -> bool:
    """
    True if ``child`` is a sub-resource of (or equal to) ``parent``. Conservative
    URL-prefix match: child must equal parent or extend it after a path
    separator. Mirrors the v1.6.2 resource-narrowing rule (Section 9.3 step 5).
    """
    # Reject relative path-traversal segments (".."): a child like
    # "https://api/v1/../admin" passes a naive prefix check yet resolves outside
    # the granted scope, so it must not count as a sub-resource.
    if _has_path_traversal(child) or _has_path_traversal(parent):
        return False
    if child == parent:
        return True
    if child.startswith(parent.rstrip("/") + "/"):
        return True
    return False


def _has_path_traversal(uri: str) -> bool:
    return ".." in uri.split("/")


def _check_resource(parent: Capability, child: Capability) -> Tuple[bool, bool]:
    p = parent.get("resource")
    c = child.get("resource")
    if not c or c == p:
        return True, False
    if not p:
        return True, True
    if is_sub_resource(c, p):
        return True, c != p
    return False, False


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _check_time(parent: Capability, child: Capability) -> Tuple[bool, bool]:
    pf, pu = _parse_iso(parent.get("validFrom")), _parse_iso(parent.get("validUntil"))
    cf, cu = _parse_iso(child.get("validFrom")), _parse_iso(child.get("validUntil"))
    if cf is None and cu is None:
        return True, False  # inherited
    # Child interval must lie within the parent interval on both ends.
    if pf is not None and cf is not None and cf < pf:
        return False, False
    if pu is not None and cu is not None and cu > pu:
        return False, False
    strict = (pf is not None and cf is not None and cf > pf) or (
        pu is not None and cu is not None and cu < pu
    )
    return True, strict


def _rate_per_second(rate: Optional[Dict[str, Any]]) -> Optional[float]:
    if not rate:
        return None
    limit = rate.get("limit")
    if limit is None:
        return None
    window = rate.get("window", 1)
    seconds = _duration_seconds(window)
    if seconds is None or seconds <= 0:
        return None
    try:
        return float(limit) / float(seconds)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _duration_seconds(window: Any) -> Optional[float]:
    """Parse a rate window: a number of seconds, or a simple ISO-8601 duration."""
    if isinstance(window, (int, float)):
        return float(window)
    if not isinstance(window, str):
        return None
    s = window.strip().upper()
    if not s.startswith("P"):
        try:
            return float(s)
        except ValueError:
            return None
    # Minimal ISO-8601 duration parse for the common PT#H/PT#M/PT#S and P#D forms.
    import re

    m = re.fullmatch(
        r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", s
    )
    if not m:
        return None
    days, hours, mins, secs = (int(g) if g else 0 for g in m.groups())
    total = days * 86400 + hours * 3600 + mins * 60 + secs
    return float(total) if total > 0 else None


def _check_rate(parent: Capability, child: Capability) -> Tuple[bool, bool]:
    child_has_rate = child.get("rate") is not None
    p = _rate_per_second(parent.get("rate"))
    c = _rate_per_second(child.get("rate"))
    if not child_has_rate:
        return True, False  # absent: inherited
    if c is None:
        # rate present but unparseable (for example window 0): we cannot prove it
        # narrows, so treat it as broadening rather than silently inheriting,
        # which would be a rate-cap bypass.
        return False, False
    if p is None:
        return True, True  # parent unconstrained, child caps: narrower
    if c <= p:
        return True, c < p
    return False, False


def _compare_policy(parent: Dict[str, Any], child: Dict[str, Any]) -> str:
    """
    Conservative default policy comparator.

    A policy is "narrower" (stricter) when the child keeps every constraint the
    parent had AND adds at least one. It is "equal" when identical. It is
    "broader" when the child relaxes or removes a parent constraint. Numeric
    fields are treated as constraints whose values must match unless a
    deployment supplies its own PolicyComparator that knows the strictness
    direction of a given field. TODO(CH-001 Q1): policy strictness direction is
    deployment-specific; do not assume a global numeric direction here.
    """
    if parent == child:
        return "equal"
    parent_keys = set(parent.keys())
    child_keys = set(child.keys())
    # Any parent key dropped, or any shared key whose value changed, is broader
    # under the conservative default (we cannot prove it got stricter).
    if not parent_keys <= child_keys:
        return "broader"
    for k in parent_keys:
        if parent[k] != child[k]:
            return "broader"
    # Child kept all parent constraints and added more: stricter.
    if child_keys > parent_keys:
        return "narrower"
    return "equal"


def _check_policy(
    parent: Capability,
    child: Capability,
    comparator: Optional[PolicyComparator],
) -> Tuple[bool, bool]:
    p = parent.get("policy")
    c = child.get("policy")
    if c is None:
        return True, False  # inherited
    if not p:
        return True, bool(c)  # parent unconstrained, child adds policy: narrower
    cmp = (comparator or _compare_policy)(p, c)
    if cmp == "broader" or cmp == "incomparable":
        return False, False
    return True, cmp == "narrower"


_DIMENSION_CHECKS = {
    "action": lambda p, c, pc: _check_action(p, c),
    "target": lambda p, c, pc: _check_target(p, c),
    "resource": lambda p, c, pc: _check_resource(p, c),
    "time": lambda p, c, pc: _check_time(p, c),
    "rate": lambda p, c, pc: _check_rate(p, c),
    "policy": lambda p, c, pc: _check_policy(p, c, pc),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_attenuation(
    parent: Capability,
    child: Capability,
    *,
    meaningful_narrowing: Optional[MeaningfulNarrowingHook] = None,
    policy_comparator: Optional[PolicyComparator] = None,
) -> AttenuationResult:
    """
    Check the attenuation rule for one (parent, child) capability pair.

    Returns ok=True iff the child is a proper subset of the parent across at
    least one dimension and broader on none. On failure, ``reason`` is
    REASON_RESOURCE_NOT_NARROWED when the offending dimension is the resource,
    else REASON_CAPABILITY_NOT_ATTENUATED.
    """
    narrowed_on: List[str] = []
    for dim in ATTENUATION_DIMENSIONS:
        is_subset, is_strict = _DIMENSION_CHECKS[dim](parent, child, policy_comparator)
        if not is_subset:
            reason = (
                REASON_RESOURCE_NOT_NARROWED
                if dim == "resource"
                else REASON_CAPABILITY_NOT_ATTENUATED
            )
            return AttenuationResult(False, reason, detail=f"broader on {dim}")
        if is_strict:
            narrowed_on.append(dim)

    if not narrowed_on:
        # Subset on every dimension but strictly narrower on none: not attenuated.
        return AttenuationResult(
            False, REASON_CAPABILITY_NOT_ATTENUATED, detail="no dimension narrowed"
        )

    # TODO(CH-001 Q1): optional stricter "meaningful narrowing" policy. The
    # permissive default accepts a proper subset on any single dimension.
    if meaningful_narrowing is not None and not meaningful_narrowing(
        parent, child, narrowed_on
    ):
        return AttenuationResult(
            False,
            REASON_CAPABILITY_NOT_ATTENUATED,
            detail="narrowing not meaningful (verifier policy)",
            narrowed_on=narrowed_on,
        )

    return AttenuationResult(True, narrowed_on=narrowed_on)


def find_broadened_dimension(
    parent: Capability,
    child: Capability,
    *,
    policy_comparator: Optional[PolicyComparator] = None,
) -> Optional[str]:
    """
    Return the first dimension on which ``child`` BROADENS ``parent``, or None.

    Builder-side helper: a delegator can never grant more than it holds, so the
    builder blocks any outright broadening. It does NOT require strict narrowing
    (the full attenuation rule, narrowing on at least one dimension, is enforced
    by the verifier via ``check_attenuation`` / ``validate_chain``). This keeps
    the builder permissive enough for equal-capability pass-through while still
    refusing to widen authority.
    """
    for dim in ATTENUATION_DIMENSIONS:
        is_subset, _ = _DIMENSION_CHECKS[dim](parent, child, policy_comparator)
        if not is_subset:
            return dim
    return None


def validate_chain(
    capabilities: List[Capability],
    *,
    budget: Optional[VerifierBudget] = None,
    meaningful_narrowing: Optional[MeaningfulNarrowingHook] = None,
    policy_comparator: Optional[PolicyComparator] = None,
    cascade_revocation_hook: Optional[CascadeRevocationHook] = None,
    elapsed_seconds: Optional[float] = None,
) -> AttenuationResult:
    """
    Validate a full delegation chain, ordered broadest (root) to narrowest (leaf).

    Each adjacent pair (capabilities[i], capabilities[i+1]) must satisfy the
    attenuation rule. The chain terminates naturally at a leaf where nothing can
    narrow further (CH-001 Q2: this falls out of the subset rule; no explicit
    leaf condition is hardcoded). Verifier cost budgets are applied first and,
    on breach, return REASON_VERIFIER_BUDGET_EXCEEDED naming the limit hit.
    """
    # "depth" is the number of capability nodes in the chain (for a delegation
    # chain, the number of delegation links). Adjacent attenuation is checked
    # over the depth-1 edges between them.
    depth = len(capabilities)

    # Verifier cost budget: depth (replaces the removed protocol depth cap).
    if budget is not None and budget.max_depth is not None and depth > budget.max_depth:
        return AttenuationResult(
            False, REASON_VERIFIER_BUDGET_EXCEEDED, detail=f"max_depth={budget.max_depth}"
        )

    # Verifier cost budget: cumulative validity (TTL) across the chain.
    if budget is not None and budget.max_cumulative_ttl_seconds is not None:
        total_ttl = _cumulative_ttl_seconds(capabilities)
        if total_ttl is not None and total_ttl > budget.max_cumulative_ttl_seconds:
            return AttenuationResult(
                False,
                REASON_VERIFIER_BUDGET_EXCEEDED,
                detail=f"max_cumulative_ttl_seconds={budget.max_cumulative_ttl_seconds}",
            )

    # Verifier cost budget: total verification time (caller measures, passes in).
    if (
        budget is not None
        and budget.max_verification_seconds is not None
        and elapsed_seconds is not None
        and elapsed_seconds > budget.max_verification_seconds
    ):
        return AttenuationResult(
            False,
            REASON_VERIFIER_BUDGET_EXCEEDED,
            detail=f"max_verification_seconds={budget.max_verification_seconds}",
        )

    for i in range(max(0, depth - 1)):
        result = check_attenuation(
            capabilities[i],
            capabilities[i + 1],
            meaningful_narrowing=meaningful_narrowing,
            policy_comparator=policy_comparator,
        )
        if not result.ok:
            return result

    # TODO(CH-003): chain-cascade revocation. The cascade semantics (mid-chain
    # revocation or key rotation invalidating downstream links) are not yet
    # specified. The hook is an extension point only; default does nothing.
    if cascade_revocation_hook is not None:
        cascade = cascade_revocation_hook(capabilities)
        if cascade is not None and not cascade.ok:
            return cascade

    return AttenuationResult(True)


def _cumulative_ttl_seconds(capabilities: List[Capability]) -> Optional[float]:
    total = 0.0
    seen = False
    for cap in capabilities:
        cf, cu = _parse_iso(cap.get("validFrom")), _parse_iso(cap.get("validUntil"))
        if cf is not None and cu is not None:
            total += max(0.0, (cu - cf).total_seconds())
            seen = True
    return total if seen else None
