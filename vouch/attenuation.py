"""v1.7 capability attenuation: the non-expansion rule over the six delegation
dimensions, verifier cost budgets, and chain-cascade revocation
(Specification 9.3-9.6).

This is a faithful port of ``core/vouch-core/src/attenuation.rs``. The two MUST
agree verdict-for-verdict; the shared vectors in
``test-vectors/delegation-attenuation/vector.json`` are the contract.

Security posture: default-deny. Any malformed input, unknown shape, or
ambiguous comparison rejects rather than admits, because a delegation chain
grants authority and a false "valid" is an authority-escalation bug.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

_RATE_EPSILON = 1e-9
_DIMENSIONS = ("action", "target", "resource", "time", "rate", "policy")


def _iso_to_epoch(s: str) -> int:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return int(dt.timestamp())


def _string_set(v: Any) -> Optional[set]:
    """None -> absent; a str or list[str] -> set; anything else raises."""
    if v is None:
        return None
    if isinstance(v, str):
        return {v}
    if isinstance(v, list):
        out = set()
        for item in v:
            if not isinstance(item, str):
                raise ValueError("action/target array must be strings")
            out.add(item)
        return out
    raise ValueError("action/target must be a string or array")


def _is_sub_resource(child: str, parent: str) -> bool:
    c = child.rstrip("/")
    p = parent.rstrip("/")
    if c == p:
        return True
    return len(c) > len(p) and c.startswith(p) and c[len(p)] == "/"


def _parse_duration_seconds(s: str) -> int:
    if not s or s[0] != "P":
        raise ValueError(f"invalid duration: {s}")
    total = 0
    num = ""
    in_time = False
    saw_field = False
    for ch in s[1:]:
        if ch == "T":
            in_time = True
        elif ch.isdigit():
            num += ch
        elif ch in ("D", "H", "M", "S"):
            if num == "":
                raise ValueError(f"invalid duration: {s}")
            n = int(num)
            if ch == "D":
                total += n * 86_400
            elif ch == "H":
                total += n * 3_600
            elif ch == "M":
                total += n * 60 if in_time else n * 2_592_000
            else:  # S
                total += n
            num = ""
            saw_field = True
        else:
            raise ValueError(f"invalid duration: {s}")
    if not saw_field or num != "":
        raise ValueError(f"invalid duration: {s}")
    return total


def _rate_events_per_sec(rate: Any) -> float:
    if not isinstance(rate, dict):
        raise ValueError("rate must be an object")
    limit = rate.get("limit")
    if not isinstance(limit, (int, float)) or isinstance(limit, bool) or limit < 0:
        raise ValueError("rate.limit must be a non-negative number")
    window = rate.get("window")
    if not isinstance(window, str):
        raise ValueError("rate.window must be an ISO-8601 duration")
    secs = _parse_duration_seconds(window)
    if secs <= 0:
        raise ValueError("rate.window must be positive")
    return float(limit) / float(secs)


def _policy_not_weaker(parent: Any, child: Any) -> bool:
    if not isinstance(parent, dict) or not isinstance(child, dict):
        return False
    for k, pv in parent.items():
        if k not in child:
            return False  # child dropped a parent constraint => weaker
        cv = child[k]
        p_num = isinstance(pv, (int, float)) and not isinstance(pv, bool)
        c_num = isinstance(cv, (int, float)) and not isinstance(cv, bool)
        if p_num and c_num:
            if cv < pv:
                return False
        elif p_num != c_num:
            return False  # type mismatch
        else:
            if pv != cv:
                return False  # non-numeric must match exactly
    return True


def _window(link: dict):
    vf = link.get("validFrom")
    vu = link.get("validUntil")
    return (
        _iso_to_epoch(vf) if isinstance(vf, str) else None,
        _iso_to_epoch(vu) if isinstance(vu, str) else None,
    )


def non_expansion(parent: dict, child: dict) -> Optional[str]:
    """Return the offending dimension name if ``child`` broadens ``parent``,
    else None."""
    p_intent = parent.get("intent") or {}
    c_intent = child.get("intent") or {}

    # action / target: child set must be a subset of the parent's.
    for dim in ("action", "target"):
        c_raw = c_intent.get(dim) if isinstance(c_intent, dict) else None
        if c_raw is not None:
            try:
                c_set = _string_set(c_raw)
            except ValueError:
                return dim
            p_set = _string_set(p_intent.get(dim)) if isinstance(p_intent, dict) else None
            if c_set is not None and p_set is not None and not c_set.issubset(p_set):
                return dim

    # resource: child resource must be a sub-resource of the parent's.
    c_res = c_intent.get("resource") if isinstance(c_intent, dict) else None
    if c_res is not None:
        if not isinstance(c_res, str):
            return "resource"
        p_res = p_intent.get("resource") if isinstance(p_intent, dict) else None
        if isinstance(p_res, str) and not _is_sub_resource(c_res, p_res):
            return "resource"

    # time: child window within parent's.
    try:
        cf, cu = _window(child)
        pf, pu = _window(parent)
    except ValueError:
        return "time"
    if cf is not None and pf is not None and cf < pf:
        return "time"
    if cu is not None and pu is not None and cu > pu:
        return "time"

    # rate: child events/sec must not exceed the parent's.
    c_rate = child.get("rate")
    if c_rate is not None:
        try:
            ce = _rate_events_per_sec(c_rate)
        except ValueError:
            return "rate"
        p_rate = parent.get("rate")
        if p_rate is not None:
            try:
                pe = _rate_events_per_sec(p_rate)
            except ValueError:
                return "rate"
            if ce > pe + _RATE_EPSILON:
                return "rate"

    # policy: child must be equal to or stricter than the parent's.
    c_pol = child.get("policy")
    if c_pol is not None:
        p_pol = parent.get("policy")
        if p_pol is not None and not _policy_not_weaker(p_pol, c_pol):
            return "policy"

    return None


def validate_chain(
    chain: List[dict],
    trusted_roots: Optional[List[str]] = None,
    revoked_indices: Optional[List[int]] = None,
    budget: Optional[Dict[str, Any]] = None,
    now_iso: str = "",
    clock_skew_seconds: int = 30,
) -> Dict[str, Any]:
    """Validate a delegation chain (root -> leaf) under the v1.7 rules and
    return a verdict dict identical in shape to the core JSON boundary."""
    trusted_roots = trusted_roots or []
    revoked_indices = revoked_indices or []
    budget = budget or {}

    if not chain:
        return {"valid": False, "code": "malformed_delegation", "detail": "empty delegation chain"}

    max_depth = budget.get("maxDepth")
    if isinstance(max_depth, int) and len(chain) > max_depth:
        return {"valid": False, "code": "verifier_budget_exceeded", "limit": "depth"}

    for i, link in enumerate(chain):
        if (
            not isinstance(link, dict)
            or not isinstance(link.get("issuer"), str)
            or not isinstance(link.get("subject"), str)
        ):
            return {"valid": False, "code": "malformed_delegation", "detail": f"link {i} malformed"}

    if trusted_roots:
        if chain[0]["issuer"] not in trusted_roots:
            return {"valid": False, "code": "untrusted_principal"}

    revoked = [i for i in revoked_indices if 0 <= i < len(chain)]
    if revoked:
        return {"valid": False, "code": "delegation_revoked", "linkIndex": min(revoked)}

    for i in range(1, len(chain)):
        parent, child = chain[i - 1], chain[i]
        if parent.get("subject") != child.get("issuer"):
            return {"valid": False, "code": "subject_issuer_mismatch", "linkIndex": i}
        dim = non_expansion(parent, child)
        if dim is not None:
            return {"valid": False, "code": "scope_exceeds_parent", "dimension": dim}

    eff_start = None
    eff_end = None
    cumulative_ttl = 0
    try:
        for link in chain:
            vf, vu = _window(link)
            if vf is not None:
                eff_start = vf if eff_start is None else max(eff_start, vf)
            if vu is not None:
                eff_end = vu if eff_end is None else min(eff_end, vu)
            if vf is not None and vu is not None and vu >= vf:
                cumulative_ttl += vu - vf
        now = _iso_to_epoch(now_iso)
    except ValueError as e:
        return {"valid": False, "code": "malformed_delegation", "detail": str(e)}

    if eff_start is not None and now < eff_start - clock_skew_seconds:
        return {"valid": False, "code": "outside_validity_window"}
    if eff_end is not None and now > eff_end + clock_skew_seconds:
        return {"valid": False, "code": "outside_validity_window"}

    max_ttl = budget.get("maxCumulativeTtlSeconds")
    if isinstance(max_ttl, int) and cumulative_ttl > max_ttl:
        return {"valid": False, "code": "verifier_budget_exceeded", "limit": "cumulative_ttl"}

    return {"valid": True}


def validate_chain_json(request_json: str) -> str:
    """JSON boundary matching the core: request in, verdict JSON out. Infallible."""
    try:
        req = json.loads(request_json)
    except json.JSONDecodeError as e:
        return json.dumps(
            {"valid": False, "code": "malformed_delegation", "detail": f"request json: {e}"}
        )
    if not isinstance(req.get("chain"), list):
        return json.dumps(
            {"valid": False, "code": "malformed_delegation", "detail": "missing chain array"}
        )
    verdict = validate_chain(
        chain=req["chain"],
        trusted_roots=req.get("trustedRoots"),
        revoked_indices=req.get("revokedIndices"),
        budget=req.get("budget"),
        now_iso=req.get("nowIso", ""),
        clock_skew_seconds=req.get("clockSkewSeconds", 30),
    )
    return json.dumps(verdict)
