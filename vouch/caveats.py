"""
Executable caveats: conditional authority that travels inside a delegation chain.

Capability attenuation narrows *static* fields (action, target, resource, time,
rate). Real grants are *conditional*: "approve refunds, but only for orders that
shipped, and never above the customer's lifetime spend," "only during a declared
incident," "never two disbursements to the same payee within an hour." None of
that is a narrowing of a static field.

This module attaches **caveats** to the links of a delegation chain. A caveat is
a deterministic, side-effect-free predicate over a proposed action's context.
Three properties make it real enforcement rather than advice:

  1. Every verifier MUST evaluate every accumulated caveat, and denies if any one
     denies.
  2. Caveats **accumulate** down the chain: a grantor's condition binds every
     descendant, however many hops away.
  3. No descendant can **remove** an ancestor's caveat, because each link signs
     its caveat set and its parent, and a verifier requires the presented chain
     to root at the grantor.

The reference caveats here are a small **standard library** (value and
running-total ceilings, time windows, allow-lists, an incident gate, a rate
limit, a boolean flag). Each is declarative and parameterised, so it evaluates
identically in every language SDK without shipping code. A custom caveat pinned
by module hash is the documented escape hatch for logic the standard set cannot
express. This is the on-protocol form of the method disclosed in PAD-086.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import data_integrity
from .jcs import canonicalize

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"

CAPABILITY_TYPE = "CapabilityDelegation"

# Structured reasons (stable strings, mirrored by the SDKs).
REASON_INVALID_LINK_PROOF = "invalid_link_proof"
REASON_BROKEN_CHAIN = "broken_chain"
REASON_UNROOTED = "unrooted_capability"
REASON_UNKNOWN_TYPE = "caveat_unknown_type"
REASON_MODULE_UNAVAILABLE = "caveat_module_unavailable"
REASON_BUDGET_EXCEEDED = "verifier_budget_exceeded"


class CaveatError(Exception):
    """Raised on malformed caveat or capability input."""


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mb64(b: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _digest(obj: Any) -> str:
    return _mb64(hashlib.sha256(canonicalize(obj)).digest())


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise CaveatError("signing requires a Signer with an Ed25519 key")
    return raw


def _attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    credential["proof"] = data_integrity.build_proof(
        credential, _raw_priv(signer), signer.verification_method_id()
    )
    return credential


def _type_list(credential: Dict[str, Any]) -> list:
    t = credential.get("type") or []
    return [t] if isinstance(t, str) else list(t)


# ---------------------------------------------------------------------------
# Caveat construction and evaluation (the standard library)
# ---------------------------------------------------------------------------


def caveat(cav_id: str, cav_type: str, **params: Any) -> Dict[str, Any]:
    """Build a caveat: an id, a type from the standard library, and its params."""
    if not cav_id or not cav_type:
        raise CaveatError("a caveat needs an id and a type")
    return {"id": cav_id, "type": cav_type, "params": dict(params)}


# Named convenience builders for the standard caveats.
def value_ceiling(cav_id: str, *, field: str = "amount", limit: float) -> Dict[str, Any]:
    return caveat(cav_id, "value_ceiling", field=field, max=limit)


def running_total_ceiling(
    cav_id: str, *, field: str = "amount", total_field: str = "runningTotal", limit: float
) -> Dict[str, Any]:
    return caveat(cav_id, "running_total_ceiling", field=field, total_field=total_field, max=limit)


def time_window(cav_id: str, *, field: str = "hour", start: int, end: int) -> Dict[str, Any]:
    return caveat(cav_id, "time_window", field=field, start=start, end=end)


def allowlist(cav_id: str, *, field: str, values: List[Any]) -> Dict[str, Any]:
    return caveat(cav_id, "allowlist", field=field, values=list(values))


def flag_true(cav_id: str, *, field: str) -> Dict[str, Any]:
    return caveat(cav_id, "flag_true", field=field)


def incident_gate(cav_id: str, *, field: str = "incidentActive") -> Dict[str, Any]:
    return caveat(cav_id, "incident_gate", field=field)


def rate_limit(cav_id: str, *, count_field: str = "recentCount", max_count: int) -> Dict[str, Any]:
    return caveat(cav_id, "rate_limit", count_field=count_field, max_count=max_count)


def _num(ctx: Dict[str, Any], key: str) -> float:
    v = ctx.get(key)
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        raise CaveatError(f"context.{key} must be a number")
    return float(v)


def evaluate_caveat(cav: Dict[str, Any], context: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Evaluate one caveat against an action context.

    Returns ``(True, None)`` if the caveat is satisfied, else
    ``(False, reason)``. Deterministic: no clock, randomness, or I/O; every input
    comes from ``context``. An unknown standard type, or a custom module with no
    registered runtime, denies with a structured reason.
    """
    t = cav.get("type")
    p = cav.get("params") or {}

    if t == "value_ceiling":
        ok = _num(context, p["field"]) <= p["max"]
    elif t == "running_total_ceiling":
        ok = _num(context, p["total_field"]) + _num(context, p["field"]) <= p["max"]
    elif t == "time_window":
        h = _num(context, p["field"])
        ok = p["start"] <= h < p["end"]
    elif t == "allowlist":
        ok = context.get(p["field"]) in p["values"]
    elif t == "flag_true":
        ok = context.get(p["field"]) is True
    elif t == "incident_gate":
        ok = context.get(p["field"]) is True
    elif t == "rate_limit":
        ok = _num(context, p["count_field"]) < p["max_count"]
    elif cav.get("moduleHash"):
        # A custom WASM caveat: the escape hatch. Denies here until a conforming
        # deterministic runtime is registered to evaluate the pinned module.
        return (False, REASON_MODULE_UNAVAILABLE)
    else:
        return (False, REASON_UNKNOWN_TYPE)

    return (True, None) if ok else (False, f"caveat_denied:{cav.get('id')}")


# ---------------------------------------------------------------------------
# Signed capability links carrying caveats
# ---------------------------------------------------------------------------


def build_capability(
    signer: Any,
    *,
    to: str,
    attenuation: Dict[str, Any],
    caveats: Optional[List[Dict[str, Any]]] = None,
    parent: Optional[Dict[str, Any]] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Issue a signed capability-delegation link, optionally carrying caveats and
    referencing a parent link (whose digest it pins).
    """
    subject: Dict[str, Any] = {"to": to, "attenuation": dict(attenuation)}
    if caveats:
        subject["caveats"] = list(caveats)
    if parent is not None:
        subject["parent"] = {"id": parent.get("id"), "digest": _digest(parent)}

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", CAPABILITY_TYPE],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": signer.get_did(),
        "validFrom": _iso(datetime.now(timezone.utc)),
        "credentialSubject": subject,
    }
    return _attach_proof(credential, signer)


def chain_caveats(chain: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The accumulated (effective) caveat set of a root-to-leaf chain: the union
    of every link's caveats, de-duplicated by id, ancestors first."""
    seen, out = set(), []
    for link in chain:
        for cav in (link.get("credentialSubject") or {}).get("caveats", []) or []:
            cid = cav.get("id")
            if cid not in seen:
                seen.add(cid)
                out.append(cav)
    return out


def verify_capability(
    chain: List[Dict[str, Any]],
    key_resolver: Callable[[str], Any],
    context: Dict[str, Any],
    *,
    root_issuer: Optional[str] = None,
    max_caveats: Optional[int] = None,
) -> Optional[str]:
    """
    Verify a capability chain and evaluate its accumulated caveats.

    Returns None if the action is allowed, else a structured reason. Checks, in
    order: each link's signature and its parent-digest linkage; that the chain
    roots at ``root_issuer`` when given (so a descendant cannot shed an ancestor
    caveat by presenting a shortened chain); an optional caveat-count budget; and
    finally every accumulated caveat against ``context``.

    Args:
        chain: The delegation links ordered root-first to leaf-last.
        key_resolver: Maps an issuer DID to its verifying key (JWK/Multikey/key).
        context: The proposed action's facts the caveats are evaluated against.
        root_issuer: If set, the first link's issuer must equal this DID.
        max_caveats: Optional ceiling on the accumulated caveat count.
    """
    from vouch.verifier import _coerce_ed25519_public_key

    if not chain:
        raise CaveatError("chain must have at least one link")

    for i, link in enumerate(chain):
        if CAPABILITY_TYPE not in _type_list(link):
            return REASON_INVALID_LINK_PROOF
        key = key_resolver(link.get("issuer"))
        resolved = _coerce_ed25519_public_key(key) if key is not None else None
        if resolved is None:
            return REASON_INVALID_LINK_PROOF
        try:
            if not data_integrity.verify_proof(link, resolved):
                return REASON_INVALID_LINK_PROOF
        except ValueError:
            return REASON_INVALID_LINK_PROOF
        if i > 0:
            parent_ref = (link.get("credentialSubject") or {}).get("parent") or {}
            if parent_ref.get("digest") != _digest(chain[i - 1]):
                return REASON_BROKEN_CHAIN

    if root_issuer is not None and chain[0].get("issuer") != root_issuer:
        return REASON_UNROOTED

    effective = chain_caveats(chain)
    if max_caveats is not None and len(effective) > max_caveats:
        return REASON_BUDGET_EXCEEDED

    for cav in effective:
        allow, reason = evaluate_caveat(cav, context)
        if not allow:
            return reason
    return None


__all__ = [
    "CaveatError",
    "CAPABILITY_TYPE",
    "caveat",
    "value_ceiling",
    "running_total_ceiling",
    "time_window",
    "allowlist",
    "flag_true",
    "incident_gate",
    "rate_limit",
    "evaluate_caveat",
    "build_capability",
    "chain_caveats",
    "verify_capability",
]
