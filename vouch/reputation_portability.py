"""
Privacy-preserving reputation portability (reputation Phase 5).

A `ReputationThresholdProof` lets an agent prove a predicate over its reputation
(composite >= 75, or reliability >= 0.9) without revealing the score or the
underlying receipts. The registry evaluates the predicate and signs the boolean
result, optionally bound to an `audience` so proofs are not linkable across
verifiers.

This is selective disclosure: the verifier trusts the issuer's signature on the
predicate result rather than recomputing it from hidden data. A full
zero-knowledge range proof, which would hide the score even from the issuer and
need no trusted issuer, is a later cryptographic upgrade. The credential shape
here is forward-compatible: the signed assertion can be swapped for a zk proof
object without changing how it is referenced.
"""

from __future__ import annotations

import operator
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

from . import data_integrity
from .reputation_aggregate import ReputationScore

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
REPUTATION_PROOF_TYPE = "ReputationThresholdProof"

_OPS = {">=": operator.ge, ">": operator.gt, "<=": operator.le, "<": operator.lt, "==": operator.eq}

ScoreLike = Union[ReputationScore, Dict[str, Any]]


class PortabilityError(Exception):
    """Raised on a malformed predicate or proof."""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _composite(score: ScoreLike) -> Optional[float]:
    if isinstance(score, ReputationScore):
        return score.composite
    return score.get("composite")


def _dimensions(score: ScoreLike) -> Dict[str, float]:
    if isinstance(score, ReputationScore):
        return dict(score.dimensions)
    return dict(score.get("dimensions") or {})


def _resolve(score: ScoreLike, path: str) -> Optional[float]:
    if path == "composite":
        return _composite(score)
    if path.startswith("dimensions."):
        return _dimensions(score).get(path.split(".", 1)[1])
    return None


def _eval(score: ScoreLike, predicate: Dict[str, Any]) -> bool:
    op = _OPS.get(predicate.get("op"))
    if op is None:
        raise PortabilityError(f"unsupported op: {predicate.get('op')!r}")
    val = _resolve(score, predicate.get("path", ""))
    if val is None:
        return False
    return bool(op(float(val), float(predicate["value"])))


def _attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise PortabilityError("signing requires a Signer with an Ed25519 key")
    credential["proof"] = data_integrity.build_proof(
        credential, raw, signer.verification_method_id()
    )
    return credential


def build_reputation_proof(
    signer: Any,
    agent: str,
    score: ScoreLike,
    *,
    predicates: List[Dict[str, Any]],
    audience: Optional[str] = None,
    evidence_root: Optional[str] = None,
    valid_from: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Issue a ReputationThresholdProof. Each predicate is `{path, op, value}` where
    `path` is "composite" or "dimensions.<name>". The proof carries only the
    predicate and whether it is satisfied, never the score itself.
    """
    if not predicates:
        raise PortabilityError("at least one predicate is required")
    assertions = [
        {
            "path": p["path"],
            "op": p["op"],
            "value": p["value"],
            "satisfied": _eval(score, p),
        }
        for p in predicates
    ]
    subject: Dict[str, Any] = {"id": agent, "assertions": assertions}
    if audience is not None:
        subject["audience"] = audience
    if evidence_root is not None:
        subject["evidenceRoot"] = evidence_root

    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", REPUTATION_PROOF_TYPE],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuer": signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return _attach_proof(credential, signer)


def verify_reputation_proof(
    proof: Dict[str, Any],
    public_key: Any,
    *,
    require: Optional[List[Dict[str, Any]]] = None,
    audience: Optional[str] = None,
):
    """
    Verify the issuer's signature and, optionally, that the required predicates are
    present and satisfied and the audience matches. Returns (ok, assertions).
    """
    from .verifier import _coerce_ed25519_public_key

    t = proof.get("type") or []
    types = [t] if isinstance(t, str) else list(t)
    if REPUTATION_PROOF_TYPE not in types:
        return False, None

    pub = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if pub is None:
        return False, None
    try:
        if not data_integrity.verify_proof(proof, pub):
            return False, None
    except ValueError:
        return False, None

    subject = proof.get("credentialSubject") or {}
    if audience is not None and subject.get("audience") != audience:
        return False, None

    assertions = subject.get("assertions") or []
    if require is not None:
        index = {(a["path"], a["op"], str(a["value"])): bool(a["satisfied"]) for a in assertions}
        for p in require:
            if not index.get((p["path"], p["op"], str(p["value"])), False):
                return False, assertions

    return True, assertions


__all__ = [
    "REPUTATION_PROOF_TYPE",
    "PortabilityError",
    "build_reputation_proof",
    "verify_reputation_proof",
]
