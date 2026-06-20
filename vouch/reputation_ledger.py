"""
Reputation ledger and signed snapshot (reputation Phase 3a, free SDK tier).

A `ReputationLedger` is an in-process, Merkle-backed, append-only store of
verified receipts about agents. On append it verifies each receipt's signature
against a caller-supplied key resolver, so only authentic receipts enter. It
computes a score with the Phase 2 aggregation function and exposes a Merkle root
over an agent's receipts, so a consumer can be handed the receipts plus inclusion
proofs and recompute the score rather than trust the ledger.

`build_reputation_credential` issues a signed `ReputationCredential`: a snapshot
of an agent's score plus the evidence Merkle root, signed by whoever runs the
ledger. The hosted registry and HTTP API are a separate (commercial) layer on
top; this module is self-hostable and open.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from . import data_integrity
from .jcs import canonicalize
from .merkle import MerkleTree
from .receipts import receipt_subject
from .reputation_aggregate import ReputationScore, aggregate_receipts

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
REPUTATION_CREDENTIAL_TYPE = "ReputationCredential"

KeyResolver = Callable[[str], Any]  # issuer DID -> public key (or None if unknown)


class LedgerError(Exception):
    """Raised on a receipt the ledger will not admit."""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _verify(credential: Dict[str, Any], public_key: Any) -> bool:
    from .verifier import _coerce_ed25519_public_key

    pub = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if pub is None:
        return False
    try:
        return data_integrity.verify_proof(credential, pub)
    except ValueError:
        return False


def _attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise LedgerError("signing requires a Signer with an Ed25519 key")
    credential["proof"] = data_integrity.build_proof(
        credential, raw, signer.verification_method_id()
    )
    return credential


class ReputationLedger:
    """Append-only, Merkle-backed store of verified receipts, with scoring."""

    def __init__(self, *, resolver: KeyResolver, **agg_kwargs: Any) -> None:
        self._resolver = resolver
        self._agg = agg_kwargs
        self._receipts: Dict[str, List[Dict[str, Any]]] = {}

    def append(self, receipt: Dict[str, Any]) -> bool:
        """Verify and admit a receipt. Raises LedgerError if it cannot be admitted."""
        agent = receipt_subject(receipt)
        if not agent:
            raise LedgerError("receipt has no subject DID")
        issuer = receipt.get("issuer")
        if not issuer:
            raise LedgerError("receipt has no issuer")
        key = self._resolver(issuer)
        if key is None:
            raise LedgerError(f"no key resolved for issuer {issuer}")
        if not _verify(receipt, key):
            raise LedgerError("receipt signature did not verify")
        self._receipts.setdefault(agent, []).append(receipt)
        return True

    def receipts(self, agent: str) -> List[Dict[str, Any]]:
        return list(self._receipts.get(agent, []))

    def count(self, agent: str) -> int:
        return len(self._receipts.get(agent, []))

    def merkle(self, agent: str) -> Optional[MerkleTree]:
        leaves = [canonicalize(r) for r in self._receipts.get(agent, [])]
        return MerkleTree(leaves) if leaves else None

    def root(self, agent: str) -> Optional[str]:
        tree = self.merkle(agent)
        return tree.root_multibase() if tree is not None else None

    def score(self, agent: str, *, at: Optional[datetime] = None, **kw: Any) -> ReputationScore:
        merged = {**self._agg, **kw}
        return aggregate_receipts(self._receipts.get(agent, []), agent=agent, at=at, **merged)

    def snapshot(
        self,
        signer: Any,
        agent: str,
        *,
        at: Optional[datetime] = None,
        valid_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Issue a signed ReputationCredential for the agent's current standing."""
        score = self.score(agent, at=at)
        return build_reputation_credential(
            signer,
            agent,
            score,
            evidence_root=self.root(agent),
            receipt_count=self.count(agent),
            valid_from=at,
            valid_seconds=valid_seconds,
        )


def build_reputation_credential(
    signer: Any,
    agent: str,
    score: ReputationScore,
    *,
    evidence_root: Optional[str] = None,
    receipt_count: Optional[int] = None,
    valid_from: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Issue a signed snapshot of an agent's reputation score."""
    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": agent,
        "score": {
            "version": score.version,
            "composite": score.composite,
            "dimensions": score.dimensions,
        },
    }
    if evidence_root is not None:
        subject["evidenceRoot"] = evidence_root
    if receipt_count is not None:
        subject["receiptCount"] = receipt_count

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", REPUTATION_CREDENTIAL_TYPE],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuer": signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return _attach_proof(credential, signer)


def verify_reputation_credential(credential: Dict[str, Any], public_key: Any):
    """Verify a ReputationCredential snapshot. Returns (ok, subject)."""
    t = credential.get("type") or []
    types = [t] if isinstance(t, str) else list(t)
    if REPUTATION_CREDENTIAL_TYPE not in types:
        return False, None
    if not _verify(credential, public_key):
        return False, None
    return True, credential.get("credentialSubject") or {}


__all__ = [
    "REPUTATION_CREDENTIAL_TYPE",
    "KeyResolver",
    "LedgerError",
    "ReputationLedger",
    "build_reputation_credential",
    "verify_reputation_credential",
]
