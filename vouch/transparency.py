"""
Action Transparency: an append-only, publicly-auditable log of agent actions.

Point verification catches what one verifier sees. Certificate Transparency
taught the harder lesson: publishing every issuance in an append-only log made
misissuance impossible to hide, and that alone changed issuer behaviour. This
module brings the same discipline to agent actions.

Consequential action credentials are submitted to an append-only Merkle log. The
log periodically signs a **Signed Tree Head** (its size and Merkle root) as a
commitment to its state. A verifier can then demand:

  - an **inclusion proof** that a given action is actually in the log a Signed
    Tree Head commits to, so an action cannot be quietly kept out of the record;
  - a **consistency proof** that an older Signed Tree Head is a strict prefix of a
    newer one, so the log cannot rewrite or delete history, and a monitor comparing
    tree heads across observers detects a split view.

The Merkle tree follows RFC 6962 (leaf and node hashes are domain-separated via
``vouch.merkle``'s ``hash_leaf`` and ``hash_node``), so inclusion and consistency
proofs are compact and the roots are reproducible across implementations. This
module ships the log mechanics and the proof verification; the anomaly-detection
policy a monitor layers on top is deployment-specific. It is the on-protocol
transparency layer beneath the accountable-autonomy runtime.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import data_integrity
from .jcs import canonicalize
from .merkle import hash_leaf, hash_node

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"

SIGNED_TREE_HEAD_TYPE = "SignedTreeHead"

# Structured verification reasons (stable strings, mirrored by the SDKs).
REASON_INVALID_STH = "invalid_signed_tree_head"
REASON_STH_MISMATCH = "sth_mismatch"
REASON_INCLUSION_FAILED = "inclusion_failed"
REASON_CONSISTENCY_FAILED = "consistency_failed"
REASON_TREE_SHRANK = "tree_shrank"


class TransparencyError(Exception):
    """Raised on malformed transparency-log input."""


# ---------------------------------------------------------------------------
# Encoding + signing helpers
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mb(b: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unmb(s: str) -> bytes:
    if not isinstance(s, str) or not s.startswith("u"):
        raise TransparencyError("expected multibase 'u' prefix")
    payload = s[1:]
    return base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise TransparencyError("signing requires a Signer with an Ed25519 key")
    return raw


def _attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    credential["proof"] = data_integrity.build_proof(
        credential, _raw_priv(signer), signer.verification_method_id()
    )
    return credential


def _type_list(credential: Dict[str, Any]) -> list:
    t = credential.get("type") or []
    return [t] if isinstance(t, str) else list(t)


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, dict):
        return canonicalize(value)
    raise TransparencyError("log entry must be a dict, str, or bytes")


def entry_digest(value: Any) -> bytes:
    """The 32-byte log entry for an action (SHA-256 over its canonical bytes)."""
    return hashlib.sha256(_to_bytes(value)).digest()


# ---------------------------------------------------------------------------
# RFC 6962 Merkle tree hash, inclusion, and consistency
# ---------------------------------------------------------------------------


def _k(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def merkle_tree_hash(entries: Sequence[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over an ordered list of leaf values."""
    n = len(entries)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hash_leaf(bytes(entries[0]))
    k = _k(n)
    return hash_node(merkle_tree_hash(entries[:k]), merkle_tree_hash(entries[k:]))


def inclusion_proof(index: int, entries: Sequence[bytes]) -> List[bytes]:
    """RFC 6962 audit path proving ``entries[index]`` is in the tree."""
    n = len(entries)
    if not 0 <= index < n:
        raise TransparencyError("index out of range")
    if n == 1:
        return []
    k = _k(n)
    if index < k:
        return inclusion_proof(index, entries[:k]) + [merkle_tree_hash(entries[k:])]
    return inclusion_proof(index - k, entries[k:]) + [merkle_tree_hash(entries[:k])]


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, proof: Sequence[bytes], root: bytes
) -> bool:
    """Verify an RFC 6962 inclusion proof: that ``leaf`` at ``index`` is in a tree
    of ``tree_size`` with the given ``root``."""
    if not 0 <= index < tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = hash_leaf(bytes(leaf))
    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = hash_node(bytes(p), r)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hash_node(r, bytes(p))
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == bytes(root)


def _subproof(m: int, entries: Sequence[bytes], b: bool) -> List[bytes]:
    n = len(entries)
    if m == n:
        return [] if b else [merkle_tree_hash(entries)]
    k = _k(n)
    if m <= k:
        return _subproof(m, entries[:k], b) + [merkle_tree_hash(entries[k:])]
    return _subproof(m - k, entries[k:], False) + [merkle_tree_hash(entries[:k])]


def consistency_proof(old_size: int, entries: Sequence[bytes]) -> List[bytes]:
    """RFC 6962 consistency proof that the tree of ``old_size`` is a prefix of the
    tree over all ``entries``."""
    n = len(entries)
    if not 0 < old_size <= n:
        raise TransparencyError("old_size must be in (0, len(entries)]")
    if old_size == n:
        return []
    return _subproof(old_size, entries, True)


def verify_consistency(
    old_size: int,
    new_size: int,
    proof: Sequence[bytes],
    old_root: bytes,
    new_root: bytes,
) -> bool:
    """Verify an RFC 6962 consistency proof: that the tree of ``old_size`` with
    ``old_root`` is a prefix of the tree of ``new_size`` with ``new_root``."""
    old_root, new_root = bytes(old_root), bytes(new_root)
    if old_size > new_size:
        return False
    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root
    if old_size == 0:
        return len(proof) == 0

    node, last = old_size - 1, new_size - 1
    while node & 1:
        node >>= 1
        last >>= 1

    proof = [bytes(p) for p in proof]
    if old_size & (old_size - 1) == 0:  # old_size is a power of two
        fr = sr = old_root
        idx = 0
    else:
        if not proof:
            return False
        fr = sr = proof[0]
        idx = 1

    while node:
        if idx >= len(proof):
            return False
        if node & 1:
            p = proof[idx]
            idx += 1
            fr = hash_node(p, fr)
            sr = hash_node(p, sr)
        elif node < last:
            p = proof[idx]
            idx += 1
            sr = hash_node(sr, p)
        node >>= 1
        last >>= 1

    while last:
        if idx >= len(proof):
            return False
        sr = hash_node(sr, proof[idx])
        idx += 1
        last >>= 1

    return idx == len(proof) and fr == old_root and sr == new_root


# ---------------------------------------------------------------------------
# The append-only log
# ---------------------------------------------------------------------------


class TransparencyLog:
    """
    An in-memory append-only Merkle log of entry digests. A hosted log persists
    the same structure; the wire artifacts (Signed Tree Heads and proofs) are
    identical either way.
    """

    def __init__(self, entries: Optional[Sequence[bytes]] = None):
        self._entries: List[bytes] = [bytes(e) for e in (entries or [])]

    @property
    def size(self) -> int:
        return len(self._entries)

    def append(self, value: Any) -> int:
        """Append an action (its entry digest) and return its index."""
        self._entries.append(entry_digest(value))
        return len(self._entries) - 1

    def append_digest(self, digest: bytes) -> int:
        if len(digest) != 32:
            raise TransparencyError("entry digest must be 32 bytes")
        self._entries.append(bytes(digest))
        return len(self._entries) - 1

    def root(self) -> bytes:
        return merkle_tree_hash(self._entries)

    def root_multibase(self) -> str:
        return _mb(self.root())

    def inclusion_proof(self, index: int) -> List[str]:
        return [_mb(h) for h in inclusion_proof(index, self._entries)]

    def consistency_proof(self, old_size: int) -> List[str]:
        return [_mb(h) for h in consistency_proof(old_size, self._entries)]


# ---------------------------------------------------------------------------
# Signed Tree Heads and verifier-side checks
# ---------------------------------------------------------------------------


def sign_tree_head(
    log_signer: Any,
    log: TransparencyLog,
    *,
    log_id: Optional[str] = None,
    timestamp: Optional[datetime] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Issue a ``SignedTreeHead`` committing to the log's current size and root."""
    issued = (timestamp or datetime.now(timezone.utc)).astimezone(timezone.utc)
    sth: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", SIGNED_TREE_HEAD_TYPE],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": log_signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": {
            "logId": log_id or log_signer.get_did(),
            "treeSize": log.size,
            "rootHash": log.root_multibase(),
        },
    }
    return _attach_proof(sth, log_signer)


def verify_tree_head(
    sth: Dict[str, Any], log_public_key: Any
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Verify a Signed Tree Head's proof and structure. Returns (ok, subject)."""
    from vouch.verifier import _coerce_ed25519_public_key

    if SIGNED_TREE_HEAD_TYPE not in _type_list(sth):
        return False, None
    resolved = _coerce_ed25519_public_key(log_public_key) if log_public_key is not None else None
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(sth, resolved):
            return False, None
    except ValueError:
        return False, None
    subject = sth.get("credentialSubject") or {}
    if not isinstance(subject.get("treeSize"), int) or not subject.get("rootHash"):
        return False, None
    return True, subject


def check_inclusion(
    entry: Any,
    index: int,
    sth: Dict[str, Any],
    proof: Sequence[str],
    *,
    log_public_key: Any = None,
) -> Optional[str]:
    """
    Confirm an action is in the log a Signed Tree Head commits to. Returns None on
    success or a structured reason. Pass ``log_public_key`` to also verify the STH.
    """
    if log_public_key is not None:
        ok, _ = verify_tree_head(sth, log_public_key)
        if not ok:
            return REASON_INVALID_STH
    subject = sth.get("credentialSubject") or {}
    size = subject.get("treeSize")
    root_mb = subject.get("rootHash")
    if not isinstance(size, int) or not root_mb:
        return REASON_INVALID_STH
    leaf = (
        entry_digest(entry)
        if not (isinstance(entry, (bytes, bytearray)) and len(entry) == 32)
        else bytes(entry)
    )
    try:
        proof_bytes = [_unmb(p) for p in proof]
        if not verify_inclusion(leaf, index, size, proof_bytes, _unmb(root_mb)):
            return REASON_INCLUSION_FAILED
    except TransparencyError:
        return REASON_INCLUSION_FAILED
    return None


def check_consistency(
    old_sth: Dict[str, Any],
    new_sth: Dict[str, Any],
    proof: Sequence[str],
    *,
    log_public_key: Any = None,
) -> Optional[str]:
    """
    Confirm an older Signed Tree Head is a strict prefix of a newer one, so the log
    did not rewrite or delete history. Returns None on success or a structured
    reason. Pass ``log_public_key`` to also verify both tree heads.
    """
    if log_public_key is not None:
        for h in (old_sth, new_sth):
            ok, _ = verify_tree_head(h, log_public_key)
            if not ok:
                return REASON_INVALID_STH
    o = old_sth.get("credentialSubject") or {}
    n = new_sth.get("credentialSubject") or {}
    old_size, new_size = o.get("treeSize"), n.get("treeSize")
    if not isinstance(old_size, int) or not isinstance(new_size, int):
        return REASON_INVALID_STH
    if new_size < old_size:
        return REASON_TREE_SHRANK
    try:
        if not verify_consistency(
            old_size,
            new_size,
            [_unmb(p) for p in proof],
            _unmb(o["rootHash"]),
            _unmb(n["rootHash"]),
        ):
            return REASON_CONSISTENCY_FAILED
    except (TransparencyError, KeyError):
        return REASON_CONSISTENCY_FAILED
    return None


__all__ = [
    "TransparencyError",
    "SIGNED_TREE_HEAD_TYPE",
    "TransparencyLog",
    "entry_digest",
    "merkle_tree_hash",
    "inclusion_proof",
    "verify_inclusion",
    "consistency_proof",
    "verify_consistency",
    "sign_tree_head",
    "verify_tree_head",
    "check_inclusion",
    "check_consistency",
]
