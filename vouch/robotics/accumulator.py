"""
Dynamic revocation accumulator via a sparse Merkle tree (PAD-120).

The reference carried-witness used a static Merkle tree over the *valid* set, which
must be rebuilt whenever the set changes. A sparse Merkle tree (SMT) is a dynamic
accumulator over the *revoked* set: the authority revokes or un-revokes a single
credential incrementally, and a node carries a compact **non-revocation** (non-
membership) proof that a verifier checks against the signed root while holding no
status list. Proofs are compressed — only the non-default sibling hashes travel —
so a sparse revocation set yields tiny proofs.

No trusted setup, no big-integer accumulator: just SHA-256 over a 256-level tree
keyed by the credential id's digest. A credential is "revoked" iff its leaf is set;
a non-revocation proof shows the leaf is still empty.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Set

from ..merkle import _decode_multibase, _encode_multibase

DEPTH = 256
EMPTY_LEAF = b"\x00" * 32
REVOKED_LEAF = hashlib.sha256(b"vouch:smt:revoked-leaf:v1").digest()


def _h(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(a + b).digest()


# Precompute the default (all-empty) subtree hash at each level.
_DEFAULTS: List[bytes] = [b""] * (DEPTH + 1)
_DEFAULTS[DEPTH] = EMPTY_LEAF
for _i in range(DEPTH - 1, -1, -1):
    _DEFAULTS[_i] = _h(_DEFAULTS[_i + 1], _DEFAULTS[_i + 1])


def _key(credential_id: str) -> bytes:
    return hashlib.sha256(credential_id.encode("utf-8")).digest()


def _bit(key: bytes, level: int) -> int:
    return (key[level >> 3] >> (7 - (level & 7))) & 1


def _node(level: int, keys: List[bytes]) -> bytes:
    """Hash of the subtree at `level` containing exactly the revoked `keys`."""
    if not keys:
        return _DEFAULTS[level]
    if level == DEPTH:
        return REVOKED_LEAF
    left = [k for k in keys if _bit(k, level) == 0]
    right = [k for k in keys if _bit(k, level) == 1]
    return _h(_node(level + 1, left), _node(level + 1, right))


class SparseMerkleTree:
    """A dynamic revocation accumulator. Revoke/un-revoke are O(1); root/proof walk the tree."""

    def __init__(self) -> None:
        self._revoked: Set[bytes] = set()

    def revoke(self, credential_id: str) -> None:
        self._revoked.add(_key(credential_id))

    def unrevoke(self, credential_id: str) -> None:
        self._revoked.discard(_key(credential_id))

    def is_revoked(self, credential_id: str) -> bool:
        return _key(credential_id) in self._revoked

    def root(self) -> bytes:
        return _node(0, list(self._revoked))

    def root_multibase(self) -> str:
        return _encode_multibase(self.root())

    def non_revocation_proof(self, credential_id: str) -> Dict[str, object]:
        """
        Build a compressed non-membership proof for `credential_id`. Only the levels
        whose sibling is non-default are carried, indexed by a 256-bit bitmap.
        """
        key = _key(credential_id)
        keys = list(self._revoked)
        bitmap = bytearray(DEPTH // 8)
        siblings: List[str] = []
        for level in range(DEPTH):
            left = [k for k in keys if _bit(k, level) == 0]
            right = [k for k in keys if _bit(k, level) == 1]
            if _bit(key, level) == 0:
                sib = _node(level + 1, right)
                keys = left
            else:
                sib = _node(level + 1, left)
                keys = right
            if sib != _DEFAULTS[level + 1]:
                bitmap[level >> 3] |= 1 << (7 - (level & 7))
                siblings.append(_encode_multibase(sib))
        return {"bitmap": _encode_multibase(bytes(bitmap)), "siblings": siblings}


def verify_non_revocation_proof(
    *, credential_id: str, proof: Dict[str, object], root: bytes
) -> bool:
    """
    Verify that `credential_id` is NOT revoked under the tree with the given `root`,
    by reconstructing the root assuming the credential's leaf is empty. If the
    credential were revoked, its true leaf is non-empty and the reconstruction would
    not match `root`.
    """
    try:
        key = _key(credential_id)
        bitmap = _decode_multibase(str(proof["bitmap"]))
        if len(bitmap) != DEPTH // 8:
            return False
        sib_list = list(proof["siblings"])  # type: ignore[arg-type]
        # Siblings are emitted in ascending level order (0..255); map each to its
        # level, filling default siblings where the bitmap bit is unset.
        sib_by_level: List[bytes] = []
        idx = 0
        for level in range(DEPTH):
            if (bitmap[level >> 3] >> (7 - (level & 7))) & 1:
                sib_by_level.append(_decode_multibase(sib_list[idx]))
                idx += 1
            else:
                sib_by_level.append(_DEFAULTS[level + 1])
        if idx != len(sib_list):
            return False  # stray, unindexed siblings
        current = EMPTY_LEAF  # asserting: not revoked -> leaf empty
        for level in range(DEPTH - 1, -1, -1):
            sibling = sib_by_level[level]
            if _bit(key, level) == 0:
                current = _h(current, sibling)
            else:
                current = _h(sibling, current)
        return current == root
    except (KeyError, ValueError, TypeError, IndexError):
        return False


__all__ = [
    "DEPTH",
    "SparseMerkleTree",
    "verify_non_revocation_proof",
]
