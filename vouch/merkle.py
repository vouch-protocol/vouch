"""
Merkle tree primitives for Vouch Protocol.

Implements a binary Merkle tree over SHA-256 hashes, used for:

- `actionMerkleRoot` in heartbeat requests (Specification §11.3) where
 an agent commits to the root of its actions in the interval.
- PAD-017 Reasoning Merkle Trees, where reasoning steps are leaves and
 selective disclosure is supported via inclusion proofs.
- PAD-042 transparency-log style anchoring of agent ledger entries.

Construction:

- Leaves: arbitrary byte strings (callers hash semantic data into leaves;
 this module hashes the leaf bytes once more as part of tree
 construction, following the convention from RFC 6962 §2.1 to prevent
 second-preimage attacks where a leaf is mistaken for an internal node).
- Internal nodes: SHA-256 of left || right.
- Domain separation: leaves are hashed with a 0x00 prefix; internal nodes
 with a 0x01 prefix, per RFC 6962 §2.1.
- Odd numbers of leaves at any level: the last node is duplicated
 (Bitcoin convention) to produce a balanced tree.

Inclusion proofs:

- An inclusion proof for a leaf is the sequence of sibling hashes from
 the leaf up to the root, plus a left/right bit per level.
- The verifier reconstructs the root from the leaf and proof; equality
 with the published root confirms inclusion.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import List, Sequence


# Domain separation tags per RFC 6962 §2.1.
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

# Multibase prefix for base64url-no-pad.
MULTIBASE_BASE64URL_PREFIX = "u"


class MerkleError(Exception):
  """Raised on malformed Merkle tree input or invalid proofs."""


def hash_leaf(data: bytes) -> bytes:
  """Return the 32-byte SHA-256 hash of a leaf value with RFC 6962 prefix."""
  if not isinstance(data, (bytes, bytearray)):
    raise MerkleError("leaf data must be bytes")
  return hashlib.sha256(_LEAF_PREFIX + bytes(data)).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
  """Return the 32-byte SHA-256 hash of an internal node with RFC 6962 prefix."""
  if not isinstance(left, (bytes, bytearray)) or not isinstance(right, (bytes, bytearray)):
    raise MerkleError("node hashes must be bytes")
  if len(left) != 32 or len(right) != 32:
    raise MerkleError("node hashes must be 32 bytes (SHA-256)")
  return hashlib.sha256(_NODE_PREFIX + bytes(left) + bytes(right)).digest()


def _encode_multibase(b: bytes) -> str:
  return MULTIBASE_BASE64URL_PREFIX + base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _decode_multibase(s: str) -> bytes:
  if not s.startswith(MULTIBASE_BASE64URL_PREFIX):
    raise MerkleError(
      f"expected multibase prefix {MULTIBASE_BASE64URL_PREFIX!r}, got {s[:1]!r}"
    )
  payload = s[1:]
  padding = (-len(payload)) % 4
  try:
    return base64.urlsafe_b64decode(payload + ("=" * padding))
  except Exception as exc:
    raise MerkleError(f"failed to decode: {exc}") from exc


@dataclass(frozen=True)
class ProofStep:
  """One step in an inclusion proof: a sibling hash and which side it sits on."""

  sibling: bytes
  is_right: bool # True if the sibling is on the right of the current node.

  def to_dict(self) -> dict:
    return {
      "sibling": _encode_multibase(self.sibling),
      "is_right": self.is_right,
    }

  @classmethod
  def from_dict(cls, d: dict) -> "ProofStep":
    return cls(
      sibling=_decode_multibase(d["sibling"]),
      is_right=bool(d["is_right"]),
    )


@dataclass
class InclusionProof:
  """A Merkle inclusion proof for a single leaf."""

  leaf_index: int
  steps: List[ProofStep] = field(default_factory=list)

  def to_dict(self) -> dict:
    return {
      "leaf_index": self.leaf_index,
      "steps": [step.to_dict() for step in self.steps],
    }

  @classmethod
  def from_dict(cls, d: dict) -> "InclusionProof":
    return cls(
      leaf_index=int(d["leaf_index"]),
      steps=[ProofStep.from_dict(s) for s in d.get("steps", [])],
    )


@dataclass
class MerkleTree:
  """
  In-memory binary Merkle tree over an ordered list of leaves.

  Construction is O(n) time and O(n) space in the number of leaves.
  Inclusion proofs are O(log n) size.

  The leaf at index `i` keeps its position in the tree; reordering
  the input leaves changes the root.
  """

  leaves: List[bytes]
  _levels: List[List[bytes]] = field(default_factory=list, init=False, repr=False)

  def __post_init__(self) -> None:
    if not self.leaves:
      raise MerkleError("Merkle tree requires at least one leaf")
    for i, leaf in enumerate(self.leaves):
      if not isinstance(leaf, (bytes, bytearray)):
        raise MerkleError(f"leaf {i} is not bytes")
    self.leaves = [bytes(leaf) for leaf in self.leaves]
    self._build()

  def _build(self) -> None:
    level = [hash_leaf(leaf) for leaf in self.leaves]
    self._levels = [level]
    while len(level) > 1:
      next_level: List[bytes] = []
      for i in range(0, len(level), 2):
        left = level[i]
        right = level[i + 1] if i + 1 < len(level) else level[i]
        next_level.append(hash_node(left, right))
      self._levels.append(next_level)
      level = next_level

  def root(self) -> bytes:
    """Return the 32-byte SHA-256 Merkle root."""
    return self._levels[-1][0]

  def root_multibase(self) -> str:
    """Return the multibase-encoded Merkle root."""
    return _encode_multibase(self.root())

  def __len__(self) -> int:
    return len(self.leaves)

  def proof(self, leaf_index: int) -> InclusionProof:
    """
    Return an inclusion proof for the leaf at `leaf_index`.

    Raises MerkleError on out-of-range index.
    """
    if leaf_index < 0 or leaf_index >= len(self.leaves):
      raise MerkleError(
        f"leaf_index {leaf_index} out of range [0, {len(self.leaves)})"
      )

    steps: List[ProofStep] = []
    index = leaf_index
    for level in self._levels[:-1]:
      if index % 2 == 0:
        sibling_idx = index + 1 if index + 1 < len(level) else index
        is_right = True
      else:
        sibling_idx = index - 1
        is_right = False
      steps.append(
        ProofStep(sibling=level[sibling_idx], is_right=is_right)
      )
      index //= 2

    return InclusionProof(leaf_index=leaf_index, steps=steps)


def verify_inclusion(
  *,
  leaf: bytes,
  proof: InclusionProof,
  root: bytes,
) -> bool:
  """
  Verify that `leaf` is included in the tree with root `root` at
  position `proof.leaf_index` using the supplied proof steps.

  Returns True if the proof reconstructs to the root, False otherwise.
  """
  if not isinstance(leaf, (bytes, bytearray)):
    raise MerkleError("leaf must be bytes")
  if not isinstance(root, (bytes, bytearray)) or len(root) != 32:
    raise MerkleError("root must be 32 bytes (SHA-256)")

  current = hash_leaf(bytes(leaf))
  for step in proof.steps:
    if step.is_right:
      current = hash_node(current, step.sibling)
    else:
      current = hash_node(step.sibling, current)
  return _constant_time_eq(current, bytes(root))


def _constant_time_eq(a: bytes, b: bytes) -> bool:
  if len(a) != len(b):
    return False
  result = 0
  for x, y in zip(a, b):
    result |= x ^ y
  return result == 0


def compute_action_merkle_root(actions: Sequence[bytes]) -> str:
  """
  Convenience wrapper for the §11.3 actionMerkleRoot field.

  Builds a tree over the supplied action byte strings (one per agent
  action in the interval) and returns the multibase-encoded root.
  """
  if not actions:
    # An empty interval is represented by the hash of an empty leaf
    # rather than rejecting; verifiers can distinguish "no actions"
    # from "missing field" cleanly.
    return _encode_multibase(hash_leaf(b""))
  tree = MerkleTree(leaves=list(actions))
  return tree.root_multibase()


__all__ = [
  "MULTIBASE_BASE64URL_PREFIX",
  "MerkleError",
  "MerkleTree",
  "InclusionProof",
  "ProofStep",
  "hash_leaf",
  "hash_node",
  "verify_inclusion",
  "compute_action_merkle_root",
]
