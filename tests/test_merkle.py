"""
Unit tests for Merkle tree primitives (PAD-017, PAD-042, Specification §11.3).
"""

import hashlib

import pytest

from vouch.merkle import (
  MULTIBASE_BASE64URL_PREFIX,
  InclusionProof,
  MerkleError,
  MerkleTree,
  ProofStep,
  compute_action_merkle_root,
  hash_leaf,
  hash_node,
  verify_inclusion,
)


class TestHashPrimitives:
  def test_hash_leaf_uses_rfc6962_prefix(self):
    data = b"my_leaf"
    expected = hashlib.sha256(b"\x00" + data).digest()
    assert hash_leaf(data) == expected
    assert len(hash_leaf(data)) == 32

  def test_hash_node_uses_rfc6962_prefix(self):
    a = hashlib.sha256(b"a").digest()
    b = hashlib.sha256(b"b").digest()
    expected = hashlib.sha256(b"\x01" + a + b).digest()
    assert hash_node(a, b) == expected

  def test_hash_leaf_rejects_non_bytes(self):
    with pytest.raises(MerkleError):
      hash_leaf("not bytes") # type: ignore[arg-type]

  def test_hash_node_requires_32_byte_inputs(self):
    with pytest.raises(MerkleError):
      hash_node(b"too short", hashlib.sha256(b"x").digest())


class TestTreeConstruction:
  def test_single_leaf_tree(self):
    tree = MerkleTree(leaves=[b"only"])
    assert tree.root() == hash_leaf(b"only")
    assert len(tree) == 1

  def test_two_leaf_tree(self):
    tree = MerkleTree(leaves=[b"a", b"b"])
    expected_root = hash_node(hash_leaf(b"a"), hash_leaf(b"b"))
    assert tree.root() == expected_root

  def test_three_leaf_tree_duplicates_last(self):
    tree = MerkleTree(leaves=[b"a", b"b", b"c"])
    # Level 0: H(a), H(b), H(c)
    # Level 1: H(H(a), H(b)), H(H(c), H(c))  # last duplicated
    # Level 2: H(H(L1[0]), H(L1[1]))
    l0 = [hash_leaf(b) for b in [b"a", b"b", b"c"]]
    l1 = [hash_node(l0[0], l0[1]), hash_node(l0[2], l0[2])]
    expected_root = hash_node(l1[0], l1[1])
    assert tree.root() == expected_root

  def test_root_changes_when_leaves_reorder(self):
    t1 = MerkleTree(leaves=[b"a", b"b", b"c"])
    t2 = MerkleTree(leaves=[b"b", b"a", b"c"])
    assert t1.root() != t2.root()

  def test_root_changes_with_leaf_value(self):
    t1 = MerkleTree(leaves=[b"a", b"b"])
    t2 = MerkleTree(leaves=[b"a", b"B"])
    assert t1.root() != t2.root()

  def test_empty_tree_rejected(self):
    with pytest.raises(MerkleError):
      MerkleTree(leaves=[])

  def test_non_bytes_leaf_rejected(self):
    with pytest.raises(MerkleError):
      MerkleTree(leaves=[b"ok", "not bytes"]) # type: ignore[list-item]

  def test_root_multibase_format(self):
    tree = MerkleTree(leaves=[b"a", b"b"])
    encoded = tree.root_multibase()
    assert encoded.startswith(MULTIBASE_BASE64URL_PREFIX)


class TestInclusionProofs:
  def test_single_leaf_proof_is_empty(self):
    tree = MerkleTree(leaves=[b"only"])
    proof = tree.proof(0)
    assert proof.leaf_index == 0
    assert proof.steps == []
    assert verify_inclusion(leaf=b"only", proof=proof, root=tree.root())

  def test_two_leaf_proof(self):
    tree = MerkleTree(leaves=[b"a", b"b"])
    proof_a = tree.proof(0)
    proof_b = tree.proof(1)
    assert verify_inclusion(leaf=b"a", proof=proof_a, root=tree.root())
    assert verify_inclusion(leaf=b"b", proof=proof_b, root=tree.root())

  def test_proof_size_log_n(self):
    tree = MerkleTree(leaves=[b"l%d" % i for i in range(16)])
    proof = tree.proof(7)
    # 16 leaves -> 4 levels of internal nodes -> proof depth 4
    assert len(proof.steps) == 4

  def test_proof_against_wrong_leaf_fails(self):
    tree = MerkleTree(leaves=[b"a", b"b"])
    proof_a = tree.proof(0)
    assert verify_inclusion(leaf=b"x", proof=proof_a, root=tree.root()) is False

  def test_proof_against_wrong_root_fails(self):
    tree = MerkleTree(leaves=[b"a", b"b"])
    proof_a = tree.proof(0)
    wrong_root = hashlib.sha256(b"wrong").digest()
    assert verify_inclusion(leaf=b"a", proof=proof_a, root=wrong_root) is False

  def test_tampered_proof_step_fails(self):
    tree = MerkleTree(leaves=[b"a", b"b", b"c", b"d"])
    proof = tree.proof(2)
    # Flip one sibling.
    tampered_steps = list(proof.steps)
    tampered_steps[0] = ProofStep(
      sibling=hashlib.sha256(b"forged").digest(),
      is_right=proof.steps[0].is_right,
    )
    tampered = InclusionProof(leaf_index=proof.leaf_index, steps=tampered_steps)
    assert verify_inclusion(leaf=b"c", proof=tampered, root=tree.root()) is False

  def test_out_of_range_index_rejected(self):
    tree = MerkleTree(leaves=[b"a", b"b"])
    with pytest.raises(MerkleError):
      tree.proof(2)
    with pytest.raises(MerkleError):
      tree.proof(-1)

  def test_proof_roundtrip_through_dict(self):
    tree = MerkleTree(leaves=[b"a", b"b", b"c"])
    proof = tree.proof(1)
    serialized = proof.to_dict()
    rehydrated = InclusionProof.from_dict(serialized)
    assert rehydrated.leaf_index == proof.leaf_index
    assert len(rehydrated.steps) == len(proof.steps)
    for original, rebuilt in zip(proof.steps, rehydrated.steps):
      assert original.sibling == rebuilt.sibling
      assert original.is_right == rebuilt.is_right
    assert verify_inclusion(leaf=b"b", proof=rehydrated, root=tree.root())


class TestActionMerkleRoot:
  def test_empty_actions_returns_hash_of_empty_leaf(self):
    root = compute_action_merkle_root([])
    assert root.startswith(MULTIBASE_BASE64URL_PREFIX)

  def test_action_root_changes_with_actions(self):
    r1 = compute_action_merkle_root([b"action1", b"action2"])
    r2 = compute_action_merkle_root([b"action1", b"action3"])
    assert r1 != r2

  def test_action_root_is_deterministic(self):
    actions = [b"a%d" % i for i in range(8)]
    assert compute_action_merkle_root(actions) == compute_action_merkle_root(actions)


class TestVerificationDefenses:
  def test_second_preimage_attack_blocked_by_domain_separation(self):
    """
    Without leaf/node domain separation, an attacker could substitute
    a leaf with an internal node's hash. RFC 6962 prefixes prevent this.
    """
    tree = MerkleTree(leaves=[b"a", b"b"])
    # Try to pass the internal node hash as a "leaf".
    internal = hash_node(hash_leaf(b"a"), hash_leaf(b"b"))
    # internal == root for this 2-leaf tree
    assert tree.root() == internal
    # But verify_inclusion treats internal as a leaf (hashes it again),
    # so the reconstructed root will not match.
    empty_proof = InclusionProof(leaf_index=0, steps=[])
    assert verify_inclusion(leaf=internal, proof=empty_proof, root=tree.root()) is False
