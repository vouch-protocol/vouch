"""Tests for Action Transparency (append-only RFC 6962 Merkle log)."""

import pytest

from vouch import Signer, generate_identity
from vouch.transparency import (
    REASON_CONSISTENCY_FAILED,
    REASON_INCLUSION_FAILED,
    REASON_INVALID_STH,
    REASON_TREE_SHRANK,
    SIGNED_TREE_HEAD_TYPE,
    TransparencyError,
    TransparencyLog,
    check_consistency,
    check_inclusion,
    consistency_proof,
    entry_digest,
    inclusion_proof,
    merkle_tree_hash,
    sign_tree_head,
    verify_consistency,
    verify_inclusion,
    verify_tree_head,
)

MAXN = 33


def _entries(n):
    return [entry_digest({"action": "a", "i": i}) for i in range(n)]


def _identity(domain="log.example.com"):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestTreeHash:
    def test_single_leaf_is_leaf_hash(self):
        from vouch.merkle import hash_leaf

        e = _entries(1)
        assert merkle_tree_hash(e) == hash_leaf(e[0])

    def test_order_sensitive(self):
        e = _entries(4)
        assert merkle_tree_hash(e) != merkle_tree_hash(list(reversed(e)))

    def test_empty_is_hash_of_empty(self):
        import hashlib

        assert merkle_tree_hash([]) == hashlib.sha256(b"").digest()


class TestInclusionExhaustive:
    def test_every_index_every_size(self):
        for n in range(1, MAXN):
            e = _entries(n)
            root = merkle_tree_hash(e)
            for i in range(n):
                proof = inclusion_proof(i, e)
                assert verify_inclusion(e[i], i, n, proof, root), f"n={n} i={i}"

    def test_wrong_leaf_fails(self):
        for n in range(2, 12):
            e = _entries(n)
            root = merkle_tree_hash(e)
            proof = inclusion_proof(0, e)
            assert not verify_inclusion(e[1], 0, n, proof, root)

    def test_wrong_index_fails(self):
        e = _entries(8)
        root = merkle_tree_hash(e)
        proof = inclusion_proof(3, e)
        assert not verify_inclusion(e[3], 4, 8, proof, root)

    def test_tampered_proof_fails(self):
        e = _entries(8)
        root = merkle_tree_hash(e)
        proof = inclusion_proof(5, e)
        proof[0] = bytes(32)
        assert not verify_inclusion(e[5], 5, 8, proof, root)

    def test_out_of_range(self):
        with pytest.raises(TransparencyError):
            inclusion_proof(5, _entries(3))


class TestConsistencyExhaustive:
    def test_every_prefix_every_size(self):
        for n in range(1, MAXN):
            e = _entries(n)
            new_root = merkle_tree_hash(e)
            for m in range(1, n + 1):
                proof = consistency_proof(m, e)
                old_root = merkle_tree_hash(e[:m])
                assert verify_consistency(m, n, proof, old_root, new_root), f"m={m} n={n}"

    def test_rewritten_history_fails(self):
        # A log that changed an old entry cannot prove consistency with the
        # original old root.
        for n in range(2, 14):
            for m in range(1, n):
                orig = _entries(n)
                orig_old_root = merkle_tree_hash(orig[:m])
                forked = list(orig)
                forked[0] = entry_digest({"tampered": True})
                proof = consistency_proof(m, forked)
                forked_new_root = merkle_tree_hash(forked)
                assert not verify_consistency(m, n, proof, orig_old_root, forked_new_root)

    def test_equal_sizes(self):
        e = _entries(5)
        r = merkle_tree_hash(e)
        assert verify_consistency(5, 5, [], r, r)
        assert not verify_consistency(5, 5, [], r, bytes(32))

    def test_tree_shrank_fails(self):
        e = _entries(6)
        assert not verify_consistency(6, 4, [], merkle_tree_hash(e), merkle_tree_hash(e[:4]))

    def test_tampered_proof_fails(self):
        e = _entries(10)
        proof = consistency_proof(3, e)
        proof[0] = bytes(32)
        assert not verify_consistency(3, 10, proof, merkle_tree_hash(e[:3]), merkle_tree_hash(e))


class TestLog:
    def test_append_and_root(self):
        log = TransparencyLog()
        assert log.size == 0
        log.append({"action": "x"})
        log.append({"action": "y"})
        assert log.size == 2
        assert log.root() == merkle_tree_hash(
            [entry_digest({"action": "x"}), entry_digest({"action": "y"})]
        )

    def test_log_inclusion_roundtrip(self):
        log = TransparencyLog()
        for i in range(9):
            log.append({"i": i})
        from vouch.transparency import _unmb

        proof = [_unmb(p) for p in log.inclusion_proof(4)]
        assert verify_inclusion(entry_digest({"i": 4}), 4, 9, proof, log.root())


class TestSignedTreeHead:
    def test_sign_and_verify(self):
        kp, log_signer = _identity()
        log = TransparencyLog()
        log.append({"action": "wire"})
        sth = sign_tree_head(log_signer, log)
        assert SIGNED_TREE_HEAD_TYPE in sth["type"]
        ok, subject = verify_tree_head(sth, kp.public_key_jwk)
        assert ok and subject["treeSize"] == 1

    def test_wrong_key_fails(self):
        _, log_signer = _identity()
        other_kp, _ = _identity("other.example.com")
        log = TransparencyLog()
        log.append({"a": 1})
        sth = sign_tree_head(log_signer, log)
        ok, _ = verify_tree_head(sth, other_kp.public_key_jwk)
        assert ok is False


class TestVerifierChecks:
    def _log_with_sth(self, n):
        kp, log_signer = _identity()
        log = TransparencyLog()
        actions = [{"action": "act", "i": i} for i in range(n)]
        for a in actions:
            log.append(a)
        sth = sign_tree_head(log_signer, log)
        return kp, log_signer, log, sth, actions

    def test_check_inclusion_ok(self):
        kp, _, log, sth, actions = self._log_with_sth(7)
        proof = log.inclusion_proof(3)
        assert check_inclusion(actions[3], 3, sth, proof, log_public_key=kp.public_key_jwk) is None

    def test_action_not_in_log_rejected(self):
        kp, _, log, sth, actions = self._log_with_sth(7)
        proof = log.inclusion_proof(3)
        assert check_inclusion({"action": "never_logged"}, 3, sth, proof) == REASON_INCLUSION_FAILED

    def test_check_inclusion_bad_sth(self):
        kp, _, log, sth, actions = self._log_with_sth(7)
        other_kp, _ = _identity("other.example.com")
        proof = log.inclusion_proof(3)
        assert (
            check_inclusion(actions[3], 3, sth, proof, log_public_key=other_kp.public_key_jwk)
            == REASON_INVALID_STH
        )

    def test_check_consistency_ok(self):
        kp, log_signer, log, old_sth, actions = self._log_with_sth(5)
        for i in range(5, 9):
            log.append({"action": "act", "i": i})
        new_sth = sign_tree_head(log_signer, log)
        proof = log.consistency_proof(5)
        assert check_consistency(old_sth, new_sth, proof, log_public_key=kp.public_key_jwk) is None

    def test_check_consistency_rewrite_rejected(self):
        # The log rewrites an old entry, then issues a new STH: consistency breaks.
        kp, log_signer, log, old_sth, actions = self._log_with_sth(5)
        forked = TransparencyLog()
        forked.append({"tampered": True})  # entry 0 changed
        for i in range(1, 9):
            forked.append({"action": "act", "i": i})
        new_sth = sign_tree_head(log_signer, forked)
        proof = forked.consistency_proof(5)
        assert check_consistency(old_sth, new_sth, proof) == REASON_CONSISTENCY_FAILED

    def test_check_consistency_shrank(self):
        kp, log_signer, log, big_sth, actions = self._log_with_sth(6)
        small = TransparencyLog()
        for i in range(3):
            small.append({"action": "act", "i": i})
        small_sth = sign_tree_head(log_signer, small)
        assert check_consistency(big_sth, small_sth, []) == REASON_TREE_SHRANK
