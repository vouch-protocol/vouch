"""
Unit tests for Canary Commitments (W3C CG Report §11.3, §11.7).
"""

import base64
import hashlib

import pytest

from vouch.canary import (
    MULTIBASE_BASE64URL_PREFIX,
    CanaryChain,
    CanaryChainError,
    CanaryVerifier,
    compute_commitment,
    verify_reveal,
)


class TestCommitmentPrimitives:
    def test_commitment_is_multibase_encoded_sha256(self):
        secret = b"test_secret"
        commitment = compute_commitment(secret)
        assert commitment.startswith(MULTIBASE_BASE64URL_PREFIX)
        # Manually verify it's a base64url-encoded SHA-256 digest.
        encoded = commitment[1:]
        padding = (-len(encoded)) % 4
        decoded = base64.urlsafe_b64decode(encoded + ("=" * padding))
        assert decoded == hashlib.sha256(secret).digest()
        assert len(decoded) == 32

    def test_commitment_is_deterministic(self):
        secret = b"x" * 32
        assert compute_commitment(secret) == compute_commitment(secret)

    def test_different_secrets_produce_different_commitments(self):
        c1 = compute_commitment(b"alpha")
        c2 = compute_commitment(b"beta")
        assert c1 != c2

    def test_empty_secret_rejected(self):
        with pytest.raises(CanaryChainError):
            compute_commitment(b"")

    def test_non_bytes_rejected(self):
        with pytest.raises(CanaryChainError):
            compute_commitment("not bytes")  # type: ignore[arg-type]


class TestVerifyReveal:
    def test_correct_reveal_verifies(self):
        secret = b"my_canary_secret"
        commitment = compute_commitment(secret)
        encoded_secret = MULTIBASE_BASE64URL_PREFIX + base64.urlsafe_b64encode(secret).rstrip(b"=").decode()
        assert verify_reveal(encoded_secret, commitment) is True

    def test_wrong_reveal_fails(self):
        commitment = compute_commitment(b"original")
        wrong_secret = b"different"
        encoded = MULTIBASE_BASE64URL_PREFIX + base64.urlsafe_b64encode(wrong_secret).rstrip(b"=").decode()
        assert verify_reveal(encoded, commitment) is False

    def test_empty_reveal_raises(self):
        with pytest.raises(CanaryChainError):
            verify_reveal("", "ucommitment_data")

    def test_malformed_multibase_raises(self):
        with pytest.raises(CanaryChainError):
            verify_reveal("not_multibase", compute_commitment(b"x"))


class TestCanaryChain:
    def test_first_heartbeat_has_commitment_but_no_reveal(self):
        chain = CanaryChain()
        msg = chain.next_heartbeat()
        assert msg.commitment.startswith(MULTIBASE_BASE64URL_PREFIX)
        assert msg.reveal is None

    def test_second_heartbeat_has_both(self):
        chain = CanaryChain()
        chain.next_heartbeat()
        msg = chain.next_heartbeat()
        assert msg.commitment.startswith(MULTIBASE_BASE64URL_PREFIX)
        assert msg.reveal is not None
        assert msg.reveal.startswith(MULTIBASE_BASE64URL_PREFIX)

    def test_reveal_matches_prior_commitment(self):
        chain = CanaryChain()
        first = chain.next_heartbeat()
        second = chain.next_heartbeat()
        # The reveal in second should hash to first's commitment.
        assert verify_reveal(second.reveal, first.commitment) is True

    def test_each_heartbeat_uses_fresh_secret(self):
        chain = CanaryChain()
        commitments = [chain.next_heartbeat().commitment for _ in range(5)]
        assert len(set(commitments)) == 5  # all unique

    def test_to_dict_omits_reveal_on_first_heartbeat(self):
        chain = CanaryChain()
        msg = chain.next_heartbeat()
        d = msg.to_dict()
        assert "canaryCommitment" in d
        assert "canaryReveal" not in d

    def test_to_dict_includes_reveal_on_subsequent_heartbeats(self):
        chain = CanaryChain()
        chain.next_heartbeat()
        msg = chain.next_heartbeat()
        d = msg.to_dict()
        assert "canaryCommitment" in d
        assert "canaryReveal" in d


class TestCanaryVerifier:
    def test_first_observation_accepts_commitment_only(self):
        verifier = CanaryVerifier()
        chain = CanaryChain()
        first = chain.next_heartbeat()
        assert verifier.observe(first.commitment, first.reveal) is True

    def test_subsequent_observation_with_correct_reveal(self):
        verifier = CanaryVerifier()
        chain = CanaryChain()
        first = chain.next_heartbeat()
        verifier.observe(first.commitment, first.reveal)
        second = chain.next_heartbeat()
        assert verifier.observe(second.commitment, second.reveal) is True

    def test_subsequent_observation_without_reveal_fails(self):
        verifier = CanaryVerifier()
        chain = CanaryChain()
        first = chain.next_heartbeat()
        verifier.observe(first.commitment, first.reveal)
        # An attacker sends a fresh commitment without revealing the prior secret.
        second = chain.next_heartbeat()
        assert verifier.observe(second.commitment, None) is False

    def test_wrong_reveal_breaks_chain(self):
        verifier = CanaryVerifier()
        chain = CanaryChain()
        first = chain.next_heartbeat()
        verifier.observe(first.commitment, first.reveal)
        # Attacker sends a fresh commitment but a wrong reveal.
        forged_reveal = compute_commitment(b"forged")
        second_commitment = compute_commitment(b"second")
        assert verifier.observe(second_commitment, forged_reveal) is False

    def test_long_chain(self):
        verifier = CanaryVerifier()
        chain = CanaryChain()
        for _ in range(20):
            msg = chain.next_heartbeat()
            assert verifier.observe(msg.commitment, msg.reveal) is True

    def test_last_commitment_tracks_state(self):
        verifier = CanaryVerifier()
        chain = CanaryChain()
        first = chain.next_heartbeat()
        verifier.observe(first.commitment, first.reveal)
        assert verifier.last_commitment == first.commitment
        second = chain.next_heartbeat()
        verifier.observe(second.commitment, second.reveal)
        assert verifier.last_commitment == second.commitment

    def test_reset_clears_state(self):
        verifier = CanaryVerifier()
        chain = CanaryChain()
        verifier.observe(chain.next_heartbeat().commitment)
        verifier.reset()
        assert verifier.last_commitment is None
        # After reset, the next heartbeat is treated as a fresh first heartbeat.
        new_chain = CanaryChain()
        first = new_chain.next_heartbeat()
        assert verifier.observe(first.commitment) is True

    def test_empty_commitment_rejected(self):
        verifier = CanaryVerifier()
        with pytest.raises(CanaryChainError):
            verifier.observe("")


class TestEndToEndChain:
    def test_persisted_state_across_verifier_restarts(self):
        """
        Verifier state must persist across restarts (only one string per agent).
        Simulate a restart by creating a new verifier and seeding it from the
        last_commitment of the old one.
        """
        chain = CanaryChain()
        v1 = CanaryVerifier()

        first = chain.next_heartbeat()
        v1.observe(first.commitment, first.reveal)
        second = chain.next_heartbeat()
        v1.observe(second.commitment, second.reveal)

        last_commit = v1.last_commitment

        # Restart verifier, seed it manually.
        v2 = CanaryVerifier()
        v2._last_commitment = last_commit  # pylint: disable=protected-access
        v2._expecting_reveal = True  # pylint: disable=protected-access

        third = chain.next_heartbeat()
        assert v2.observe(third.commitment, third.reveal) is True
