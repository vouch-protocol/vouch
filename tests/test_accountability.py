"""Tests for outcome-evidence credentials (commit-before-outcome + settlement)."""

from datetime import datetime, timedelta, timezone

import pytest

from vouch import Signer, generate_identity
from vouch.accountability import (
    OUTCOME_ATTESTATION_TYPE,
    OUTCOME_COMMITMENT_TYPE,
    AccountabilityError,
    accountability_pointer,
    attest_outcome,
    commit_outcome,
    commitment_digest,
    verify_attestation,
    verify_commitment,
)


def _identity(domain: str = "agent.example.com"):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


SETTLEMENT = {
    "method": "market-settlement",
    "locator": "https://example.com/markets/42",
    "resolutionCriteria": "settled price at expiry vs strike",
    "resolveBy": "2026-07-01T00:00:00Z",
}

CLAIM = {"asset": "XYZ", "direction": "up", "horizon": "2026-07-01"}
OUTCOME = {"result": "up", "evidence": "https://example.com/markets/42/settle"}


class TestCommitment:
    def test_public_commit_and_verify(self):
        kp, signer = _identity()
        cred, secret = commit_outcome(signer, claim=CLAIM, settlement=SETTLEMENT)

        assert OUTCOME_COMMITMENT_TYPE in cred["type"]
        assert cred["issuer"] == kp.did
        subject = cred["credentialSubject"]
        assert subject["id"] == kp.did  # self-commitment by default
        assert subject["claim"] == CLAIM  # public claim disclosed
        assert subject["commitment"]["salted"] is False
        assert secret["claim"] == CLAIM

        ok, returned = verify_commitment(cred, kp.public_key_jwk)
        assert ok is True
        assert returned["commitment"]["digest"] == subject["commitment"]["digest"]

    def test_public_commitment_digest_matches_claim(self):
        _, signer = _identity()
        cred, _ = commit_outcome(signer, claim=CLAIM, settlement=SETTLEMENT)
        from vouch.accountability import _mb64  # internal helper, tested for parity

        assert cred["credentialSubject"]["commitment"]["digest"] == _mb64(
            commitment_digest(CLAIM, None)
        )

    def test_private_commit_hides_claim(self):
        kp, signer = _identity()
        cred, secret = commit_outcome(signer, claim=CLAIM, settlement=SETTLEMENT, private=True)

        subject = cred["credentialSubject"]
        assert "claim" not in subject  # withheld until settlement
        assert subject["commitment"]["salted"] is True
        assert secret["salt"] is not None
        assert secret["claim"] == CLAIM

        ok, _ = verify_commitment(cred, kp.public_key_jwk)
        assert ok is True

    def test_wrong_key_fails(self):
        _, signer = _identity()
        other, _ = _identity("other.example.com")
        cred, _ = commit_outcome(signer, claim=CLAIM, settlement=SETTLEMENT)
        ok, _ = verify_commitment(cred, other.public_key_jwk)
        assert ok is False

    def test_tampered_digest_fails_proof(self):
        kp, signer = _identity()
        cred, _ = commit_outcome(signer, claim=CLAIM, settlement=SETTLEMENT)
        cred["credentialSubject"]["commitment"]["digest"] = "uAAAA"
        ok, _ = verify_commitment(cred, kp.public_key_jwk)
        assert ok is False

    def test_settlement_fields_required(self):
        _, signer = _identity()
        with pytest.raises(AccountabilityError):
            commit_outcome(
                signer, claim=CLAIM, settlement={"method": "oracle"}
            )  # missing resolutionCriteria

    def test_claim_must_be_object(self):
        _, signer = _identity()
        with pytest.raises(AccountabilityError):
            commit_outcome(signer, claim="up", settlement=SETTLEMENT)


class TestAttestation:
    def test_full_private_chain(self):
        kp, signer = _identity()
        cred, secret = commit_outcome(signer, claim=CLAIM, settlement=SETTLEMENT, private=True)
        att = attest_outcome(signer, commitment=cred, outcome=OUTCOME, secret=secret, matches=True)

        assert OUTCOME_ATTESTATION_TYPE in att["type"]
        subj = att["credentialSubject"]
        assert subj["reveal"]["claim"] == CLAIM
        assert subj["outcome"]["matchesCommitment"] is True
        assert subj["commitment"]["digest"] == cred["credentialSubject"]["commitment"]["digest"]

        ok, _ = verify_attestation(
            att, kp.public_key_jwk, commitment=cred, committer_public_key=kp.public_key_jwk
        )
        assert ok is True

    def test_neutral_third_party_settler(self):
        committer_kp, committer = _identity("committer.example.com")
        settler_kp, settler = _identity("settler.example.com")

        cred, secret = commit_outcome(committer, claim=CLAIM, settlement=SETTLEMENT, private=True)
        att = attest_outcome(settler, commitment=cred, outcome=OUTCOME, secret=secret, matches=True)

        assert att["issuer"] == settler_kp.did
        assert att["credentialSubject"]["id"] == committer_kp.did  # subject is still the committer
        ok, _ = verify_attestation(
            att,
            settler_kp.public_key_jwk,
            commitment=cred,
            committer_public_key=committer_kp.public_key_jwk,
        )
        assert ok is True

    def test_reveal_mismatch_rejected_at_signing(self):
        _, signer = _identity()
        cred, secret = commit_outcome(signer, claim=CLAIM, settlement=SETTLEMENT, private=True)
        with pytest.raises(AccountabilityError):
            attest_outcome(
                signer,
                commitment=cred,
                outcome=OUTCOME,
                claim={"asset": "XYZ", "direction": "down", "horizon": "2026-07-01"},
                salt=None,
            )

    def test_salt_required_for_salted_commitment(self):
        _, signer = _identity()
        cred, _ = commit_outcome(signer, claim=CLAIM, settlement=SETTLEMENT, private=True)
        with pytest.raises(AccountabilityError):
            attest_outcome(signer, commitment=cred, outcome=OUTCOME, claim=CLAIM)

    def test_backdated_settlement_rejected(self):
        kp, signer = _identity()
        committed_at = datetime(2026, 6, 17, 0, 0, 0, tzinfo=timezone.utc)
        cred, secret = commit_outcome(
            signer, claim=CLAIM, settlement=SETTLEMENT, private=True, valid_from=committed_at
        )
        # Settlement timestamped BEFORE the commitment must be rejected.
        att = attest_outcome(
            signer,
            commitment=cred,
            outcome=OUTCOME,
            secret=secret,
            valid_from=committed_at - timedelta(days=1),
        )
        ok, _ = verify_attestation(att, kp.public_key_jwk, commitment=cred)
        assert ok is False

    def test_forward_settlement_accepted(self):
        kp, signer = _identity()
        committed_at = datetime(2026, 6, 17, 0, 0, 0, tzinfo=timezone.utc)
        cred, secret = commit_outcome(
            signer, claim=CLAIM, settlement=SETTLEMENT, private=True, valid_from=committed_at
        )
        att = attest_outcome(
            signer,
            commitment=cred,
            outcome=OUTCOME,
            secret=secret,
            valid_from=committed_at + timedelta(days=7),
        )
        ok, _ = verify_attestation(att, kp.public_key_jwk, commitment=cred)
        assert ok is True

    def test_tampered_reveal_fails_verification(self):
        kp, signer = _identity()
        cred, secret = commit_outcome(signer, claim=CLAIM, settlement=SETTLEMENT, private=True)
        att = attest_outcome(signer, commitment=cred, outcome=OUTCOME, secret=secret)
        # Swap the revealed claim after signing: digest no longer reproduces, and
        # the settler proof breaks too.
        att["credentialSubject"]["reveal"]["claim"] = {"asset": "XYZ", "direction": "down"}
        ok, _ = verify_attestation(att, kp.public_key_jwk)
        assert ok is False

    def test_digest_mismatch_between_commitment_and_attestation(self):
        kp, signer = _identity()
        cred_a, secret_a = commit_outcome(signer, claim=CLAIM, settlement=SETTLEMENT, private=True)
        other_claim = {"asset": "ABC", "direction": "up", "horizon": "2026-07-01"}
        cred_b, _ = commit_outcome(signer, claim=other_claim, settlement=SETTLEMENT, private=True)
        att = attest_outcome(signer, commitment=cred_a, outcome=OUTCOME, secret=secret_a)
        # Attestation settles commitment A but is checked against commitment B.
        ok, _ = verify_attestation(att, kp.public_key_jwk, commitment=cred_b)
        assert ok is False


class TestAccountabilityPointer:
    def test_pointer_shape(self):
        ptr = accountability_pointer(
            ledger="https://example.com/ledger",
            record="anchor-1",
            subject="did:web:agent.example.com",
            digest="uABC",
        )
        assert ptr["type"] == "AccountabilityRecord"
        assert ptr["ledger"] == "https://example.com/ledger"
        assert ptr["record"] == "anchor-1"
        assert ptr["subject"] == "did:web:agent.example.com"
        assert ptr["digest"] == "uABC"

    def test_pointer_requires_ledger(self):
        with pytest.raises(AccountabilityError):
            accountability_pointer(ledger="")


class TestDigest:
    def test_reproducible_and_salt_sensitive(self):
        d1 = commitment_digest(CLAIM, None)
        d2 = commitment_digest(CLAIM, None)
        assert d1 == d2
        assert commitment_digest(CLAIM, b"\x00" * 32) != d1
