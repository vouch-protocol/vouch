"""
Outcome-evidence credentials: commit a verdict before the outcome, settle it later.

Vouch proves *who* acted. This demo shows the complementary layer: proving an
agent's verdict was fixed *before* its outcome was known, so its track record
cannot be backdated or cherry-picked.

Run:
    python examples/accountability_demo.py
"""

from datetime import datetime, timedelta, timezone

from vouch import Signer, generate_identity
from vouch.accountability import (
    accountability_pointer,
    attest_outcome,
    commit_outcome,
    verify_attestation,
    verify_commitment,
)


def main() -> None:
    # Two independent parties: the agent making the call, and a neutral settler.
    agent_kp = generate_identity(domain="agent.example.com")
    agent = Signer(private_key=agent_kp.private_key_jwk, did=agent_kp.did)

    settler_kp = generate_identity(domain="settler.example.com")
    settler = Signer(private_key=settler_kp.private_key_jwk, did=settler_kp.did)

    committed_at = datetime.now(timezone.utc)

    # 1) The agent commits a verdict BEFORE the outcome is known. Private mode
    #    publishes only a salted digest, so the verdict cannot be read or
    #    front-run, yet is provably unalterable.
    claim = {"asset": "XYZ", "direction": "up", "horizon": "2026-07-01"}
    settlement = {
        "method": "market-settlement",
        "locator": "https://example.com/markets/42",
        "resolutionCriteria": "settled price at expiry versus strike",
        "resolveBy": "2026-07-01T00:00:00Z",
    }
    commitment, secret = commit_outcome(
        agent,
        claim=claim,
        settlement=settlement,
        claim_type="prediction",
        private=True,
        valid_from=committed_at,
    )

    ok, _ = verify_commitment(commitment, agent_kp.public_key_jwk)
    print("commitment id:        ", commitment["id"])
    print("verdict published?    ", "claim" in commitment["credentialSubject"])  # False
    print("digest:               ", commitment["credentialSubject"]["commitment"]["digest"])
    print("commitment verifies:  ", ok)

    # 2) After the outcome is observable, the neutral settler reveals the claim
    #    and salt, binds the observed outcome to the prior commitment, and signs.
    outcome = {
        "result": "up",
        "evidence": "https://example.com/markets/42/settle",
        "observedAt": "2026-07-01T00:05:00Z",
    }
    attestation = attest_outcome(
        settler,
        commitment=commitment,
        outcome=outcome,
        secret=secret,
        matches=True,
        valid_from=committed_at + timedelta(days=14),
    )

    # 3) Anyone verifies: the settler's signature, that the revealed claim
    #    recomputes to the committed digest, and that settlement did not predate
    #    the commitment.
    ok, subject = verify_attestation(
        attestation,
        settler_kp.public_key_jwk,
        commitment=commitment,
        committer_public_key=agent_kp.public_key_jwk,
    )
    print("\nrevealed verdict:     ", subject["reveal"]["claim"])
    print("outcome correct?      ", subject["outcome"]["matchesCommitment"])
    print("settled by:           ", attestation["issuer"])
    print("attestation verifies: ", ok)

    # A backdated settlement (timestamped before the commitment) is rejected.
    backdated = attest_outcome(
        settler,
        commitment=commitment,
        outcome=outcome,
        secret=secret,
        valid_from=committed_at - timedelta(days=1),
    )
    ok_bad, _ = verify_attestation(backdated, settler_kp.public_key_jwk, commitment=commitment)
    print("backdated settlement: ", "rejected" if not ok_bad else "ACCEPTED (bug)")

    # An identity credential can point at the settled record.
    pointer = accountability_pointer(
        ledger="https://example.com/markets/42",
        record=attestation["id"],
        subject=agent_kp.did,
    )
    print("\naccountability pointer:", pointer)


if __name__ == "__main__":
    main()
