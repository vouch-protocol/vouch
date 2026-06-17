# Outcome Evidence Reference

Vouch proves who acted and under what authority. Outcome evidence proves a
different thing: that an agent's verdict, prediction, or recommendation was fixed
before its result was known, so a track record cannot be backdated or
cherry-picked. It ships in the Python SDK as `vouch.accountability`.

## Two credential types

- **OutcomeCommitmentCredential**: a claim committed and signed before the
  outcome is known. The subject carries a salted SHA-256 digest of the
  JCS-canonical claim, so the claim can stay private until settlement yet is
  provably fixed at commit time.
- **OutcomeAttestationCredential**: signed by a settler, who may differ from the
  committer. It reveals the claim and salt, lets anyone recompute the committed
  digest, and binds the observed outcome back to the commitment.

Both are ordinary `eddsa-jcs-2022` Verifiable Credentials, so they verify across
the language SDKs.

## Why the record is hard to game

- Commit-before-outcome: the signed `created` time and the digest are fixed at
  commit time, so a winning verdict cannot be minted after the result is known.
- Private reveal: a salt lets you publish only the digest, so the verdict cannot
  be read or front-run before settlement.
- Neutral settler: the settlement is signed by whoever observed the result and
  binds to the committed digest, not to trust in the committer.
- Verification rejects any settlement timestamped before its commitment.

## Commit a verdict before the outcome

```python
from vouch import Signer, generate_identity
from vouch.accountability import commit_outcome, verify_commitment

keys = generate_identity("agent.example.com")
agent = Signer(private_key=keys.private_key_jwk, did=keys.did)

commitment, secret = commit_outcome(
    agent,
    claim={"asset": "XYZ", "direction": "up", "horizon": "2026-07-01"},
    settlement={
        "method": "market-settlement",
        "locator": "https://example.com/markets/42",
        "resolutionCriteria": "settled price at expiry versus strike",
    },
    private=True,  # publish only the digest; keep `secret` to settle later
)

ok, _ = verify_commitment(commitment, keys.public_key_jwk)
```

Keep `secret` (the claim and salt). It is required to settle a private
commitment later.

## Settle the outcome later

```python
from vouch.accountability import attest_outcome, verify_attestation

# a neutral settler observes the result and binds it to the commitment
attestation = attest_outcome(
    settler,  # a Signer; may be a third party, not the committer
    commitment=commitment,
    outcome={"result": "up", "evidence": "https://example.com/markets/42/settle"},
    secret=secret,
    matches=True,
)

ok, subject = verify_attestation(
    attestation,
    settler_keys.public_key_jwk,
    commitment=commitment,
    committer_public_key=agent_keys.public_key_jwk,
)
# verification rejects a settlement timestamped before its commitment
```

## Reference a record from another credential

```python
from vouch.accountability import accountability_pointer

pointer = accountability_pointer(
    ledger="https://example.com/markets/42",
    record=attestation["id"],
    subject=keys.did,
)
# embed `pointer` in another credential's subject as an AccountabilityRecord
```

## How it relates to the reputation engine

`vouch.reputation` keeps a score that the operator updates. Outcome evidence is
the tamper-evident record underneath such a score: a per-verdict artifact the
subject cannot edit. Feed settled attestations into the reputation engine rather
than trusting a self-reported number.

## Runnable demo and disclosure

- Demo: `python examples/accountability_demo.py`
- Defensive disclosure: PAD-071 in `docs/disclosures/`.
