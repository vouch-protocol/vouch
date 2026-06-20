# Evidence-Backed Reputation Reference

Reputation in Vouch is a verifiable aggregate of signed, interaction-bound
receipts, computed by a public deterministic function and keyed to the agent's
DID. A consumer trusts the signatures and the math, never a server's stored
number: given the same receipts and the same function version, every party
computes the same score. It ships in the Python SDK across `vouch.receipts`,
`vouch.reputation_aggregate`, `vouch.reputation_ledger`, `vouch.reputation_policy`,
`vouch.reputation_portability`, and `vouch.reputation_disputes`.

This is distinct from the older `vouch.reputation` engine, which keeps a mutable
operator-set score. The evidence-backed path is the one to lead with.

## The signals (objective-first)

Every input is a signed Verifiable Credential about an agent DID, tied to an
`interactionId`:

- `StateReceipt`: the relying party the agent acted on signs the result of an
  action (success or failure, SLA met). The agent cannot withhold it. Objective.
- `OutcomeAttestationCredential`: a settled commit-before-outcome verdict (from
  `vouch.accountability`). Objective.
- `PenaltyReceipt`: a validator or authority records a violation. Negative.
- `ReviewCredential`: a human rater's multi-dimensional rating, bound to proof of
  interaction. Subjective, low weight.

Each receipt normalizes to dimensioned signals (`reliability`, `performance`,
`compliance`, `satisfaction`) in [-1, 1].

## The aggregation function

Deterministic and versioned. A signal contributes to its dimension with weight
`type_weight(source) * decay(age) * issuer_weight(issuer)`. A dimension score is
the baseline plus the weighted-mean signal value scaled across the span, clamped
to [0, 100]; the composite is the support-weighted mean of the dimensions.

```python
from vouch.reputation_aggregate import aggregate_receipts

score = aggregate_receipts(receipts, agent="did:web:agent.example.com")
print(score.composite, score.dimensions)
```

## The ledger and a signed snapshot

```python
from vouch.reputation_ledger import ReputationLedger, verify_reputation_credential

ledger = ReputationLedger(resolver=lambda did: public_key_for(did))
ledger.append(state_receipt)   # verifies the signature before admitting it
snapshot = ledger.snapshot(registry_signer, agent_did)   # a signed ReputationCredential
```

The ledger keeps receipts in a Merkle log, so a consumer can be handed the
receipts plus inclusion proofs and recompute the score rather than trust the
snapshot's number.

## Policy gate, portability, disputes

```python
from vouch.reputation_policy import evaluate_reputation, policy_for_stakes
decision = evaluate_reputation(snapshot, policy_for_stakes("high"), public_key=registry_pub)

from vouch.reputation_portability import build_reputation_proof
proof = build_reputation_proof(registry_signer, agent_did, score,
    predicates=[{"path": "composite", "op": ">=", "value": 75}], audience=verifier_did)
# proves the threshold without revealing the score

from vouch.reputation_disputes import build_dispute, build_dispute_resolution
ledger.apply_resolution(resolution, arbiter_pub)   # an upheld dispute drops the receipt
```

## Where it sits

Reviews and ratings are a subjective, application-level signal and easy to game;
objective receipts (relying-party state, settled outcomes) carry the score.
Demo: `python examples/reputation_demo.py`. The hosted registry and a public
`GET /v1/reputation/{did}` API are a separate commercial layer; the formats, the
aggregation function, and a self-hostable ledger are open.
