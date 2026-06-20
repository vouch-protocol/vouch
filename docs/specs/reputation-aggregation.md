# Vouch Reputation: Evidence-Backed Aggregation (design spec)

Status: draft. This is the contract the `vouch` reputation modules implement.

## Principle

Reputation is a verifiable aggregate of signed, interaction-bound receipts,
computed by a public deterministic function and keyed to an agent's DID. A
consumer trusts the signatures and the function, never a server's stored number.
Given the same receipts and the same function version, every party computes the
same score.

This supersedes a mutable operator-kept score. The existing `vouch.reputation`
engine remains as an optional, subjective signal; this system is the
evidence-backed path.

## Dimensions

Scores are multi-dimensional. The baseline set:

- `reliability` - did the agent's actions and pre-committed claims hold up.
- `performance` - latency, throughput, SLA adherence.
- `compliance` - policy and authorization adherence; absence of violations.
- `satisfaction` - subjective counterparty experience.

A `composite` is derived from the dimensions. The set is extensible; unknown
dimensions are carried through.

## Receipts (the inputs)

Every input is a signed Verifiable Credential about an agent DID, tied to an
`interactionId`. Four types, objective-first:

| Type | Issuer | Objectivity | Base weight |
|---|---|---|---|
| `StateReceipt` | the relying party the agent acted on | objective | high |
| `OutcomeAttestationCredential` | a neutral settler (existing) | objective | high |
| `PenaltyReceipt` | a validator or authority | objective | high |
| `ReviewCredential` | a human rater, bound to proof-of-interaction (existing) | subjective | low |

A receipt the agent can withhold (an agent-issued receipt) is not admissible as
an objective signal. The strong objective source is the relying-party
`StateReceipt`, which the counterparty issues.

## Normalization

Each receipt normalizes to zero or more `Signal`s:

```
Signal = {
  dimension: str,
  value: float in [-1, 1],   # -1 worst, +1 best
  source_type: str,          # the receipt type, drives base weight
  issuer: str,               # issuer DID, for issuer-weighting
  interaction_id: str,
  timestamp: datetime,       # the receipt's validFrom
}
```

Normalization rules:

- `StateReceipt`: `result == success` to `reliability +1`, `failure` to `-1`;
  `slaMet` to `performance +/-1`.
- `OutcomeAttestationCredential`: `outcome.matchesCommitment` to `reliability +/-1`.
- `PenaltyReceipt`: a negative signal on the named dimension (default
  `compliance`), magnitude `-severity`, with `severity` in `[0, 1]`.
- `ReviewCredential`: each rating `r` in `1..5` maps to `(r - 3) / 2` on the
  matching dimension, else `satisfaction`.

## Aggregation function

Deterministic and versioned (`AGGREGATION_VERSION`). For each dimension, over its
signals:

```
w(signal)        = type_weight[source_type]
                 * decay(age, half_life)
                 * issuer_weight(issuer)
                 * stake_factor(signal)
decay(age, hl)   = 0.5 ** (age_days / half_life_days)
dimension_score  = baseline + span * ( Σ value*w / max(Σ w, eps) )   # clamped [0, 100]
composite        = support-weighted mean of the present dimension scores
```

Defaults: `baseline = 50`, `span = 50` (scores in `[0, 100]`), `half_life = 90
days`, `type_weight = {StateReceipt: 1.0, OutcomeAttestationCredential: 1.0,
PenaltyReceipt: 1.0, ReviewCredential: 0.4}`. `issuer_weight` defaults to uniform
`1.0`; a recursive issuer-reputation weighting is a later refinement.
`stake_factor` defaults to `1.0`.

The function is pure: inputs are the signals plus an explicit evaluation time
`at`, so any party recomputes the same result.

## Verification model

A consumer verifies a score by (1) checking each receipt's Data Integrity proof
against its issuer, (2) discarding receipts from revoked or inadmissible issuers,
and (3) replaying the named `AGGREGATION_VERSION` over the admissible signals.
Receipts are kept in an append-only Merkle log so the input set has an inclusion
proof and cannot be silently edited.

## Anti-gaming

- Proof-of-interaction gate: a signal counts only if its receipt binds issuer,
  agent, and a specific interaction.
- Issuer weighting: a receipt counts in proportion to the issuer's own standing.
- Optional slashable stake on high-assurance receipts.
- Time decay: standing trends to baseline without fresh evidence.

## Build phases

- Phase 1: receipt types (`StateReceipt`, `PenaltyReceipt`) and normalization
  (covering the two existing types too).
- Phase 2: the aggregation function.
- Phase 3: the service (Merkle log, `GET /v1/reputation/{did}`, signed snapshots).
- Phase 4: token attachment (`AccountabilityRecord` pointer) and verifier
  threshold integration.
- Phase 5: zero-knowledge portability and dispute resolution.

## Free vs commercial

Receipt formats, the aggregation function, and a self-hostable service are open.
The hosted registry at scale, certified scoring, anti-fraud, and dispute
arbitration are commercial.
