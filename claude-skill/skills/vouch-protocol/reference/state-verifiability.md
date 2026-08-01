# State Verifiability Reference

The State Verifiability layer answers: "Is this agent still behaving
correctly RIGHT NOW, after we let it through the door?" Built on top of
the credential layer; uses the SessionVoucher credential format.

Seven composable modules shipped in the Python SDK:

- `vouch.trust_entropy` - decay computation
- `vouch.authority_state` - authority state as an input to freshness
- `vouch.behavioral_attestation` - per-interval signal collection
- `vouch.canary` - commit/reveal chain (silent-failure detection)
- `vouch.merkle` - Merkle tree primitives
- `vouch.heartbeat` - the renewal protocol orchestration
- `vouch.quorum` - M-of-N validator federation

TypeScript and Go ports are work-in-progress; data formats are
cross-language but the runtime orchestration is Python-only today.
`vouch.authority_state` is the exception: it ships in the Rust core
and in Python, TypeScript, and Go.

## Trust Entropy decay

A SessionVoucher carries `initialTrust` and `decayLambda`; the agent's
effective trust decays exponentially over time:

```
trust(t) = initialTrust * exp(-decayLambda * (now - issuedAt_seconds))
```

```python
from vouch import compute_trust_at, check_trust_threshold
from vouch.trust_entropy import (
    TRUST_THRESHOLD_HIGH_STAKES,    # 0.9
    TRUST_THRESHOLD_MEDIUM_STAKES,  # 0.75
    TRUST_THRESHOLD_LOW_STAKES,     # 0.5
)
from datetime import datetime, timezone

trust = compute_trust_at(session_voucher, at_time=datetime.now(timezone.utc))

if check_trust_threshold(session_voucher, TRUST_THRESHOLD_HIGH_STAKES):
    allow_financial_transaction()
elif check_trust_threshold(session_voucher, TRUST_THRESHOLD_MEDIUM_STAKES):
    allow_phi_read()
elif check_trust_threshold(session_voucher, TRUST_THRESHOLD_LOW_STAKES):
    allow_status_query()
else:
    reject_action()
```

`half_life_seconds(decay_lambda)` returns `ln(2) / decay_lambda`. Set
heartbeat intervals less than the half-life so renewal stays ahead of
decay.

## Authority Freshness

Time-decay answers "how long ago was this trust established". That is
necessary but not sufficient for a treasury or trading agent, whose
mandate can be suspended seconds after a perfectly valid SessionVoucher
was issued. The voucher's decayed trust is still well above threshold,
and the revocation cache may not refresh for minutes. Authority
Freshness closes that window by treating a change in authority state as
a first-class input to freshness:

```
freshness(action) = f(elapsed_time, authority_state_version, consequence)
```

An authority publishes a signed `AuthorityState` credential carrying
`authorityEpoch`, a counter that only goes up, and a `status`. Any
authority-relevant transition (a fraud signal, a suspended mandate, an
exposure breach, an incident) bumps the epoch. A SessionVoucher records
the epoch it was minted under, and a verifier tracks the highest epoch
it has seen for that authority, learned from a status-list refresh or
from the heartbeat channel.

The collapse rule: for an action whose consequence tier requires
state-freshness, a voucher whose `authorityEpoch` is lower than the
highest epoch the verifier has seen for that authority is rejected, even
when its time-decay trust still passes.

`status` is one of `active`, `suspended`, `incident`,
`exposure_breached`, or `revoked`. `active` is the only value under
which a state-freshness action may proceed.

### Consequence tiers

The tiers are the same `routine` / `sensitive` / `critical` vocabulary
already used for bounded-staleness revocation, so a deployment carries
one consequence vocabulary rather than two.

| Tier | Behavior |
|---|---|
| `routine` | Time-decay only. Authority Freshness adds nothing. |
| `sensitive` | The epoch-collapse rule, enforced locally. |
| `critical` | The epoch-collapse rule and a live M-of-N co-sign, read at action time. |

`routine` and `sensitive` are enforced locally. The epoch comparison is
a comparison of two integers the verifier already holds, so there is no
network call at action time.

`critical` is the tier that needs a live quorum. When the acceptable
window is near zero a cached epoch is not good enough, because the
authority could have changed state between the last refresh and this
action. So the verifier requires a co-sign from an M-of-N quorum
(`vouch.threshold`, FROST over Ed25519), produced at action time and
bound to the action by a nonce. The aggregate is a standard Ed25519
signature, so a verifier checks it with the ordinary verifier and needs
no threshold-signing code of its own.

### Using it

The gate is folded into the one composed trust check:

```python
from vouch.trust_check import verify_agent_call
from vouch import CONSEQUENCE_SENSITIVE

verdict = verify_agent_call(
    credential,
    public_key=caller_key,
    session_voucher=voucher,          # carries authorityEpoch 5
    trust_threshold=0.9,
    consequence=CONSEQUENCE_SENSITIVE,
    last_seen_authority_epoch=7,      # a suspension already bumped it
)
# verdict.ok is False; verdict.authority_reason is
# "authority_epoch_stale:seen=7,voucher=5", even though verdict.trust_ok is True.
```

The default tier is `routine`, so existing callers see no change until
they opt a higher tier in.

Reason codes are identical across every language binding, so an audit
log reads the same whichever SDK produced it. An absent epoch renders as
`?` and the check fails closed, for example
`authority_epoch_unknown:voucher=?,seen=9`. Every reason code is pinned
by the shared interop vector at `test-vectors/authority-state/`.

Implemented in the Rust core and in Python, TypeScript, and Go, signed
with `eddsa-jcs-2022` like every other credential.

## Behavioral Attestation

Per-interval signal collection. Agent records signals as it runs; on
each heartbeat the collector produces a `behavioralDigest`:

```python
from vouch import BehavioralCollector
from vouch.behavioral_attestation import ewma_drift_scorer

collector = BehavioralCollector(intent_drift_scorer=ewma_drift_scorer(alpha=0.3))

# During the interval
collector.record_api_call("https://api.example.com/orders", tokens=120)
collector.record_api_call("https://api.example.com/users", tokens=50, drift=0.1)
collector.record_resource_access("order:42")

# At heartbeat time
digest = collector.digest()
# {
#     "apiCalls": 2,
#     "tokensConsumed": 170,
#     "resourcesAccessed": ["order:42"],
#     "intentDriftScore": 0.1
# }
collector.reset()  # start fresh for next interval
```

Three reference drift scorers:

- `mean_drift_scorer` (default): arithmetic mean of samples
- `max_drift_scorer`: most cautious, highest sample wins
- `ewma_drift_scorer(alpha)`: exponential weighted moving average, recent samples weighted

Resource list capped at `DEFAULT_MAX_RESOURCES` (64) to prevent unbounded
growth. Beyond the cap, counts remain accurate in `apiCalls` but
individual URIs aren't enumerated.

## Canary Commitments

Commit/reveal chain. Every heartbeat commits to a fresh secret hash;
the next heartbeat reveals the prior secret. A missed heartbeat means
no future heartbeat can resume the chain. Silent-failure detection.

```python
from vouch import CanaryChain, CanaryVerifier

# Agent side
chain = CanaryChain()
msg = chain.next_heartbeat()
# msg.commitment is what to send this interval
# msg.reveal is the previous secret (None on first interval)

# Validator side
verifier = CanaryVerifier()
ok = verifier.observe(msg.commitment, msg.reveal)
if not ok:
    revoke_session_voucher()
```

Secrets are 32 random bytes; commitments are SHA-256 of the secret,
multibase base64url encoded. Verifier state is small (one string per
agent), so it survives validator restarts cheaply via `last_commitment`
persistence.

## Merkle trees

RFC 6962 domain-separated Merkle tree for `actionMerkleRoot` in
heartbeats, and as a primitive for selective disclosure:

```python
from vouch import MerkleTree, compute_action_merkle_root, verify_inclusion

# Build a tree
tree = MerkleTree(leaves=[b"action_1", b"action_2", b"action_3"])
root = tree.root_multibase()

# Inclusion proof for one leaf
proof = tree.proof(leaf_index=1)
# proof.leaf_index = 1
# proof.steps = [ProofStep(sibling, is_right), ...]

# Verify
ok = verify_inclusion(leaf=b"action_2", proof=proof, root=tree.root())
```

Domain separation: leaves hashed with `0x00` prefix, internal nodes
with `0x01` prefix. Prevents the classic second-preimage attack where
an internal node hash is fed back as a "leaf."

## Heartbeat Protocol

Composes the four primitives above. Agent side:

```python
from vouch import HeartbeatSession, HeartbeatScheduler
import asyncio

session = HeartbeatSession(subject_did="did:web:agent.example.com")

# During agent activity
session.record_action(b"submit_claim:HC-001")
session.collector.record_api_call("https://api.example.com/orders", tokens=120)

# Submit callback
async def submit(req):
    signed = signer.sign(req.to_dict())
    response = await http.post(validator_url, json=signed)
    new_session_voucher = response.json()
    return new_session_voucher

scheduler = HeartbeatScheduler(
    session=session,
    interval_seconds=60,
    submit_callback=submit,
)
scheduler.start()
# ... agent runs ...
await scheduler.stop()
```

Validator side:

```python
from vouch import HeartbeatValidator, MemoryHeartbeatStore

validator = HeartbeatValidator(
    validator_did="did:web:validator.example.com",
    initial_trust=1.0,
    decay_lambda=0.01,
    voucher_valid_seconds=120,
    scope=["agent_actions"],
    store=MemoryHeartbeatStore(),  # or RedisHeartbeatStore in production
)

result = validator.validate(heartbeat_request_dict)
if result.ok:
    new_voucher = result.session_voucher  # unsigned, caller signs
else:
    for reason in result.reasons:
        log(reason)
```

The validator checks: schema, behavioral digest structure, canary
chain integrity, interval-index monotonicity. On success, returns an
unsigned SessionVoucher carrying configured trust parameters.

## Validator Quorum (M-of-N)

Single validators are single points of failure. A regulated deployment
uses multiple validators with different responsibilities:

```python
from vouch import HeartbeatQuorum, QuorumValidator, ROLE_POLICY, ROLE_BEHAVIORAL, ROLE_BUDGET

quorum = HeartbeatQuorum(
    validators=[
        QuorumValidator(validator=policy_validator, role=ROLE_POLICY),
        QuorumValidator(validator=behavioral_validator, role=ROLE_BEHAVIORAL),
        QuorumValidator(validator=budget_validator, role=ROLE_BUDGET),
    ],
    threshold=2,  # 2-of-3
)

result = quorum.validate(heartbeat_request_dict)
if result.ok:
    voucher = result.session_voucher  # issuer field lists all approving DIDs
```

Trust parameter aggregation across approving validators (configurable):

- `initial_trust`: minimum (most cautious, default)
- `decay_lambda`: maximum (fastest decay, default)
- `scope`: intersection (only allow capabilities ALL approvers grant)

Custom aggregation via `QuorumPolicy`:

```python
from vouch.quorum import QuorumPolicy

def avg(values):
    return sum(values) / len(values)

policy = QuorumPolicy(initial_trust_aggregator=avg)
quorum = HeartbeatQuorum(validators=[...], threshold=2, policy=policy)
```

Weighted voting:

```python
v1 = QuorumValidator(validator=senior, weight=2.0)
v2 = QuorumValidator(validator=junior, weight=1.0)
quorum = HeartbeatQuorum(validators=[v1, v2], threshold=2)
# senior alone meets threshold 2; junior alone doesn't
```

## Pluggable storage

`HeartbeatStoreInterface` keeps per-session state. JSON-serializable
state dict: `{ last_commitment, expecting_reveal, last_interval }`.

```python
from vouch import HeartbeatValidator, MemoryHeartbeatStore

# Default: in-memory
validator = HeartbeatValidator(validator_did="...")

# Custom store
class RedisHeartbeatStore(HeartbeatStoreInterface):
    def get(self, key): ...
    def put(self, key, state): ...
    def delete(self, key): ...
    def known_sessions(self): ...

validator = HeartbeatValidator(validator_did="...", store=RedisHeartbeatStore(redis_url))
```

The state survives validator restarts; tests demonstrate this.

## Threshold guidance

For a 60-second heartbeat interval and operation-specific risk:

| Operation type | Recommended threshold | Rationale |
|---|---|---|
| Financial transfer, code deploy | 0.9 (high-stakes) | Trust must be near peak |
| PHI read, customer data access | 0.75 (medium) | Some decay tolerable |
| Status query, idle activity | 0.5 (low) | Renewal soon will recover |

These are reference values; tune per your risk model.

## What's NOT here

The Python implementation is the reference. TypeScript and Go ports
of the runtime modules are still work in progress (the data formats
are cross-language; only the orchestration is Python-only today).

Concrete persistence backends (Redis, Postgres, Kafka, S3 stores for
`HeartbeatStoreInterface`) are not in OSS; they ship in the commercial
Pro tier.

## Common patterns

### "I want my agent to renew its credential every minute"
Run `HeartbeatScheduler` with `interval_seconds=60`. Submit each
heartbeat to the validator's `/heartbeat` endpoint. The new SessionVoucher
gets used for outgoing action credentials.

### "I want multiple validators to agree before issuing a SessionVoucher"
Use `HeartbeatQuorum` with N validators and threshold M. Each validator
checks the heartbeat independently; the SessionVoucher's issuer field
lists the approving DIDs.

### "I want trust to drop fast for misbehaving agents"
Set a high `decay_lambda`. Half-life of 30 seconds: `decay_lambda =
ln(2) / 30 ≈ 0.0231`. After 30 seconds the agent has 50% trust; after
60 seconds, 25%; after 90 seconds, 12.5%. Only frequent renewal keeps
the agent operational.

### "I want a missed heartbeat to immediately revoke"
The canary chain handles this. Without a successful heartbeat, the
prior canary secret stays unrevealed; no subsequent heartbeat can
resume the chain. The validator sees the broken chain and refuses to
issue a new SessionVoucher; the existing voucher expires naturally.

## Common errors

- **`canary_chain_broken`**: agent skipped a heartbeat or sent a wrong
  reveal. Treat as immediate revocation.
- **`stale_interval_index`**: heartbeat's `interval_index` <= last seen.
  Usually a replayed heartbeat. Validator rejects.
- **`behavioral_digest_invalid`**: malformed digest. Validate against
  the schema before sending.
- **`schema_invalid`**: heartbeat request shape doesn't match §11.3.
  Check `HeartbeatRequest.from_dict` validation.
- **`authority_epoch_stale:seen=N,voucher=M`**: the voucher was minted
  under an older authority epoch than the highest the verifier has seen.
  Re-mint the voucher under the current epoch.
- **`authority_epoch_unknown:voucher=?,seen=N`**: an epoch is missing on
  one side, so the check fails closed. Confirm the voucher carries
  `authorityEpoch` and that the verifier has learned an epoch for the
  authority.
- **`authority_status_not_active:status=suspended`**: the authority's
  current status is something other than `active`.
- **`live_cosign_required:tier=critical`**: a `critical` action needs a
  live M-of-N co-sign read at action time; none was supplied or it did
  not verify.
