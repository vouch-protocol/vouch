# DTN-Aware Bounded-Staleness Revocation

**Status:** Draft specification (design)
**Applies to:** `vouch.status_list`, `vouch.robotics.revocation`, offline verifiers
**Companion demo:** [`examples/disconnected_exchange_demo.py`](../examples/disconnected_exchange_demo.py)

## 1. Problem

Vouch already gives an offline verifier everything it needs to check *authority*
without a network call: a delegation lease, a passport, and a robot-to-robot
handshake all verify against pre-distributed trust anchors. Revocation is the
one part of the trust decision that is inherently a *freshness* problem rather
than a *signature* problem.

Today's revocation surface (`BitstringStatusList` status lists plus the whole-DID
`RevocationRegistry`) answers one question: **"was this credential revoked as of
the status list I am holding?"** In a connected setting the verifier just fetches
the current list, so "the list I am holding" and "the current list" are the same
thing.

In a disconnected or delay-tolerant network (DTN) — a robot in a tunnel, an ROV
under water, a node behind hours of light-time — they are not the same thing. The
verifier holds a *snapshot* synced at last contact. A credential revoked five
minutes after that sync looks perfectly valid to it. `verify_status()` will
happily return `False` (not revoked) because that is the honest answer *for the
snapshot it was given* — the function even documents that the caller must verify
the snapshot's proof first, and it makes no claim about the snapshot's age.

The missing piece is not a new signature check. It is a **policy** that binds the
acceptable *age* of the revocation view to the *consequence* of the action being
authorized. A stale view is fine for a telemetry beacon and unacceptable for a
physical maneuver. Nothing in the protocol expresses that today, so every offline
verifier either invents its own ad-hoc rule or (worse) ignores staleness
entirely and treats a week-old "not revoked" as authoritative.

This gap is not space-specific. It is the general disconnected-robotics case;
space is merely its most extreme instance. Anything built here helps a warehouse
robot that lost Wi-Fi for an hour just as much as a lunar relay.

### 1.1 Non-goals

- This is not a replacement for revocation propagation (SLAs, gossip, dashboards)
  — those remain a service concern layered on top.
- This does not attempt to make a stale view *fresh*. It makes staleness
  **explicit, bounded, and fail-closed**.
- No new cryptography and no new DID method. This is a verifier-side policy plus
  two small, backward-compatible fields.

## 2. Model

Three facts are available to a disconnected verifier at decision time:

1. **The credential** being presented, carrying a `credentialStatus` entry that
   points at a status list (already standard).
2. **A revocation snapshot** — a signed `BitstringStatusListCredential` the
   verifier synced at last contact. Its `validFrom` is the authority's assertion
   of *when this revocation view was current*. This is the freshness anchor.
3. **The verifier's own trusted clock.**

Staleness is defined against the snapshot's `validFrom`, not its `validUntil`:

```
staleness = verifier_now − snapshot.validFrom
```

`validFrom` answers "how old is this revocation *knowledge*", which is the
security-relevant quantity. (`validUntil` is the publisher's own expiry and is
still enforced separately — an expired snapshot is unusable regardless of tier.)

> **Why `validFrom` and not the credential's own age.** The credential may be
> long-lived and legitimately so; what must be fresh is the *revocation view*,
> because revocation is the only signal that can turn a still-valid-looking
> credential bad. Binding the budget to the snapshot forces re-sync, not
> re-issuance.

## 3. Consequence tiers

Every authorization is classified into a consequence tier. Tiers and their
default **staleness budgets** (the maximum snapshot age the verifier will accept):

| Tier        | Meaning                                              | Default budget |
| ----------- | ---------------------------------------------------- | -------------- |
| `routine`   | Reversible, low-impact (telemetry, status beacons)   | 30 days        |
| `sensitive` | Data exchange, non-physical commitments, handoffs    | 24 hours       |
| `critical`  | Physical actuation, maneuvers, anything irreversible  | 1 hour         |

Budgets are policy, not protocol constants — an operator tightens or loosens them
per deployment. The tiers and their ordering are the normative part; the numbers
are defaults. A conformant verifier MUST allow budgets to be configured and MUST
treat an unknown tier as `critical` (fail-closed by default).

The consequence tier of an action SHOULD be carried in the grant that authorizes
it, so the issuer — not the verifier — decides how consequential an action is.
Two placements are supported:

- **On the lease scope.** A `DelegationLeaseCredential`'s `physicalScope` MAY
  carry a `freshness` object mapping action names to tiers:

  ```jsonc
  "physicalScope": {
    "actions": ["relay_uplink", "handoff_payload", "maneuver"],
    "freshness": { "maneuver": "critical", "handoff_payload": "sensitive" }
  }
  ```

- **Verifier default.** If the grant is silent, the verifier applies its own
  mapping, defaulting unmapped actions to `critical`.

## 4. The decision procedure

A conformant offline verifier authorizing an action MUST evaluate, in order:

1. **Signature & scope** (existing). Verify the credential's Data Integrity
   proof against a pre-distributed anchor and that the action fits scope. On
   failure → **DENY**.
2. **Snapshot validity** (existing). If a revocation snapshot is present, verify
   its Data Integrity proof and that `verifier_now ≤ snapshot.validUntil`. A
   snapshot that fails either check is treated as **absent** (step 4).
3. **Revocation bit** (existing). `verify_status()` against the snapshot. If the
   bit is set → **DENY** (revoked). This is unconditional and independent of
   freshness: a known revocation always wins.
4. **Freshness gate** (new). Compute `staleness` and compare to the tier budget:
   - snapshot present and `staleness ≤ budget[tier]` → **ALLOW**
   - snapshot present and `staleness > budget[tier]` → **DENY (fail-closed)**
   - snapshot absent and `tier == routine` → **ALLOW**
   - snapshot absent and `tier > routine` → **DENY (fail-closed)**

The ordering matters: a *known* revocation (step 3) denies regardless of tier,
while an *unknowably-stale* view (step 4) denies only for consequential tiers.
The system never treats "I could not check recently enough" as "allowed".

### 4.1 Reference implementation

The freshness gate is small and lives entirely on the verifier. It ships in the
SDK as `vouch.status_list.evaluate_freshness`, alongside the tier constants
(`CONSEQUENCE_ROUTINE` / `CONSEQUENCE_SENSITIVE` / `CONSEQUENCE_CRITICAL`), the
`DEFAULT_STALENESS_BUDGETS` policy defaults, and the `FreshnessVerdict` result:

```python
from vouch.status_list import evaluate_freshness, CONSEQUENCE_CRITICAL

# snapshot is the fetched-at-last-contact BitstringStatusListCredential (or None)
verdict = evaluate_freshness(tier=CONSEQUENCE_CRITICAL, snapshot=snapshot, now=now)
if verdict.allow and not revoked_bit:
    ...  # authorize
```

`evaluate_freshness` judges only the snapshot's age against the tier budget:
it coerces an unknown tier to `critical`, treats a snapshot past its own
`validUntil` (or with a malformed `validFrom`) as absent, and fails closed on
every ambiguous state. Budgets are overridable per call via `budgets=`.

Steps 1–3 are unchanged calls into `verify_delegation_lease()` /
`lease_permits()` / `verify_status()`. The gate composes on top; it does not
modify any existing verifier. A full runnable wiring is in
[`examples/disconnected_exchange_demo.py`](../examples/disconnected_exchange_demo.py).

## 5. Wire format (backward compatible)

Two optional additions, both ignorable by existing verifiers:

1. **`freshness` map** inside a lease's `physicalScope` (§3). Absent → verifier
   default. An old verifier ignores it and falls back to its own tiering, which
   is a safe (fail-closed) direction.

2. **A `snapshotPolicy` hint** MAY be published inside a status list credential's
   `credentialSubject` to advertise the issuer's *expected* re-sync cadence, so a
   verifier can warn when it is drifting toward its budget before it actually
   breaches:

   ```jsonc
   "credentialSubject": {
     "type": "BitstringStatusListEntry",
     "statusPurpose": "revocation",
     "encodedList": "…",
     "snapshotPolicy": { "expectedResyncSeconds": 3600 }
   }
   ```

   This is advisory only. It changes no verification outcome; it exists so a node
   can proactively schedule a re-sync during its next contact window rather than
   discovering staleness at decision time.

Neither field changes the JCS canonicalization behavior of unaware
implementations: unknown members are carried through the proof like any other,
so a credential signed with these fields still verifies byte-identically across
the Python, TypeScript, Go, and Rust cores.

## 6. Security considerations

- **Clock trust.** The whole mechanism rests on the verifier's clock. A verifier
  with an untrusted or unset clock MUST treat every tier above `routine` as
  fail-closed, because it cannot compute staleness. Secure time is a
  prerequisite, and on constrained hardware it typically comes from the same
  attested root as the identity key.
- **Snapshot rollback.** An adversary who can feed the verifier an *older* valid
  snapshot (one signed before a revocation) could hide a revocation. Two
  defenses: (a) the freshness gate itself caps how old an accepted snapshot can
  be, shrinking the rollback window to the budget; (b) a verifier SHOULD refuse a
  snapshot whose `validFrom` predates the newest one it has already seen
  (monotonicity), which eliminates rollback entirely for any node that stays
  powered.
- **Budget as attack surface.** Loosening a budget widens the window in which a
  revoked-but-not-yet-seen credential is honored. Budgets are therefore part of
  the deployment's threat model, not a convenience knob, and the `critical`
  default is deliberately tight.
- **Fail-closed is the invariant.** Every ambiguous state — no snapshot, expired
  snapshot, unknown tier, unusable clock — resolves to DENY for consequential
  actions. "Uncertain" must never read as "authorized" for anything
  irreversible.

## 7. Relationship to existing primitives

| Concern                          | Existing primitive                                | This spec adds                    |
| -------------------------------- | ------------------------------------------------- | --------------------------------- |
| Is the credential authentic?     | `verify_delegation_lease`, Data Integrity proof   | — (unchanged)                     |
| Does the action fit scope?       | `lease_permits`, `check_physical_action`          | — (unchanged)                     |
| Was it revoked (per my snapshot)?| `verify_status`, `BitstringStatusList`            | — (unchanged)                     |
| Is my snapshot fresh *enough*?   | *(none)*                                           | consequence tiers + freshness gate|
| Whole-DID kill on compromise     | `RevocationRegistry`                              | subject to the same freshness gate|

The contribution is deliberately narrow: one policy function and two optional,
ignorable fields, sitting on top of primitives that already ship. It makes
disconnected revocation *honest about time* instead of silently trusting a
snapshot of unknown age.

## 8. Presenter-side proof of freshness (complementary)

The gate in §4 is **verifier-side**: the verifier judges the age of *its own*
revocation snapshot. That defends against a stale view of *revocation*, but it
says nothing about the *presenter*. A presenter can hold a perfectly valid,
unexpired credential while having been out of contact — and therefore
unaccountable — for a long time. The dual mechanism closes that half.

**Freshness token.** A relay (any node the authority has designated as a
freshness anchor) issues a short-lived, signed `FreshnessToken` to a presenter
during a contact window:

```jsonc
{
  "type": ["VerifiableCredential", "FreshnessToken"],
  "issuer": "did:web:relay.control.example",
  "validFrom": "2026-07-19T11:40:00Z",
  "validUntil": "2026-07-19T12:40:00Z",
  "credentialSubject": {
    "id": "did:web:surveyor.operator-a.example",
    "epoch": 4412,               // monotonic DTN epoch counter
    "nonce": "…"                 // binds the token to this contact, anti-replay
  }
}
```

At authorization time the verifier requires the presenter to show a
`FreshnessToken` whose `validUntil` is current **and** whose `epoch` is within a
tier-scoped window of the verifier's own last-known epoch:

```
epoch_gap = verifier_epoch − token.epoch
allow if epoch_gap ≤ max_epoch_gap[tier]     (0 for the tightest critical policy)
```

This is the symmetric statement of §4: §4 bounds *"how old is my revocation
knowledge"*; §8 bounds *"how recently has the presenter proven itself live to the
network"*. A complete disconnected authorization applies **both** — a known
revocation still denies unconditionally (§4 step 3), the verifier's snapshot must
be fresh enough for the tier (§4 step 4), **and** the presenter must carry a
recent-enough freshness token (§8).

**This is not new machinery.** A `FreshnessToken` is a `SessionVoucher`
(`vouch.heartbeat`, Specification §11) issued by a DTN relay instead of an
always-on validator, and the epoch-window decay is exactly the `trust_entropy`
model already used for heartbeat renewal. The contribution here is the *binding
to DTN epochs* and the *tiering of the acceptable gap*, not a new credential
type. Epochs (rather than wall-clock) matter precisely because a disconnected
node's clock may drift; an epoch counter advanced by relays gives an
adversary-resistant ordering that does not depend on synchronized time.

**Honest limits.** This raises the bar; it is not a liveness *guarantee*. A
presenter compromised *within* its freshness window still presents a valid token.
Shrinking the window shrinks that exposure at the cost of demanding more frequent
relay contact — the same budget/availability trade-off as §3, now on the
presenter side. Detecting a peer that goes bad *between* contacts, with no relay
reachable at all, is a different problem (peer-observation revocation) and is out
of scope for this spec.

## 9. Open questions

- **Per-action budgets vs. per-tier.** Tiers keep policy legible; some
  deployments may want a raw seconds budget per action. The tier model can carry
  that as a degenerate case (one tier per action) if demand appears.
- **Probabilistic freshness.** For very long disconnection (deep-space), a hard
  budget may be too blunt; a future revision could express a decaying trust
  weight (cf. `vouch.robotics` living-trust heartbeat) rather than a binary
  cutoff. Out of scope for this draft.
- **Aggregated proofs of absence.** Whether a verifier can accept a compact
  cryptographic proof that "no revocation exists as of time T" (rather than a
  full status list) is left for a separate proposal.
