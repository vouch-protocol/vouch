# Authority Freshness

**Status:** Draft specification (design)
**Applies to:** `vouch.authority_state`, `vouch.trust_check`, `vouch.heartbeat`
**Companion demo:** the Authority freshness section at [/demos](../website/src/app/demos/DemosClient.tsx) (`vouch.freshness`)

## 1. Problem

Trust freshness in Vouch Protocol has, until now, been a function of elapsed time. A
SessionVoucher carries an `initialTrust` and a `decayLambda`, and a verifier
computes `trust(t) = initialTrust * exp(-decayLambda * (t - issuedAt))` and
compares it to a per-action threshold (Specification 11.5). Revocation adds a
coarse second signal, but a disconnected verifier only refreshes its revocation
view on a cache interval that defaults to five minutes.

That is not enough for a high-consequence agent. Picture a treasury or trading
agent that holds a valid SessionVoucher. Its mandate is suspended for fraud one
second after the voucher was issued. The voucher's time-decay trust is still far
above threshold, and the revocation cache will not refresh for minutes. Pure
elapsed-time freshness keeps accepting that voucher and authorizes the transfer.
The gap is that a real change in authority state has no way to instantly shrink
the acceptable freshness window for the actions that matter most.

## 2. Why an epoch rather than a fresher timestamp

A timestamp tells you when a voucher was minted. It never tells you whether the
authority behind it has changed since. Those are different questions, and only
the first one has an answer written on the credential, so a verifier working
from time alone has to guess a staleness window that is short enough to be safe
and long enough to be usable. It is guessing because it has no signal for the
thing it actually cares about. A monotonic epoch carries what a clock cannot. A
new epoch is not an opinion about elapsed time, it is proof that a real
transition occurred, published and signed by the authority itself. Walk it
through a treasury agent: at 10:00:00 the agent holds a voucher minted under
epoch 7 and everything about it is valid. At 10:00:04 a fraud signal fires and
the authority republishes its state at epoch 8. At 10:00:06 the agent presents
that voucher for a transfer. It is six seconds old and its time-decay trust is
still comfortably above threshold, so on elapsed time alone the transfer would
go through. Because the verifier has seen epoch 8, it rejects a voucher minted
under epoch 7 as stale, and the window that was notionally five minutes wide
closes in the moment the authority changed. The honest limit is that this only
works once the verifier has learned about the newer epoch, so a verifier that
has not yet refreshed still holds the old view. That is exactly why the
zero-tolerance tier does not rely on a cached epoch at all and falls back to a
live M-of-N co-sign read at the moment of the action.

This framing came out of a public discussion with Sudip Chatterjee
([@aiconsulting4future](https://github.com/aiconsulting4future)), who argued
that freshness has to be a function of both elapsed time and authority state
change, with the consequence of the action setting the threshold, and who
supplied the treasury and trading scenario above where a credential stays
cryptographically valid while no longer representing current authority.

## 3. The idea

Authority Freshness treats the freshness of an action as a function of three
inputs instead of one:

```
freshness(action) = f(elapsed_time, authority_state_version, consequence)
```

- **elapsed_time** is the existing time-decay computation, unchanged.
- **authority_state_version** is a monotonic counter, `authorityEpoch`,
  published by the principal or issuer in a signed `AuthorityState` credential.
  Any authority-relevant transition (a fraud signal, a suspended mandate, an
  exposure breach, an incident) bumps the epoch and is signed with the same
  `eddsa-jcs-2022` Data Integrity path as every other Vouch Protocol credential.
- **consequence** reuses the tiers already defined for bounded-staleness
  revocation (`routine`, `sensitive`, `critical`), so a deployment carries one
  consequence vocabulary rather than two.

A SessionVoucher (and a heartbeat request) records the `authorityEpoch` it was
minted under. A verifier tracks the highest epoch it has seen for each authority,
learned from a status-list refresh or from the heartbeat channel. When an
authority-relevant transition bumps the epoch, the verifier learns the new,
higher epoch, and any voucher minted under the old one is now stale.

## 4. The collapse rule

For an action whose consequence tier requires state-freshness, a voucher whose
`authorityEpoch` is lower than the highest epoch the verifier has seen for that
authority is rejected, even when its time-decay trust still passes. That is the
window collapsing to now instead of in five minutes. The verifier returns a
clear reason code, for example `authority_epoch_stale:seen=7,voucher=5`.

Reason codes are byte-identical across every language binding, so an audit log
reads the same whichever SDK produced it. When an epoch is not available at all
the verifier still fails closed, rendering the absent side as `?`, for example
`authority_epoch_unknown:voucher=?,seen=9`. Every reason code is pinned by the
shared interop vector.

The consequence-to-policy map is:

| Tier        | Behavior                                                              |
|-------------|----------------------------------------------------------------------|
| `routine`   | Time-decay only. Authority Freshness adds nothing.                   |
| `sensitive` | The epoch-collapse rule, enforced locally.                           |
| `critical`  | The epoch-collapse rule and a live M-of-N co-sign, read at action time. |

## 5. Enforced locally vs. checked live

Being explicit about what needs a network call matters for offline verifiers:

- The `routine` and `sensitive` tiers are enforced **locally**. The epoch
  comparison is a comparison of two integers the verifier already holds. There
  is no network call at action time.
- The `critical` tier is the honest limit of a purely local check. When the
  acceptable window is near zero, a cached epoch is not good enough, because the
  authority could have changed state in the moment between the last refresh and
  this action. So the verifier does not trust any cached epoch. It requires a
  live co-sign from an M-of-N quorum (`vouch.threshold`, FROST over Ed25519),
  produced at action time and bound to the action by a nonce. The quorum has to
  be reachable and willing to sign at that instant, which is what reads the
  authority's current state at the moment of the action. The aggregated co-sign
  is a standard Ed25519 signature, so a verifier checks it with the ordinary
  verifier and needs no threshold-signing code of its own.

## 6. The AuthorityState credential

`AuthorityState` is a plain VC Data Model 2.0 credential:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://vouch-protocol.com/contexts/v1"],
  "id": "urn:uuid:...",
  "type": ["VerifiableCredential", "AuthorityState"],
  "issuer": "did:web:treasury.example.com",
  "validFrom": "2026-07-26T10:00:00Z",
  "validUntil": "2026-07-26T10:05:00Z",
  "credentialSubject": {
    "id": "did:web:treasury.example.com",
    "authorityEpoch": 5,
    "status": "active"
  }
}
```

`status` is one of `active`, `suspended`, `incident`, `exposure_breached`, or
`revoked`. `active` is the only value under which a state-freshness action may
proceed; every other value is a transition that bumps `authorityEpoch`. The
credential is signed with `eddsa-jcs-2022`, so it canonicalizes byte-identically
across the Rust core and the Python, TypeScript, and Go bindings, pinned by the
shared interop vector in `test-vectors/authority-state/`.

## 7. Using it

The gate is folded into the one composed trust check, `verify_agent_call`:

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

The default tier is `routine`, so existing callers see no change until they opt
a higher tier in.
