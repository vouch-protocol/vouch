# Disconnected-Edge Trust (including space)

Vouch makes trust decisions locally, with no live connection to a home server.
That is what lets it work at the disconnected edge: in orbit, on the lunar
surface, deep underground, under water, or anywhere a round trip to an
Earth-based registry is impossible or too slow to be part of a real-time
decision. Space is the most demanding instance of this; the same primitives
serve any disconnected robot, so a satellite constellation and an underground
mine use one mechanism.

## The general class: DDIL environments

Space is the lighthouse example, not the whole market. The unifying category is
what defense and comms call **DDIL — Denied, Degraded, Intermittent, or Limited**
connectivity. Every one of these has the same shape: pre-distribute trust anchors
during a contact window, verify offline, and bound revocation staleness by the
consequence of the action.

| Domain | Example edge nodes | Why the round trip fails |
| --- | --- | --- |
| Orbital / cislunar | satellites, rovers, probes, cislunar relays | light-time and line-of-sight windows |
| Subsea | ROVs, AUVs, ocean gliders, pipeline crawlers | RF does not penetrate water; acoustic links are kbps |
| Subterranean | mining, tunnel-boring, cave rescue, deep wells | rock blocks all RF |
| Polar / remote wilderness | Antarctic stations, wildfire crews, remote sensors | no infrastructure, satellite-only, weather outages |
| Tactical / defense edge | dismounted units, BLOS UAV swarms, GPS-denied ops | connectivity actively denied by an adversary |
| Aviation | transoceanic flights, high-altitude platforms, BVLOS drones | no continuous ground link |
| Maritime | vessels mid-ocean, autonomous shipping, offshore rigs | intermittent, expensive satcom |
| Grid / industrial | substations, pipeline SCADA, field agriculture robots | air-gapped by design or no cell coverage |

The same Vouch code serves all of these; only the physical link and the contact
cadence change.

## Why offline verification is possible

A Vouch credential is a self-contained `eddsa-jcs-2022` Verifiable Credential.
Verifying it needs the issuer's public key, not a live network call. Two nodes
that hold each other's trust anchors can therefore authenticate and exchange
authority with no connection home.

**One honest caveat:** offline trust is *enabled* by distributing trust anchors
during a contact window, not by removing that step. Vouch makes the offline
exchange sound and makes staleness explicit; it does not pretend a node can trust
a peer it has never had any prior root for. "Spontaneous discovery with no prior
configuration" is a myth — the trust anchors are the configuration, and they must
be synced at some point.

## What runs offline today

- **Offline mutual authentication.** Two nodes in different trust domains run the
  three-message robot-to-robot handshake (HELLO, ACCEPT, CONFIRM) and agree a
  bounded-trust session whose scope is the intersection of what each side offers,
  never the union. No central broker. (`vouch.robotics.handshake`)
- **Authority that travels with the craft.** A short-lived, scope-bounded
  `DelegationLeaseCredential` and a scannable passport let a probe or rover prove
  what it is authorized to do and act on it while out of contact. Leases nest and
  each sub-grant can only narrow the one above it. (`vouch.robotics.lease`,
  `vouch.robotics.passport`)
- **Provenance at the moment of capture.** Signed perception provenance binds each
  sensor frame's hash to the node's key and hash-links them, so a node can prove
  what its sensors saw and a substituted frame is detectable.
  (`vouch.robotics.perception`)

## The hard part: revocation that is honest about time

Authentication, delegation, and provenance verify offline against pre-distributed
anchors. Revocation is different: it is a *freshness* problem, not a *signature*
problem. A disconnected verifier holds a status-list snapshot synced at last
contact, so a credential revoked after that sync still looks valid to it.
`verify_status` honestly answers only "revoked per the snapshot I hold."

Vouch closes this with **bounded-staleness revocation**: the verifier weighs the
age of its last-synced snapshot against the consequence of the action, and fails
closed when the view is too old.

```python
from vouch.status_list import evaluate_freshness, CONSEQUENCE_CRITICAL

# snapshot = the BitstringStatusListCredential synced at last contact (or None)
verdict = evaluate_freshness(tier=CONSEQUENCE_CRITICAL, snapshot=snapshot, now=now)
if verdict.allow and not revoked_bit:
    ...  # authorize
```

Consequence tiers and their default staleness budgets (overridable per
deployment):

| Tier        | Example                          | Default budget |
| ----------- | -------------------------------- | -------------- |
| `routine`   | a telemetry beacon               | 30 days        |
| `sensitive` | accept a data-payload handoff    | 24 hours       |
| `critical`  | execute a physical maneuver      | 1 hour         |

The gate fails closed on every ambiguous state: an unknown tier is treated as
critical; a snapshot past its own `validUntil` or with a malformed `validFrom` is
treated as absent; and an absent snapshot allows only routine actions. A *known*
revocation always denies, independent of freshness.

A complementary **presenter-side proof of freshness** is specified as well: a
relay issues a short-lived `FreshnessToken` (a SessionVoucher bound to a monotonic
DTN epoch), and the verifier requires the presenter to show one within a
tier-scoped epoch window. Epochs rather than wall-clock resist clock drift on
disconnected nodes.

## Where this is defined

- Spec: `docs/dtn-bounded-staleness-revocation.md`
- Runnable example: `examples/disconnected_exchange_demo.py` (two nodes complete
  the full offline exchange over a simulated high-latency link, with the socket
  layer disabled to prove nothing phones home)
- API: `vouch.status_list.evaluate_freshness`, `FreshnessVerdict`,
  `DEFAULT_STALENESS_BUDGETS`, `CONSEQUENCE_ROUTINE` / `_SENSITIVE` / `_CRITICAL`
- Robotics primitives: `vouch.robotics` (handshake, lease, passport, perception)

## Shipped disconnected-edge modules (disclosed PAD-106 to PAD-124)

The full portfolio is implemented as open-layer formats and verifier predicates
(hardware acquisition — ranging, TPM, orbital propagators — is the caller's concern):

- `vouch.status_list.evaluate_freshness` — consequence-tiered revocation staleness (106)
- `vouch.robotics.freshness` — presenter freshness token + graded trust decay (107, 119)
- `vouch.robotics.presence` — channel-geometry (range/Doppler) proof of presence (108)
- `vouch.robotics.geoscope` — ephemeris/geometric-scoped authority (109)
- `vouch.robotics.quorum_trust` — swarm quarantine, quorum-of-orbits, key continuity (110, 111, 116)
- `vouch.robotics.dtn_revocation` — dead-man revocation, carried validity witness (112, 120)
- `vouch.robotics.localization` — proof-of-location, kinematic plausibility, beam presence (113, 114, 121)
- `vouch.robotics.edge_trust` — time-quality, autonomy envelope, integrity-risk narrowing (115, 117, 118)
- `vouch.robotics.perception_consensus` — Byzantine sensor agreement, mesh standing (122, 123)
- `vouch.robotics.bundle` — DTN Bundle Protocol custody binding (124)
