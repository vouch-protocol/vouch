# PAD-110: Swarm-Consensus Revocation — Local Peer-Observation Quarantine of a Compromised Node Under an Honest-Majority Assumption

**Identifier:** PAD-110  
**Title:** Method by Which a Local Cluster of Attested Peers Quarantines a Compromised or Misbehaving Node Offline, by a Threshold of Evidence-Bound Distress Attestations, Under a Local Honest-Majority Assumption, With Bounded and Reversible Effect  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Revocation / Swarm Governance / Offline Verification / Byzantine Fault Tolerance  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-106 (Bounded-Staleness Revocation), PAD-107 (Presenter Proof of Freshness), PAD-034 (Composite Threshold Swarm Consensus), PAD-022 (Agent Population Governance), PAD-032 (Cryptographic Mortality Protocol), PAD-099/PAD-100 (Swarm Membership and Collective-Action Attestation)  

---

## 1. Abstract

A method by which a local cluster of mutually-attested peer nodes can quarantine a
compromised or misbehaving member **without any path to a home authority**. When a
node begins acting maliciously — replaying, exceeding its physical envelope,
emitting inconsistent state — nearby nodes that directly observe the misbehavior
each sign a distress attestation bound to the observed evidence. When a threshold of
distinct, attested observers has signed distress against the same target within a
window, any node holding those attestations locally treats the target as quarantined:
it refuses to cooperate with, hand authority to, or accept telemetry from the target.
Because a disconnected node cannot receive a traditional revocation list, this closes
the gap in which a still-valid, unexpired credential lets a compromised peer keep
exploiting the swarm until the next contact with Earth.

The method operates under an explicit **local honest-majority assumption** and is
designed so its worst-case failure (a colluding minority, or a griefing attempt) is
bounded and reversible rather than catastrophic.

Key innovations:

- **Offline, peer-observation-driven quarantine.** Revocation authority is exercised
  locally by the cluster from direct observation, filling the case that neither a
  central revocation list nor bounded-staleness snapshots (PAD-106) can cover:
  a node that turns malicious *between* contacts with no relay reachable.
- **Evidence-bound threshold distress.** Each distress attestation references the
  concrete evidence observed (a signed perception frame, a telemetry inconsistency, an
  out-of-envelope actuation), and quarantine takes effect only at a threshold of
  distinct attested observers, so a single node cannot eject a peer.
- **Bounded, reversible, scope-limited effect.** Quarantine is local to the cluster,
  time-limited, and reversible: it is not a permanent whole-DID kill (that still
  requires the real authority, PAD-032), so an erroneously quarantined node is
  restored on appeal or expiry, containing the damage from collusion or error.

---

## 2. Problem Statement

### 2.1 A disconnected swarm cannot receive a revocation list

If a node is compromised while out of contact, it retains valid, unexpired
credentials. A central revocation list cannot reach the cluster, and bounded-
staleness revocation (PAD-106) only limits how old a *carried* snapshot may be; it
cannot generate a *new* revocation for a node that went bad after the last sync.

### 2.2 The peers are the only witnesses

At the edge, the only parties positioned to detect the misbehavior in time are the
neighboring nodes that directly observe it. There must be a way for their local
observation to have authority, without waiting for a distant server.

### 2.3 Peer-driven revocation is dangerous if naive

A naive "any node can revoke any node" scheme is a denial-of-service and collusion
weapon: a compromised or malicious minority could quarantine honest nodes. The
mechanism must resist Sybil inflation, bound the effect of collusion, and be
reversible when it is wrong.

---

## 3. Solution (The Invention)

**Attested membership.** Only nodes admitted to the swarm (PAD-099), each carrying a
hardware-rooted identity (so an attacker cannot cheaply mint many voting identities),
are eligible to sign distress. This constrains Sybil inflation to the cost of
compromising real, attested hardware.

**Evidence-bound distress attestation.** An observer that detects misbehavior signs a
`DistressAttestation` naming the target node, a reason code, and a reference to the
observed evidence (a signed perception-frame hash, an out-of-envelope actuation, a
telemetry inconsistency), within a time window and against a monotonic epoch.

**Threshold quarantine.** A node treats the target as quarantined only when it holds
distress attestations from at least a threshold M of the N attested members present,
signed by distinct members within the window. This is the **local honest-majority
assumption**: the mechanism is sound as long as fewer than the threshold of the
locally present, attested members are malicious. Below threshold, nothing happens.

**Bounded and reversible effect.** Quarantine is:

- **Local** — it governs how this cluster cooperates with the target; it is not a
  global whole-DID revocation, which remains the authority's prerogative (PAD-032).
- **Time-limited** — it expires and must be renewed by continued threshold distress,
  so a transient or mistaken quarantine self-heals.
- **Appealable** — the target, or any node, can carry the distress set and its own
  counter-evidence to an authority at the next contact, which adjudicates and can
  overturn or escalate to a real revocation.

**Anti-griefing.** Distress is rate-limited per signer and must carry evidence;
unsupported or excessive distress is itself an observable misbehavior that counts
against the signer. The threshold, window, and quarantine lifetime are deployment
policy.

The result is a decentralized, offline, evidence-based quarantine whose soundness
rests on a stated honest-majority-of-present-members assumption, and whose failure
modes (collusion, error, griefing) are bounded and reversible by construction.

---

## 4. Prior Art Differentiation

Threshold signatures, BFT consensus, reputation-based ejection, and this project's own
swarm consensus (PAD-034), population governance (PAD-022), and mortality protocol
(PAD-032) are prior art. This disclosure does **not** claim threshold signing or BFT
in general. What is differentiated is:

- **Peer-observation-driven quarantine executed entirely offline**, filling the gap of
  a node compromised between contacts with no authority reachable — distinct from
  PAD-034 (aggregating a collective *decision*), PAD-022 (population *bounds*), and
  PAD-032 (a node terminating *its own* identity).
- **Evidence-bound distress** referencing concrete observed artifacts, so a vote is a
  claim about witnessed behavior, not an opinion.
- **A bounded, reversible, local quarantine under an explicit honest-majority
  assumption**, rather than an irreversible global revocation — so collusion or error
  degrades to a temporary, appealable, cluster-local effect instead of a permanent
  kill.

Reputation-based peer ejection in distributed systems typically assumes connectivity
to a shared store and produces a soft score; it does not define an offline,
hardware-attested, evidence-bound, threshold quarantine with an explicit honest-
majority bound and authority-adjudicated reversal for physical edge swarms.

---

## 5. Technical Implementation

A reference design defines a `DistressAttestation` credential (target, reason,
evidence reference, window, epoch, signer), a quarantine evaluator that admits a
quarantine only on M-of-N distinct attested signers within the window, and a
quarantine record that is time-limited and carries the distress set for later
adjudication. Membership and hardware attestation reuse PAD-099 and PAD-064; whole-DID
escalation reuses PAD-032. Detection of misbehavior (the sensing that produces the
evidence) is platform-specific; the open layer is the attestation format, the
threshold rule, and the bounded-reversible quarantine semantics.

---

## 6. Claims Summary

1. A method by which a cluster of mutually-attested peer nodes quarantines a target
   node offline when at least a threshold of distinct attested members have each signed
   an evidence-bound distress attestation against the target within a window, with no
   contact to a central authority.
2. The method of claim 1 wherein eligibility to sign distress is limited to members
   admitted with a hardware-rooted identity, constraining Sybil inflation.
3. The method of claim 1 wherein each distress attestation references concrete observed
   evidence of the target's misbehavior.
4. The method of claim 1 wherein the quarantine is local to the cluster, time-limited,
   and reversible, and is not a permanent whole-identity revocation, so that collusion
   or error produces a bounded, appealable effect.
5. The method of claim 4 wherein the distress set is carried to an authority at the
   next contact, which adjudicates and may overturn the quarantine or escalate it to a
   whole-identity revocation.
6. The method of claim 1 wherein the soundness of the quarantine is stated to hold
   under a local honest-majority assumption over the attested members present, and
   distress signing is rate-limited and itself accountable to deter griefing.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
