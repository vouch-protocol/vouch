# PAD-106: DTN-Aware Bounded-Staleness Revocation for Disconnected Verifiers

**Identifier:** PAD-106  
**Title:** Method for Authorizing an Action Against a Locally-Held Revocation Snapshot of Unknown Age by Binding the Acceptable Staleness of the Snapshot to the Consequence Tier of the Action, With Fail-Closed Resolution of Every Ambiguous State  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Revocation / Offline Verification / Delay-Tolerant Networking / Robotics  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-076 (Offline Physical Delegation Lease), PAD-070 (Offline Robot Passport), PAD-087 (Bounded Infrastructure Access), PAD-016 (Heartbeat Protocol), PAD-039 (Deterministic Multi-Party Trust State)  

---

## 1. Abstract

A method for making a revocation decision at a verifier that cannot reach a live
revocation authority. Such a verifier — a spacecraft, a subsea vehicle, an
underground robot, a tactical edge node — holds only a status-list *snapshot*
synced at last contact, so a credential revoked after that sync still appears
valid. This disclosure treats revocation at the disconnected edge as a *freshness*
problem rather than a *signature* problem, and resolves it by binding the maximum
acceptable age of the snapshot to the *consequence* of the action being
authorized, failing closed on every ambiguous state.

Key innovations:

- **Consequence-tiered staleness budgets.** Each action is classified into a
  consequence tier, and each tier carries a maximum acceptable snapshot age. A
  low-consequence action tolerates a stale revocation view; a high-consequence,
  irreversible action does not.
- **Freshness measured against the snapshot's assertion time.** Staleness is
  computed against the snapshot's `validFrom` (when the revocation knowledge was
  current), not the credential's own validity, because revocation freshness is the
  security-relevant quantity.
- **Fail-closed resolution of ambiguity.** A missing snapshot, an expired snapshot,
  a malformed freshness anchor, an unknown consequence tier, or an untrusted clock
  all resolve to denial for any action above the lowest tier. A known revocation
  denies unconditionally, independent of freshness.

---

## 2. Problem Statement

### 2.1 Disconnected verifiers cannot fetch a current revocation list

Standard credential-status mechanisms (CRLs, OCSP, status-list credentials) assume
the verifier can retrieve the current status at decision time. A node in orbit,
underground, or under water cannot. It holds a snapshot from its last contact
window, and that snapshot silently ages.

### 2.2 A stale "not revoked" is treated as authoritative

A verifier that looks up a credential's status bit in an old snapshot gets an
honest answer *for that snapshot* — but "not revoked as of three weeks ago" is
treated as "not revoked now." Nothing in the standard mechanism expresses how old
a revocation view may be before it should no longer be trusted.

### 2.3 Freshness requirements are not uniform

The tolerance for a stale revocation view depends entirely on what is being
authorized. Accepting a stale view to emit a telemetry beacon is reasonable;
accepting the same stale view to execute an irreversible physical maneuver is not.
A single fixed validity window cannot express this.

---

## 3. Solution (The Invention)

The verifier classifies each action into a consequence tier (for example routine,
sensitive, critical), and each tier carries a configurable maximum acceptable
snapshot age (a staleness budget). At authorization time the verifier:

1. Verifies the credential's proof and that the action fits scope (existing).
2. Verifies the snapshot's own Data Integrity proof and that it is within its own
   `validUntil` (existing); an unusable snapshot is treated as absent.
3. Looks up the revocation bit in the snapshot; a set bit denies unconditionally
   (existing).
4. **Computes staleness = now − snapshot.validFrom and compares it to the tier's
   budget (new).** Within budget authorizes; over budget denies (fail-closed); an
   absent snapshot authorizes only the lowest tier and denies everything above it.

The consequence tier of an action may be carried by the granting credential (so the
issuer, not the verifier, decides how consequential an action is) or supplied by
verifier policy, defaulting an unclassified action to the highest tier. An unknown
tier is coerced to the highest tier. A verifier without a trusted clock cannot
compute staleness and therefore fails closed above the lowest tier.

A reference implementation exposes a single verifier-side function that returns an
allow/deny verdict with the tier, the computed staleness, the applied budget, and a
human-readable reason for an audit log, composing on top of the existing offline
verification and status-list primitives without modifying them.

---

## 4. Prior Art Differentiation

Credential revocation, status lists, and fixed freshness windows (OCSP
`nextUpdate`, CRL `nextUpdate`, short-lived credentials) are established prior art.
This disclosure does **not** claim those. What is differentiated is:

- **Consequence-bound staleness, not a fixed window.** The acceptable age of the
  revocation view is a function of the physical or operational consequence of the
  specific action, not a single publisher-set expiry applied uniformly.
- **A verifier-side freshness gate for disconnected operation.** The decision is
  made locally against a carried snapshot of known assertion time, with no live
  authority, specifically for delay-tolerant and denied-connectivity settings.
- **Fail-closed by construction.** Every ambiguous state — absent, expired,
  malformed, unknown tier, untrusted clock — resolves to denial for consequential
  actions, so "unable to check recently enough" never reads as "authorized."

Fixed-lifetime credentials and OCSP stapling shorten the exposure window but do not
scale that window to the action's consequence and do not define a fail-closed
disconnected decision procedure over a carried snapshot of asserted age.

---

## 5. Technical Implementation

A reference implementation provides a verifier-side evaluation over a fetched-at-
last-contact status-list credential, using the snapshot's `validFrom` as the
freshness anchor and a configurable per-tier budget table (with sane defaults). It
returns an immutable verdict object. Two optional, canonicalization-safe wire
fields are defined: a per-action consequence map carried on a delegation credential,
and an advisory expected-resync hint carried on the status-list credential. Neither
changes the verification outcome for an implementation unaware of them.

---

## 6. Claims Summary

1. A method for a disconnected verifier to authorize an action against a locally-
   held revocation snapshot by classifying the action into a consequence tier and
   admitting the action only if the age of the snapshot, measured against the
   snapshot's asserted currency time, is within a maximum acceptable age configured
   for that tier.
2. The method of claim 1 wherein a set revocation status for the credential denies
   the action unconditionally, independent of the snapshot's age.
3. The method of claim 1 wherein an absent, expired, or malformed snapshot, an
   unrecognized consequence tier, or an untrusted verifier clock resolves to denial
   for any action above the lowest consequence tier.
4. The method of claim 1 wherein the consequence tier of an action is carried by the
   credential that grants the action, and an unclassified action defaults to the
   highest consequence tier.
5. The method of claim 1 wherein the per-tier maximum acceptable ages are
   configurable per deployment, and the evaluation composes over existing offline
   credential-verification and status-list primitives without modifying them.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
