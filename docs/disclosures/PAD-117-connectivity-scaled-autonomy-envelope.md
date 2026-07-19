# PAD-117: Connectivity-Scaled Autonomy Envelope — Narrowing Authority as a Function of Time Since Last Trusted Contact

**Identifier:** PAD-117  
**Title:** Method by Which a Node's Permitted Authority Envelope Automatically Narrows as Its Time Since Last Trusted Contact Increases, So Autonomy Contracts With Staleness and Is Restored on Re-Contact  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Authorization / Autonomy Governance / Delay-Tolerant Networking / Robotics  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-106 (Bounded-Staleness Revocation), PAD-107 (Presenter Proof of Freshness), PAD-076 (Offline Delegation Lease), PAD-021 (Inverse Capability Protocol)  

---

## 1. Abstract

Bounded-staleness revocation (PAD-106) scales the acceptability of a *revocation view*
to the consequence of an action. This method generalizes that principle from revocation
to *all authority*: a node's permitted authority envelope automatically **narrows as its
time since last trusted contact grows**, so a node that has been out of contact longer
may do less. A freshly-synced node operates at its full granted envelope; as staleness
increases it steps down through progressively tighter envelopes (lower force/speed,
fewer zones, only reversible actions), and re-contact restores the envelope. Autonomy
becomes a decaying function of connectivity, computed offline by the node from its own
last-contact epoch.

Key innovations:

- **Authority as a function of staleness, not a fixed grant.** The permitted envelope
  is recomputed from time-since-contact, so trust that cannot be refreshed
  automatically shrinks rather than persisting at full strength.
- **Graceful step-down and automatic restoration.** The node steps through defined
  tighter envelopes as staleness crosses thresholds, and steps back up on re-contact,
  with no operator intervention.
- **Computed offline from an authenticated last-contact marker.** The node needs only
  its last trusted-contact epoch and a signed decay schedule, so it enforces its own
  contraction with no live authority.

---

## 2. Problem Statement

### 2.1 A static grant does not reflect growing uncertainty

A node authorized to a fixed envelope keeps that full envelope no matter how long it has
been since anyone could correct, update, or revoke it. Risk grows with disconnection
while permitted authority stays flat.

### 2.2 Binary cutoffs are too blunt

Simply expiring all authority at a deadline forces a node from full capability to none,
which is operationally unacceptable for a vehicle that must still act safely while out of
contact.

### 2.3 The contraction must be self-enforcing offline

There is no live authority at the edge to reduce a node's powers, so the node must
compute and enforce its own reduced envelope.

---

## 3. Solution (The Invention)

The authority issues, with the node's grant, a signed decay schedule: a sequence of
progressively tighter authority envelopes keyed to staleness thresholds (time since last
trusted contact, measured in monotonic epochs, PAD-107). The node marks each trusted
contact and, at every proposed action, selects the envelope corresponding to its current
staleness and admits the action only if it fits that (narrowed) envelope. As staleness
crosses each threshold the envelope steps down — lower force and speed caps, fewer
permitted zones, and eventually only reversible or safe-hold actions. On re-contact the
staleness resets and the full envelope is restored. Each envelope in the schedule is a
valid attenuation of the one above it, so the step-down never widens authority, and the
schedule composes with the offline delegation lease (PAD-076) and consequence-scaled
revocation (PAD-106): the same staleness that tightens revocation acceptance also
tightens the action envelope.

---

## 4. Prior Art Differentiation

Fail-safe defaults, dead-reckoning limits, lease expiry, and graduated autonomy
(including this project's inverse-capability scaling, PAD-021) are prior art. This
disclosure does **not** claim graduated autonomy generally. What is differentiated is:

- **Making the permitted authority envelope an explicit, signed, decaying function of
  time-since-trusted-contact**, computed offline, rather than a fixed grant or a binary
  expiry.
- **A stepped, attenuating schedule with automatic restoration on re-contact**, so
  autonomy contracts and recovers smoothly with connectivity.
- **Unifying the staleness signal across revocation and authority**, so one
  time-since-contact measure drives both the PAD-106 revocation gate and the action
  envelope.

Inverse-capability scaling (PAD-021) scales capability to *earned trust/behavior*; this
scales the *permitted envelope to connectivity staleness* and enforces it offline.

---

## 5. Technical Implementation

A reference design carries a signed decay schedule (staleness thresholds mapped to
attenuating authority envelopes) with the node's grant, plus a node-side selector that
picks the current envelope from its last-contact epoch and admits actions only within
it. Envelopes reuse the physical-capability-scope format and its attenuation check;
staleness reuses PAD-107 epochs. The open layer is the decay-schedule format and the
offline selector.

---

## 6. Claims Summary

1. A method by which a node's permitted authority envelope is selected as a function of
   its time since last trusted contact and narrows as that time increases, computed
   offline by the node.
2. The method of claim 1 wherein the envelope steps through a signed schedule of
   progressively tighter, attenuating envelopes as staleness crosses thresholds, and is
   restored on re-contact.
3. The method of claim 1 wherein each envelope in the schedule is a valid attenuation of
   the one above it, so contraction never widens authority.
4. The method of claim 1 wherein staleness is measured in a monotonic network-epoch
   counter, so the contraction is well-defined without a trusted wall-clock.
5. The method of claim 1 wherein the same staleness measure drives both a
   consequence-scaled revocation gate and the action envelope.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
