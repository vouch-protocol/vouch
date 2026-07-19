# PAD-114: Kinematic-Plausibility Checking of Position and Velocity Claims Against Physical Motion Bounds

**Identifier:** PAD-114  
**Title:** Method by Which a Verifier Rejects a Node's Position or Velocity Claim That Is Physically Impossible Given the Node's Prior Attested State and Its Bounded Motion Envelope, Including Orbital-Mechanics and Maximum-Maneuver Constraints  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Anti-Spoofing / Proof of Location / Offline Verification / Space Systems  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-108 (Channel-Geometry Proof of Presence), PAD-113 (Distributed Proof of Location), PAD-109 (Ephemeris-Scoped Authority)  

---

## 1. Abstract

A method by which a verifier rejects a node's claimed position or velocity when it is
physically unreachable from the node's most recent attested state within the elapsed
time, given a declared motion envelope — a maximum speed and acceleration for a surface
or aerial vehicle, or orbital-mechanics propagation bounds and a maximum maneuver
(delta-v) budget for a spacecraft. A claim that would require the node to have
teleported, exceeded its thrust budget, or violated orbital dynamics is refused before
it is trusted, providing a physics-grounded anti-spoofing filter that needs no live
authority and complements measurement-based presence and location proofs.

Key innovations:

- **Physics as an admissibility predicate on identity claims.** A position/velocity
  claim is admitted only if it is kinematically reachable from the last attested
  state, turning the laws of motion into a spoofing filter.
- **Domain-specific envelopes, including orbital mechanics.** For spacecraft the
  reachable set is bounded by propagating the prior orbit and adding a maximum maneuver
  budget; for surface/aerial nodes it is bounded by speed and acceleration limits.
- **Offline and composable.** The check uses only the node's own prior attested state
  and a declared envelope, and strengthens presence (PAD-108) and proof-of-location
  (PAD-113) by discarding physically impossible claims up front.

---

## 2. Problem Statement

### 2.1 Measurement checks still admit physically impossible histories

Single-observer geometry (PAD-108) and even triangulation (PAD-113) validate a claim at
one instant. An attacker presenting a sequence of individually-plausible claims can
still describe an impossible trajectory (a node appearing far away moments after being
measured close).

### 2.2 The reachable set is knowable

For a vehicle with a bounded motion envelope, the set of positions reachable in a given
time from a known prior state is computable. Any claim outside it is provably false,
independent of measurement.

### 2.3 Disconnected verifiers cannot call a tracking service

There is no live space-surveillance or tracking service at the edge to sanity-check a
claim, so the plausibility test must be self-contained.

---

## 3. Solution (The Invention)

Each node's attested state carries a position, a velocity, an epoch, and a declared
motion envelope. When the node later presents a new position/velocity claim (in a
handshake, a presence attestation, or a proof-of-location), the verifier computes the
reachable set from the prior attested state over the elapsed interval:

- **Surface/aerial:** a ball of radius bounded by maximum speed and acceleration.
- **Orbital:** the propagated orbit from the prior state, expanded by a maximum
  maneuver (delta-v) budget over the interval.

The claim is admitted only if it lies within the reachable set (within measurement
tolerance). A claim outside the set is rejected as kinematically impossible. The check
consumes only the node's own signed prior state and its declared envelope, so it runs
offline, and it is layered before measurement-based checks so that impossible claims
are discarded without spending measurement effort. The declared envelope is itself part
of the node's signed identity, so a node cannot silently widen its own envelope to
excuse an impossible jump.

---

## 4. Prior Art Differentiation

Kalman filtering, track gating, and anomaly detection in tracking systems use motion
models to reject implausible measurements as prior art. This disclosure does **not**
claim motion models or gating in general. What is differentiated is:

- **Applying a kinematic-reachability predicate as an admissibility test on
  identity/location claims bound to a decentralized identity**, evaluated offline by a
  verifier from the node's own signed prior state.
- **Binding the motion envelope (including an orbital delta-v budget) into the node's
  signed identity**, so the reachable set is authenticated and cannot be widened to
  excuse a spoofed jump.
- **Composition with cryptographic presence and proof-of-location** as a
  physics-grounded pre-filter, rather than a tracking-system internal.

Tracking gates operate inside a connected sensor-fusion system on raw measurements; they
do not gate signed decentralized-identity claims against an authenticated per-node
motion envelope evaluated by a disconnected verifier.

---

## 5. Technical Implementation

A reference implementation ships in `vouch.robotics.orbital`
(`propagate_two_body` via the universal-variable Kepler solver, and
`reachable_two_body`) and is wired into `vouch.robotics.localization.kinematically_reachable`
via a `{"model": "two-body", "maxDeltaVMps": …, "muM3S2": …}` envelope: the coasting
orbit is propagated precisely and the reachable set is a delta-v-budget ball around
the propagated position. Surface/aerial speed/acceleration envelopes and a
dependency-free delta-v ball remain for non-orbital nodes. The open layer is the
envelope binding and the reachability predicate, composing with PAD-108 and PAD-113.

---

## 6. Claims Summary

1. A method by which a verifier admits a node's position or velocity claim only if it is
   reachable from the node's most recent attested state within the elapsed time given a
   declared motion envelope, and rejects it otherwise.
2. The method of claim 1 wherein, for a spacecraft, the reachable set is computed by
   propagating the prior orbit and adding a maximum maneuver budget.
3. The method of claim 1 wherein the motion envelope is bound into the node's signed
   identity so it cannot be widened to excuse an impossible claim.
4. The method of claim 1 evaluated entirely offline from the node's own signed prior
   state, with no live tracking or surveillance service.
5. The method of claim 1 applied as a pre-filter before cryptographic presence or
   proof-of-location checks.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
