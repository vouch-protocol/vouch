# PAD-109: Ephemeris-Scoped Delegation Authority Bound to a Trajectory or Geometric Predicate

**Identifier:** PAD-109  
**Title:** Method for a Delegation Grant Whose Validity Is Expressed as a Trajectory or Geometric Predicate — an Orbital Arc, a Ground-Station Footprint, or a Geofence — Evaluated by the Holder Against Its Own Navigation State Rather Than a Wall-Clock Window  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Delegation / Authorization / Offline Verification / Robotics / Space Systems  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-076 (Offline Physical Delegation Lease), PAD-087 (Bounded Infrastructure Access), PAD-106 (Bounded-Staleness Revocation), PAD-108 (Channel-Geometry Proof of Presence)  

---

## 1. Abstract

A method for a delegation grant whose validity window is expressed not as a wall-
clock interval but as a *trajectory or geometric predicate* over the holder's own
navigation state: an orbital arc, a ground-station or coverage footprint, an
altitude band, or a geofenced volume. The holder — a spacecraft, a rover, a
drone, an underwater or underground vehicle — verifies the grant's signature offline
and admits an action only while its own measured state satisfies the predicate. This
ties authority to *where the vehicle physically is*, which a disconnected node can
evaluate from onboard navigation, rather than to a clock a long-disconnected node
cannot be trusted to hold accurately.

Key innovations:

- **Authority scoped by physical trajectory, not time.** The grant is valid only
  while the holder occupies a named orbital arc, footprint, altitude band, or
  geofence, evaluated against onboard navigation state.
- **Robust where clocks are not.** A geometric predicate is evaluated from a
  disconnected node's own position/velocity solution, so authority remains well-
  defined even when the node's wall-clock has drifted (the failure mode that a
  fixed-time lease suffers in long disconnection).
- **Shrink-only over both geometry and physical scope.** A sub-grant may only narrow
  the inherited geometric region and the inherited physical capability envelope,
  never widen either, so authority attenuates down a chain across regions.

---

## 2. Problem Statement

### 2.1 Time-windowed authority is fragile under clock drift

A delegation lease bounded by a wall-clock window (PAD-076) assumes the holder knows
the current time. A node out of contact for a long period may have a drifted or
reset clock, making a time window either prematurely closed or dangerously open.

### 2.2 The operationally meaningful bound is often geometric

For a spacecraft or a field robot, the natural bound on authority is frequently
*where* it is: over a given ground-station footprint, within a certified orbital
arc, inside a permitted zone, below an altitude ceiling. Encoding that as a time
window is an indirect and fragile proxy.

### 2.3 A verifier cannot re-check region membership at the edge with a server

Geofencing is commonly enforced by a connected policy service. A disconnected node
must be able to decide region membership itself, from its own navigation solution,
with only a cached issuer key.

---

## 3. Solution (The Invention)

A delegation grant carries, in place of (or alongside) a wall-clock window, a
geometric predicate describing the region of validity: an orbital-element arc, a
latitude/longitude/altitude footprint, a geofenced volume, or a coverage cone. The
holder verifies the grant's signature offline against a cached issuer key and, at
each proposed action, evaluates the predicate against its own onboard navigation
state (position and velocity from GNSS, star tracker, inertial solution, ranging, or
odometry). The action is admitted only while the state satisfies the region and the
proposed action fits the grant's physical capability envelope.

Grants nest: a sub-grant may only intersect (never enlarge) the inherited region and
may only narrow the inherited physical envelope, so a verifier confirms that every
hop attenuated over both geometry and physical scope. The geometric predicate can be
combined with the channel-geometry presence check (PAD-108), so a peer's claimed
position used in region evaluation is itself corroborated by physical measurement,
and with bounded-staleness revocation (PAD-106) so the grant can still be revoked.

---

## 4. Prior Art Differentiation

Geofencing, geo-restricted keys, and time-windowed delegation are established prior
art. This disclosure does **not** claim geofencing generally or time-windowed leases.
What is differentiated is:

- **Expressing delegated authority's validity as a trajectory/orbital/geometric
  predicate evaluated offline by the holder against its own navigation state**, as a
  first-class alternative to a wall-clock window, chosen specifically to survive
  clock drift on long-disconnected nodes.
- **Shrink-only nesting over geometry and physical envelope together**, so a multi-
  party chain attenuates across regions as well as capabilities.
- **Composition with disconnected presence and revocation checks** (PAD-108,
  PAD-106), so a self-asserted position used for region evaluation is corroborated
  and the grant remains revocable at the edge.

Prior geofenced authorization typically relies on a connected enforcement point and a
trusted device clock; it does not define an offline, holder-evaluated, trajectory-
predicate grant with shrink-only geometric nesting for delay-tolerant vehicles.

---

## 5. Technical Implementation

A reference design extends the delegation-lease credential with an optional region
predicate (orbital-element bounds, a geodetic footprint/volume, or an altitude band)
and a holder-side evaluator that tests the region against the onboard navigation
solution before admitting an action, reusing the existing offline lease verification
and shrink-only attenuation checks. Acquisition of the navigation solution is
platform-specific; the open layer is the predicate format, the attenuation rule over
regions, and the holder's accept/reject decision.

---

## 6. Claims Summary

1. A method for a delegation grant whose validity is expressed as a geometric or
   trajectory predicate over the holder's navigation state, verified offline against
   a cached issuer key and evaluated by the holder against its own position and
   velocity before admitting an action.
2. The method of claim 1 wherein the predicate is an orbital-element arc, a geodetic
   footprint or volume, an altitude band, or a coverage cone.
3. The method of claim 1 wherein an action is admitted only while the holder's state
   satisfies the region and the action fits the grant's physical capability envelope.
4. The method of claim 1 wherein a sub-grant may only intersect the inherited region
   and only narrow the inherited physical envelope, and a verifier confirms every hop
   attenuated over both.
5. The method of claim 1 combined with a physical-measurement presence check that
   corroborates the holder's position used for region evaluation, and with a
   consequence-scaled revocation-staleness gate that keeps the grant revocable at the
   disconnected edge.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
