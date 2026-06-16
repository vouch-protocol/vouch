# PAD-066: Physical Capability Scope as Cryptographically Enforceable Attenuation

**Identifier:** PAD-066  
**Title:** Method for Expressing and Enforcing a Robot's Physical Action Limits (Force, Speed, Proximity-to-Human Speed, Zones, Shift Windows) as a Cryptographically Signed, Monotonically Attenuating Capability Scope  
**Publication Date:** June 14, 2026  
**Prior Art Effective Date:** June 14, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Physical Safety / Capability Attenuation / Verifiable Credentials / AI Safety  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-021 (Inverse Capability Protocol), PAD-022 (Swarm Limits Protocol), PAD-064 (Hardware-Rooted Robot Identity), PAD-068 (Kill-Switch Credential)  

---

## 1. Abstract

A method for extending the capability-attenuation model of delegated authority
from the digital domain (action, target, resource, time, rate, policy) into the
physical domain, by expressing a robot's permitted physical envelope as a signed
capability scope: maximum force, maximum speed, a separate lower maximum speed
when near humans, the set of allowed zones, and the permitted shift windows. The
scope is carried in a Verifiable Credential and checked before each actuation, and
when authority is delegated the child scope must attenuate (narrow, never broaden)
its parent on every physical dimension.

Key innovations:

- **Physical dimensions as first-class capability attenuation.** Force, speed,
  near-human speed, zones, and shift windows join the existing attenuation
  dimensions, so a physical envelope can be delegated and narrowed with the same
  cryptographic rule as a digital capability.
- **Proximity-aware speed cap.** A distinct, lower speed limit applies when the
  robot is near a human, enforced as part of the signed scope.
- **Pre-actuation enforcement.** A proposed physical action (its force, speed,
  near-human flag, zone, and time) is checked against the scope and refused before
  the actuator moves.
- **Monotone narrowing on delegation.** A delegated scope is valid only if it is
  not broader than its parent on any physical dimension (caps may only shrink,
  allowed zones may only be a subset, shift windows must fit inside parent
  windows).

---

## 2. Problem Statement

### 2.1 Physical limits are not part of any verifiable authority model

A robot's force and speed limits live in firmware or controller configuration,
not in a verifiable, delegable credential. There is no cryptographic way to grant
a robot a narrower physical envelope for a particular task and prove it.

### 2.2 Delegation does not constrain the physical world

When a robot's authority is delegated (to a sub-task, a teleoperator, a cooperating
robot), there is no mechanism ensuring the delegate's physical envelope is no
broader than the delegator's.

### 2.3 Near-human operation needs a distinct, enforceable limit

Safety standards require slower operation near people, but that limit is not
expressed as a signed, verifiable, enforceable capability that travels with the
robot's authority.

---

## 3. Solution (The Invention)

A PhysicalCapabilityScope credential carries a `physicalScope` object:

```
{ "maxForceN", "maxSpeedMps", "maxSpeedNearHumansMps",
  "allowedZones": [...], "shiftWindows": [{"start","end"}, ...] }
```

signed (eddsa-jcs-2022). Before actuating, the controller evaluates a proposed
physical action (force, speed, a near-human flag, a zone, a time) against the
scope: the force must not exceed `maxForceN`; the speed must not exceed
`maxSpeedMps`, or `maxSpeedNearHumansMps` when the near-human flag is set; the zone
must be in `allowedZones`; the time must fall in a shift window. Any violation
refuses the action.

When authority is delegated, the child scope is accepted only if it attenuates the
parent: each numeric cap is less than or equal to the parent's, the allowed zones
are a subset, and each child shift window fits inside some parent window. This is
the same monotone-narrowing discipline as digital capability attenuation, extended
to physical dimensions.

---

## 4. Prior Art Differentiation

- **Safety-rated controllers / speed-and-separation monitoring (ISO/TS 15066).**
  Define physical safety behavior but not a signed, delegable, attenuating
  capability credential that expresses and enforces the envelope as verifiable
  authority.
- **Object-capability and macaroon attenuation.** Attenuate digital authority; do
  not model physical force/speed/zone/shift dimensions.
- **PAD-021 (Inverse Capability) / PAD-022 (Swarm Limits).** Govern autonomy
  budgets and swarm limits; the present method adds the physical-envelope
  dimensions to the cryptographic attenuation model and the pre-actuation check.

---

## 5. Technical Implementation

A reference implementation provides `build_physical_scope_credential`,
`check_physical_action` (pre-actuation enforcement), and `attenuates`
(delegation-narrowing check), reusing the eddsa-jcs-2022 credential format. The
near-human speed cap is selected automatically when the action is flagged
near-human.

---

## 6. Claims Summary

1. A method for expressing a robot's permitted physical envelope (maximum force,
   maximum speed, a lower maximum speed near humans, allowed zones, and shift
   windows) as a signed capability scope in a Verifiable Credential.
2. The method of claim 1 wherein a proposed physical action is checked against the
   scope and refused before actuation.
3. The method of claim 1 wherein a lower speed limit is enforced when the robot is
   near a human.
4. The method of claim 1 wherein a delegated scope is valid only if it does not
   broaden the parent on any physical dimension, caps may only shrink, allowed
   zones may only be a subset, and shift windows must fit inside parent windows.
5. The method of claim 1 wherein the physical dimensions are added to a digital
   capability-attenuation model so physical and digital authority attenuate by the
   same rule.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the robotics community.
