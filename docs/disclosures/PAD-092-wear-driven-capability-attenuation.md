# PAD-092: Wear-Driven Automatic Attenuation of a Robot's Physical Capability Scope

**Identifier:** PAD-092  
**Title:** Method for Deterministically Narrowing a Robot's Physical Capability Scope From Its Attested Wear Level So the Derated Scope Remains a Valid Attenuation of the Original  
**Publication Date:** July 5, 2026  
**Prior Art Effective Date:** July 5, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Safety / Capability Control  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-066 (Physical Capability Scope), PAD-091 (Robot Wear and Degradation Attestation)  

---

## 1. Abstract

A method for automatically tightening a robot's physical limits as it wears. From a
robot's attested wear level, a deterministic rule derives a physical capability scope
whose numeric caps, such as maximum force and speed, are scaled down in proportion to
the wear, while the allowed zones and shift windows are carried through unchanged. The
derived scope is, by construction, a valid attenuation of the original scope, never
broader on any dimension, so the same attenuation check the rest of the system uses to
accept a delegated scope accepts the derated one. A worn robot therefore operates
inside a tighter, verifiable envelope than the static limit it shipped with.

Key innovations:

- **Capability caps driven by attested wear.** The physical limits a robot operates
  under are derived from its signed wear level, so a degrading robot is bound to a
  proportionally tighter envelope rather than its original factory caps.
- **Derating that is a valid attenuation by construction.** Because the rule only ever
  lowers numeric caps and preserves zones and windows, the derived scope always passes
  the existing attenuation check, so wear-based narrowing composes with delegation.
- **Deterministic and reproducible.** The narrowing is a fixed computation, so a
  verifier reproduces the derated scope from the wear level and the original scope and
  confirms a robot is honoring the tighter envelope.

---

## 2. Problem Statement

### 2.1 Physical limits do not track wear

A robot's physical capability scope is normally the fixed set of caps it was
commissioned with. As the robot wears, those caps become unsafe, but nothing
automatically ties the limit a robot operates under to how degraded it is.

### 2.2 An ad hoc derating does not compose with delegation

If an operator hand-lowers a worn robot's caps, there is no guarantee the result is a
valid attenuation of the original grant, so it does not compose with the delegation and
attenuation rules that govern the rest of the robot's authority.

---

## 3. Solution (The Invention)

`attenuate_for_wear(scope, wear_level)` derives a physical scope in which each numeric
cap present in the original, such as maximum force, maximum speed, and maximum speed
near humans, is scaled by one minus the wear level, and the allowed zones and shift
windows are carried through unchanged. Because every cap can only decrease and the
zones and windows are unchanged, the derived scope satisfies the existing `attenuates`
relation with the original scope, so wear-based narrowing is a valid attenuation and
composes with delegation. The computation is deterministic, so a verifier reproduces
the derated scope from the attested wear level of PAD-091 and the original scope and
confirms the robot is operating inside the tighter envelope. This is the open layer of
deriving and verifying the narrowed scope credential; firmware-level enforcement of the
narrowed envelope at the actuator and managed predictive-maintenance modeling are out
of scope.

---

## 4. Prior Art Differentiation

Derating, safety envelopes, and capability attenuation each exist as prior art. This
disclosure does **not** claim those mechanisms in the abstract. What is differentiated
is the reduction to wear-driven capability attenuation for a robot:

- **Deriving the physical caps from an attested wear level**, so the limit a robot
  operates under is a function of its signed degradation state.
- **A derating that is a valid attenuation by construction**, so it composes with the
  existing delegation and attenuation rules rather than sitting outside them.
- **A deterministic, reproducible narrowing**, so a verifier confirms a worn robot is
  honoring the tighter envelope from the wear level and the original scope.

---

## 5. Technical Implementation

A reference implementation provides `attenuate_for_wear`, which scales the numeric caps
of a physical scope by the attested wear level and preserves the zones and windows, and
the result satisfies the shared `attenuates` relation, so the same check runs across the
language SDKs.

---

## 6. Claims Summary

1. A method for narrowing a robot's physical capability scope in which the numeric caps
   of the scope are scaled down as a function of the robot's attested wear level.
2. The method of claim 1 wherein the allowed zones and shift windows are preserved so
   the derived scope is a valid attenuation of the original on every dimension.
3. The method of claim 2 wherein the derived scope satisfies the same attenuation
   relation used to accept a delegated scope, so wear-based narrowing composes with
   delegation.
4. The method of claim 1 wherein the narrowing is deterministic, so a verifier
   reproduces the derated scope from the wear level and the original scope.
5. The method of claim 1 wherein the wear level is taken from a signed wear attestation
   bound to the robot's identity.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
