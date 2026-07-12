# PAD-098: Deterministic Multi-Dimensional In-Domain Check for a Robot's Operating Parameters

**Identifier:** PAD-098  
**Title:** Method for a Deterministic, Reproducible Predicate That Decides Whether a Robot's Observed Operating Parameters Stayed Inside Its Certified Domain Across Zone, Speed, Condition, and Time Dimensions  
**Publication Date:** July 6, 2026  
**Prior Art Effective Date:** July 6, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Autonomy Safety / Conformance  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-066 (Physical Capability Scope), PAD-097 (Operating-Domain Conformance)  

---

## 1. Abstract

A method for deciding, deterministically and reproducibly, whether a robot's observed
operating parameters stayed inside its certified operating domain. The check compares the
observed maximum speed, the zones visited, the environmental conditions, and the time of
operation against the corresponding dimensions of a signed operating-domain credential, and
returns a pass with the specific reasons for any out-of-domain dimension. Because the check
is a fixed computation, a verifier reproduces the in-domain verdict from the domain and the
observations, so a robot cannot report parameters that are out of domain while claiming it
stayed in.

Key innovations:

- **A single predicate over heterogeneous domain dimensions.** Zone membership, a numeric
  speed cap, named condition bounds, and time windows are evaluated by one check that
  returns a combined verdict and per-dimension reasons.
- **Named condition bounds by direction.** A condition keyed with a maximum prefix is an
  upper bound and one keyed with a minimum prefix is a lower bound, so a maximum wind speed
  and a minimum visibility are both expressible and checkable.
- **Deterministic and reproducible.** The check is a fixed computation reproduced across
  language SDKs, so a verifier confirms the in-domain verdict rather than trusting it.

---

## 2. Problem Statement

### 2.1 Out-of-domain has many dimensions

A robot can leave its operating domain by speed, by zone, by an environmental condition, or
by time of day, and a check that covers only one dimension misses the others.

### 2.2 A self-reported verdict must be reproducible

If a robot reports whether it stayed in domain, that verdict is only trustworthy if a
verifier can reproduce it deterministically from the same domain and observations.

---

## 3. Solution (The Invention)

`check_in_domain(...)` takes a certified operating domain and a set of observed operating
parameters and returns a verdict with reasons. It compares the observed maximum speed
against the domain maximum, the zones visited against the allowed set, each observed
condition against its named bound (a key prefixed with a maximum term is an upper bound, a
minimum term a lower bound), and the observed time against the domain time windows. An
absent domain dimension is unconstrained by design. Because the check is a fixed
computation over the credential fields, the same verdict is reproduced across language SDKs,
which is what lets `verify_odd_conformance` of PAD-097 confirm a robot's self-reported
in-domain verdict rather than trust it. This is the open layer of the deterministic check;
predicting an imminent out-of-domain excursion and enforcing a safe stop are out of scope.

---

## 4. Prior Art Differentiation

Predicate evaluation, geofencing, and envelope checks each exist as prior art, as does this
project's own physical-action check. This disclosure does **not** claim those in the
abstract. What is differentiated is the reduction to a robot's operating domain:

- **One predicate spanning zone, speed, environmental condition, and time**, returning a
  combined verdict with per-dimension reasons.
- **Directional named condition bounds**, so both upper and lower environmental limits are
  checkable.
- **A deterministic, reproducible verdict**, so a self-reported in-domain claim is
  confirmable from the domain and the observations.

---

## 5. Technical Implementation

A reference implementation provides `check_in_domain`, evaluated inside
`build_odd_conformance` and reproduced inside `verify_odd_conformance`, using the shared
primitives so the same verdict is produced across the language SDKs.

---

## 6. Claims Summary

1. A method for deciding whether a robot's observed operating parameters stayed inside a
   certified operating domain by comparing observed speed, zones, conditions, and time
   against the corresponding domain dimensions and returning a verdict with reasons.
2. The method of claim 1 wherein a condition bound is interpreted as an upper or a lower
   bound according to a named prefix, so both maximum and minimum environmental limits are
   checkable.
3. The method of claim 1 wherein an absent domain dimension is unconstrained.
4. The method of claim 1 wherein the check is deterministic, so a verifier reproduces the
   in-domain verdict from the domain and the observations.
5. The method of claim 1 wherein the computation is shared across language SDKs, so the
   same verdict is produced cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented, to
prevent patenting by any party and to keep them available to the open Vouch Protocol
ecosystem and the robotics community.
