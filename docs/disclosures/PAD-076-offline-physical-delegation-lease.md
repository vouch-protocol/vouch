# PAD-076: Offline-Verifiable, Scope-Bounded Delegation Lease for Physical Authority

**Identifier:** PAD-076  
**Title:** Method for a Short-Lived, Scope-Bounded Delegation Lease That a Disconnected Robot Verifies and Acts On Entirely Offline, With Shrink-Only Nesting Across Parties, Bounded by a Physical Capability Scope  
**Publication Date:** July 4, 2026  
**Prior Art Effective Date:** July 4, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Delegation / Offline Verification / Physical-World Credentials  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-002 (Chain of Custody), PAD-021 (Inverse Capability Protocol), PAD-064 (Hardware-Rooted Robot Identity), PAD-066 (Physical Capability Scope)  

---

## 1. Abstract

A method for a delegation lease: a short-lived, self-contained grant of physical
authority that a disconnected robot verifies and acts on with no network call at
use time. The lease is a signed Verifiable Credential carrying a lease identifier,
a validity window, and a scope that is itself a physical capability scope (force,
speed, a tighter cap near humans, allowed zones, and shift windows). A robot that
holds the lease and the issuer's public key can confirm, entirely offline, that it
is authorized to perform a given physical action right now, and that the action
falls inside the leased scope.

Key innovations:

- **Offline, self-contained physical-authority grant.** The lease travels with the
  robot and verifies against a cached issuer key, so an edge robot with no
  connectivity can still prove it is acting within a currently valid grant.
- **Bounded by a physical capability scope.** The grant is not an abstract role; it
  is a concrete envelope of force, speed, proximity, zone, and time, checked against
  the proposed physical action before actuation.
- **Shrink-only nesting across parties.** A lease can delegate a sub-lease, and each
  sub-grant may only narrow the envelope it inherits, never widen it, so authority
  attenuates down a cross-vendor chain and a verifier can confirm the chain never
  broadened.

---

## 2. Problem Statement

### 2.1 Edge robots act where there is no network

A robot on a loading dock, in a field, or deep in a warehouse often has no reliable
connectivity at the moment it must decide whether it is allowed to act. A grant of
authority that requires a live policy-server lookup fails exactly where the robot
operates.

### 2.2 Role tokens do not bound physical action

A bearer token or a role claim says who may act, not what force, speed, or zone is
permitted. For a machine that can cause physical harm, the grant must carry the
physical envelope the action is checked against, not a name.

### 2.3 Delegation across vendors can silently widen authority

When one party sub-delegates to another across an integration boundary, nothing in
a plain token prevents the sub-grant from claiming more than the parent held. A
verifier needs to confirm that every hop only narrowed the envelope.

---

## 3. Solution (The Invention)

`build_delegation_lease(...)` issues a `DelegationLeaseCredential` whose subject
carries a lease id, the delegated physical scope, and a validity window, signed
eddsa-jcs-2022 by the granting party. A robot calls `verify_delegation_lease(...)`
to check the proof and window using only the issuer's public key, then
`lease_permits(subject, action, lease)` to confirm a proposed physical action lies
inside the leased scope. No network call is made at use time.

A lease may delegate a sub-lease. The verifier confirms that each sub-lease's scope
attenuates the parent's (every bound is equal or tighter), so authority can pass
down a chain of parties while only ever shrinking. Because the lease uses the shared
JCS plus eddsa-jcs-2022 primitives and the same physical capability scope format,
the same lease verifies across the language SDKs.

---

## 4. Prior Art Differentiation

Delegation credentials, capability attenuation, and offline credential verification
each exist as prior art, including in this project's own agent-side delegation work.
This disclosure does **not** claim those general mechanisms. What is differentiated
is the reduction to a disconnected, physical, nesting grant:

- **Physical-envelope scope.** The leased authority is a force/speed/proximity/zone/
  time envelope checked before actuation, not an abstract permission.
- **Use-time offline verification for an embodied actor.** The robot decides at the
  edge with no server, using only a cached issuer key.
- **Shrink-only nesting across parties.** Attenuation is enforced and verifiable at
  every hop of a cross-vendor chain, so no sub-grant can exceed its parent.

---

## 5. Technical Implementation

A reference implementation provides `build_delegation_lease`,
`verify_delegation_lease`, and `lease_permits`, with the lease scope expressed in
the same physical capability scope format as PAD-066 and verified with the shared
Data Integrity primitives. The lease is signed and validity-windowed; rendering,
transport, and storage are the caller's concern.

---

## 6. Claims Summary

1. A method for delegating physical authority to a robot as a signed, validity-
   windowed credential whose scope is a physical capability envelope, verifiable and
   enforceable entirely offline at use time using only a cached issuer public key.
2. The method of claim 1 wherein a proposed physical action is admitted only if it
   lies inside the leased envelope of force, speed, proximity, zone, and time.
3. The method of claim 1 wherein a lease may issue a sub-lease whose envelope may
   only narrow, never widen, the envelope it inherits.
4. The method of claim 3 wherein a verifier confirms that every hop of a multi-party
   delegation chain attenuated rather than broadened the authority.
5. The method of claim 1 wherein the lease uses canonicalization and signature
   primitives shared across language SDKs, so the same lease verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the robotics community.
