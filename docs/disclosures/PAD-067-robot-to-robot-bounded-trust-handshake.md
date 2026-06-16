# PAD-067: Robot-to-Robot Bounded-Trust Handshake Across Trust Domains

**Identifier:** PAD-067  
**Title:** Method for Two Robots in Different Trust Domains to Authenticate and Establish a Scope-Bounded Cooperation Session via a Three-Message Signed Handshake with Scope Intersection  
**Publication Date:** June 14, 2026  
**Prior Art Effective Date:** June 14, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Multi-Agent Systems / Cross-Domain Trust / Authenticated Key/Scope Agreement / AI Safety  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-063 (Live Trust-Standing Propagation), PAD-064 (Hardware-Rooted Robot Identity), PAD-066 (Physical Capability Scope)  

---

## 1. Abstract

A method by which two robots that belong to different trust domains establish a
bounded-trust cooperation session before acting jointly, using a three-message
signed handshake. The initiator sends a signed HELLO carrying its identity, a
fresh nonce, and the scope it proposes. The responder verifies the initiator's
identity, checks the initiator's trust domain against the responder's policy, and
signs an ACCEPT carrying the **intersection** of the proposed scope with what the
responder is willing to grant, bound to the nonce. The initiator verifies the
ACCEPT and signs a CONFIRM. The agreed session scope is therefore never broader
than what either robot grants.

Key innovations:

- **Scope intersection as bounded trust.** The cooperation scope is the
  intersection of the two robots' offered scopes, so neither side is exposed to
  more than it agreed to.
- **Domain-policy gate.** The responder accepts only if the initiator's trust
  domain (its did:web domain) is permitted by the responder's policy, enabling
  cross-domain cooperation under explicit policy.
- **Nonce-bound three-message exchange.** A fresh nonce binds the HELLO, ACCEPT,
  and CONFIRM into one session, preventing replay and binding the agreed scope to
  the exchange.

---

## 2. Problem Statement

### 2.1 Cooperating robots from different operators lack a trust-establishment step

When two robots from different fleets or vendors must cooperate, there is no
standard, identity-authenticated, scope-bounded handshake that establishes how
much each will trust the other and for what.

### 2.2 Authentication without bounded scope is unsafe

Authenticating the peer is not enough; a cooperation session must bound what the
peer is allowed to do, derived from what each side is willing to grant.

### 2.3 Cross-domain policy is not expressed at the handshake

The decision to cooperate with a peer from another trust domain should be a policy
decision made at the handshake, not an implicit consequence of mere reachability.

---

## 3. Solution (The Invention)

Each message is a signed (eddsa-jcs-2022) object:

1. **HELLO** (initiator A): `{ from: A, to: B?, nonce, proposedScope, issuedAt }`.
2. **ACCEPT** (responder B): B verifies HELLO's signature, checks A's domain
   against B's trust policy (a set of trusted did:web domains, or accept-unknown),
   computes `boundedScope = proposedScope intersect offeredScope`, and signs
   `{ from: B, sessionId, nonce, boundedScope, validUntil }`.
3. **CONFIRM** (A): A verifies ACCEPT, confirms the nonce echoes, and signs
   `{ from: A, sessionId, nonce, acceptedScope }`.

Both parties now hold the same bounded session: an identifier, the two DIDs, the
intersected scope, the nonce, and an expiry. The scope is the meet of the two
offers, so cooperation is bounded by mutual consent. The trust-domain check makes
cross-domain cooperation an explicit policy decision.

---

## 4. Prior Art Differentiation

- **TLS / Noise / authenticated key exchange.** Establish a secure channel and
  authenticate peers but do not negotiate a bounded authorization scope as the
  intersection of two offered capability sets, nor gate on a cross-domain trust
  policy expressed in robot identity terms.
- **OAuth scopes.** Are granted by an authorization server to a client; they are
  not the mutually-intersected scope of two peer robots established in a direct
  handshake.
- **PAD-063 (Live Trust-Standing Propagation).** Carries a caller's trust into a
  call; the present method is a symmetric, scope-bounding handshake between two
  robots in different domains, which PAD-063 does not address.

---

## 5. Technical Implementation

A reference implementation provides `build_hello`, `build_accept` (with the trust
policy check and scope intersection), `verify_accept`, `build_confirm`, and
`verify_confirm`, plus a `TrustPolicy` over did:web domains and a `BoundedSession`
result. Each message reuses the eddsa-jcs-2022 signing, so the handshake verifies
with the cross-language SDKs.

---

## 6. Claims Summary

1. A method for two robots in different trust domains to establish a cooperation
   session via a three-message signed handshake in which the agreed scope is the
   intersection of the two robots' offered scopes.
2. The method of claim 1 wherein the responder accepts only if the initiator's
   trust domain is permitted by the responder's policy.
3. The method of claim 1 wherein a fresh nonce binds the three messages into one
   session and prevents replay.
4. The method of claim 1 wherein the bounded session carries the two identities,
   the intersected scope, and an expiry, and neither robot is exposed beyond the
   intersected scope.
5. The method of claim 1 wherein the offered scopes and the intersection include
   physical capability dimensions (force, speed, zones, shift windows).

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the robotics community.
