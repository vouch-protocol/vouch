# PAD-075: Untrusted-Resolver Identity Routing via Self-Signed Route Records with Anti-Substitution Binding

**Identifier:** PAD-075  
**Title:** Method for Reaching an Agent by Its Decentralized Identifier in Which the Agent Self-Signs a Record Binding Its Identifier to a Current Network Endpoint, the Resolving Infrastructure Is Treated as an Untrusted Cache, and the Requesting Party Re-Verifies the Record and Confirms Its Subject Equals the Queried Identifier, So a Resolver Can Neither Forge a Route Nor Substitute Another Identity's Record  
**Publication Date:** June 30, 2026  
**Prior Art Effective Date:** June 30, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Agent Identity / Decentralized Identifiers / Routing / Trust  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-005 (Detached Signature Recovery), PAD-074 (Trust-Preserving Transport Failover)  

---

## 1. Abstract

A method for resolving an autonomous agent's decentralized identifier (DID) to
the network endpoint at which it can currently be reached, without DNS, without
the agent owning a domain, and without trusting the resolving infrastructure. The
agent publishes a compact route record that binds its DID to a current endpoint,
an optional capability lane, an expiry, and a nonce, and signs the record with
the DID's own key. The resolving infrastructure, whether a single rendezvous
service, a registry, or a distributed overlay, is treated as an untrusted cache:
it may withhold, delay, or replay a record but is never believed. On resolving,
the requesting party re-verifies the record's signature against the key recovered
from the DID and, critically, confirms that the record's subject DID equals the
DID it queried for. A resolver therefore cannot forge a route, and cannot answer
a query for one identity with a different identity's validly-signed record.

Key innovations:

- **Self-signed route, not authority-signed.** The agent asserts its own location
  by signing the binding with its identity key, so the record is self-certifying;
  no naming authority, registrar, or zone signs on the agent's behalf.
- **Untrusted resolving infrastructure.** The resolver is explicitly modeled as a
  cache that cannot be believed. Security does not depend on the honesty or
  integrity of the host that stores and serves records, which lets the resolver
  run on infrastructure the agent does not control.
- **Anti-substitution binding to the queried identifier.** Re-verification checks
  not only that the record is validly signed but that its subject equals the
  identifier the caller asked for, defeating an infrastructure that returns
  another identity's genuine record in response to a query.
- **Bounded freshness via signed expiry and nonce.** The expiry and nonce are
  inside the signed body, so a stale or replayed record is detectable and is
  rejected on read as well as on write.

---

## 2. Problem Statement

### 2.1 The identifier is a key store, not a location

A DID Document answers "what is this identity's public key," not "where is this
identity right now." `did:web` recovers a location only by borrowing DNS and a
domain, which ephemeral agents rarely hold and which reintroduces a seizable,
poisonable naming authority. The location an agent actually needs is dynamic and
self-asserted, not delegated to a registrar.

### 2.2 Trusting the resolver reintroduces the problem it solves

A directory that maps identifiers to endpoints is only as honest as its operator.
If the resolver is trusted, it becomes a single point that can redirect any agent
to an endpoint of its choosing, which is the same seizure-and-poisoning risk that
identity-first routing set out to remove.

### 2.3 A valid signature is not enough

Re-verifying that a returned record is validly signed is necessary but not
sufficient. A malicious resolver can hold many genuine, validly-signed records
and answer a query for identity A with identity B's record. Unless the caller
binds the answer to the identifier it asked for, signature checking alone does not
prevent substitution.

### 2.4 Stale and replayed routes

An endpoint binding is time-sensitive: agents move. A record with no signed
freshness bound can be replayed by infrastructure long after the agent has moved,
directing traffic to a dead or reassigned endpoint.

---

## 3. Solution (The Invention)

An agent constructs a route record with its DID, a current endpoint, an optional
capability-lane selector, an expiry, and a fresh nonce, and signs the canonical
(JCS) form of that body with the Ed25519 key behind its DID. The signature covers
every field but itself, so the record is tamper-evident and self-authenticating.

To publish, the agent hands the record to resolving infrastructure: a single
rendezvous service, a registry, or a distributed overlay. The infrastructure
verifies the record on write (rejecting anything not validly self-signed or
already expired) purely as hygiene, but no party relies on it having done so. The
record is indexed under a one-way fingerprint of the DID so the identifier itself
need not appear in a lookup key or URL.

To resolve, a requesting party computes the same fingerprint for the DID it wants,
fetches the record, and then performs the verification that actually matters,
independent of and not trusting the infrastructure:

1. recover the public key from the DID and verify the record's signature;
2. confirm the record has not expired;
3. confirm the record's subject DID is exactly the DID that was queried.

Only if all three hold does the caller use the endpoint. Because step 3 binds the
answer to the question, an infrastructure that serves a different identity's
genuine record is caught; because steps 1 and 2 are done by the caller, an
infrastructure that forges or replays is caught. The same record format and the
same three-step verification apply whether the infrastructure is an in-memory
rendezvous, an HTTPS service, or a distributed overlay, so the resolver can be
swapped without changing the trust argument.

---

## 4. Prior Art Differentiation

Self-certifying names (SFS), IPNS, DNSSEC, and DID resolution methods that publish
to a distributed store (for example DHT-published DID Documents) are established
prior art. This disclosure does **not** claim self-certifying identifiers, signed
name records, or DHT publication in general. What is differentiated is the
combination that makes the resolving infrastructure untrusted for agent endpoint
routing:

- **Authority model: the identity signs its own route.** DNSSEC records are signed
  by the zone authority, and the resolver trust chain is rooted in that hierarchy.
  Here the named identity itself signs the endpoint binding and no authority signs
  on its behalf, so there is no naming authority to trust or seize.
- **Explicit untrusted-resolver threat model with anti-substitution.** Self-
  certifying and DHT-published schemes establish that a record is authentic, but
  do not, as a defined verification step, bind the served record to the exact
  identifier the caller queried. The disclosed method makes "subject equals
  queried identifier" a mandatory verification step precisely to defeat a resolver
  that substitutes another identity's genuine record. This is the non-obvious
  addition when the resolver is assumed hostile.
- **Endpoint-route attestation, not content addressing or document publication.**
  IPNS binds a key to content; DID-Document publication serves a document. The
  unit here is a compact, freshness-bound endpoint route for reaching a live
  agent, designed to be re-verified per resolution and composed with an
  accountability-bearing message envelope (see PAD-074).
- **Resolver as interchangeable untrusted cache.** Because the trust argument is
  entirely on the caller's side, the same record and verification hold across an
  in-memory rendezvous, an HTTPS service, or a distributed overlay, and the
  infrastructure may run on hosts the agent does not control.

### Relationship to UDNA

This method is designed to run on, and interoperate with, UDNA (Universal
DID-Native Addressing). It does **not** claim UDNA's primitives: DID-as-routing-
primitive, the `sha256(did)` fingerprint used as the routing key, and the
capability-lane (facet) model are UDNA's, and the disclosed method adopts them for
interoperability rather than claiming them. What is claimed is the untrusted-
resolver verification model, the self-signed endpoint-route attestation, and the
anti-substitution binding to the queried identifier, which are independent of any
particular overlay and apply equally to a single rendezvous or to DNS-free HTTPS
resolution.

---

## 5. Technical Implementation

A reference implementation ships in the Python SDK under `vouch.transport`:
`RouteRecord` and `build_route_record` produce and self-sign the binding (DID,
endpoint, facet, expiry, nonce) over the shared JCS canonical form; `RouteRecord.
verify` performs the three-step check (signature against the key recovered from
the `did:key`, non-expiry, and subject equality enforced by the caller via the
queried DID); `route_fingerprint` computes the one-way DID fingerprint used as the
lookup key. Two interchangeable resolvers ship behind one record format:
`RendezvousRegistry` / `RendezvousChannel` in memory, and a deployable HTTPS
rendezvous (`RendezvousService` / `build_rendezvous_app` server,
`HttpRendezvousResolver` / `HttpRendezvousChannel` client) in which the client
re-verifies every served record and rejects any whose subject differs from the
queried DID. Outbound endpoints are screened for SSRF before use. The resolved
route then carries a `VouchEnvelope`, so the trust evidence is preserved end to
end regardless of the resolver.

---

## 6. Claims Summary

1. A method for reaching an agent by its decentralized identifier in which the
   agent signs, with the key behind that identifier, a record binding the
   identifier to a current network endpoint with a signed expiry, and resolving
   infrastructure stores and serves the record without being trusted.
2. The method of claim 1 wherein the requesting party, on resolving, recovers the
   public key from the identifier, verifies the record's signature, confirms the
   record is unexpired, and confirms the record's subject identifier equals the
   identifier queried, before using the endpoint.
3. The method of claim 2 wherein confirming the subject equals the queried
   identifier defeats infrastructure that answers a query for one identity with
   another identity's validly-signed record.
4. The method of claim 1 wherein the record is indexed under a one-way function of
   the identifier so the identifier does not appear in the lookup key, and the
   record carries a nonce within the signed body to bound replay.
5. The method of claim 1 wherein the same record format and verification apply
   across an in-memory rendezvous, a hosted service, and a distributed overlay, so
   the resolving infrastructure is interchangeable and may run on hosts the agent
   does not control.
6. The method of claim 1 wherein the resolved endpoint carries a self-protecting
   credential envelope, so the message's integrity, authenticity, and
   accountability hold independently of the resolver and the transport.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem.
