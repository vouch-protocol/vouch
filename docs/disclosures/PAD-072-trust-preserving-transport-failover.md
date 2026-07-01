# PAD-072: Trust-Preserving Multi-Transport Failover for Liability-Bearing Credential Envelopes

**Identifier:** PAD-072  
**Title:** Method for Delivering a Self-Protecting Credential Envelope Across Heterogeneous Transports Selected at Runtime, in Which the Same Envelope Is Handed Byte-for-Byte to Whichever Transport Succeeds and an Integrity-Versus-Availability Error Taxonomy Forbids Re-Routing a Corrupted Payload, So the Trust Properties Are Invariant Under Failover  
**Publication Date:** June 30, 2026  
**Prior Art Effective Date:** June 30, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Agent Identity / Transport / Verifiable Credentials / Liability  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-002 (Chain of Custody), PAD-003 (Identity Sidecar), PAD-073 (Untrusted-Resolver Identity Routing)  

---

## 1. Abstract

A method for moving a trust-bearing message between autonomous agents over more
than one network transport, chosen at the moment of delivery, without ever
weakening the message's trust properties. The message is a self-protecting
envelope that carries a signed Verifiable Credential, one or more liability
attestations, and provenance metadata, together with a canonical content digest
over that payload. A dispatcher holds an ordered set of transports (for example
an identity-first overlay and a location-first DNS/HTTPS path) and hands the
**same** envelope, byte-for-byte, to whichever transport can reach the peer.
Delivery distinguishes two failure classes: a transport-availability failure is
recoverable and advances to the next transport, while a payload-integrity
failure is fatal and stops delivery, so a corrupted or tampered envelope is never
re-routed across transports in search of one that will accept it.

Key innovations:

- **Trust carried by the payload, not the channel.** The cryptographic
  properties (integrity, authenticity, accountability) live in the signed
  envelope, so they do not depend on which transport carries the bytes. Failover
  is a pure reachability operation and cannot change the security posture.
- **Byte-identical handoff across transports.** The winning transport receives
  the exact envelope produced once at the source. Failover never re-signs,
  re-wraps, re-canonicalizes, or strips the credential, attestations, or
  provenance, so nothing about the trust evidence changes between attempts.
- **Integrity-versus-availability error taxonomy.** Delivery classifies failures
  as either "transport unavailable" (try the next transport) or "payload
  integrity violated" (stop immediately and never re-route). A corrupted payload
  cannot be laundered by trying another channel.
- **Liability and provenance travel with the credential.** The envelope binds
  the accountability evidence (who is answerable, and the origin trail) to the
  same digest as the credential, so an intermediary cannot deliver the credential
  while dropping the attestations that make the actor accountable.

---

## 2. Problem Statement

### 2.1 Channel-rooted trust breaks under failover

Conventional secure delivery roots trust in the channel: TLS, a libp2p secure
stream, or an overlay's encrypted session. When an agent must reach a peer over
whichever path happens to be available, channel-rooted trust forces a separate
trust negotiation per transport, and the security posture silently varies with
the path actually taken. Two transports with different channel guarantees give
the same message two different trust stories.

### 2.2 Agents are multi-homed and ephemeral

Autonomous agents move across hosts and clouds, are reachable sometimes by a
stable domain and sometimes only by identity, and frequently fail over between
paths within a single conversation. A delivery layer that must be reconfigured,
or that changes the message, on each path is fragile exactly where agents operate.

### 2.3 Failover can launder a bad payload

A naive failover loop that simply tries the next transport on any error will,
on a payload that fails an integrity check at one endpoint, keep trying other
endpoints until one accepts it. Without distinguishing "could not reach" from
"payload is corrupt," failover becomes an oracle that searches for a transport
willing to take a tampered message.

### 2.4 Stripping accountability in transit

When liability and provenance are carried separately from the credential, an
intermediary can forward the credential while quietly dropping the attestations
that make the actor answerable, leaving an authentic-looking but unaccountable
message.

---

## 3. Solution (The Invention)

A source agent builds a single envelope object that wraps the signed credential
as its payload and carries, alongside it, the liability attestations, the
provenance metadata, an envelope version, and a content digest computed as a
SHA-256 over the RFC 8785 (JCS) canonical form of the payload. The envelope is
produced once.

A transport manager holds an ordered list of transports, each implementing a
small uniform interface: a cheap pre-filter that says whether it can route a
given DID, a resolution step that returns a peer address or declines, and a send
step. For a given envelope the manager walks the list: it skips a transport whose
pre-filter declines, skips a transport whose resolution declines (the peer is not
reachable that way), and otherwise attempts the send. The exact same envelope
instance is passed to whichever transport attempts delivery.

Failures are typed. A transport that cannot reach the peer raises a recoverable
"transport unavailable" condition, and the manager advances to the next
transport, recording the attempt so the delivery result reports the path taken
(for example, identity-first first, then DNS/HTTPS). A failure that indicates the
payload's integrity is in question raises a fatal "payload integrity" condition,
and the manager stops at once and does not try any further transport. If every
transport is exhausted by availability failures, the manager raises a terminal
error carrying the last cause.

Because the trust evidence is entirely inside the signed envelope and the digest
is verifiable on receipt, a receiver validates the message identically no matter
which transport delivered it, and switching transports is provably incapable of
altering the credential, the attestations, or the provenance.

---

## 4. Prior Art Differentiation

Connection-level failover (happy-eyeballs across IPv4/IPv6, QUIC-to-TCP
fallback, libp2p multistream transport selection) and signed messages over a
retrying transport (S/MIME over SMTP) are established prior art. This disclosure
does **not** claim transport failover or message signing in general. What is
differentiated is their composition for accountable agent messaging:

- **Trust invariance under failover, not connection liveness.** Existing failover
  selects a working connection and roots trust in that connection's channel
  security. Here trust is carried by the payload and is therefore invariant
  across whichever transport wins; the channel is reduced to a pure reachability
  concern. The protected property is that failover cannot change the security
  posture, which connection-level failover does not provide.
- **Integrity-versus-availability error taxonomy governing failover.** The
  delivery loop is explicitly forbidden from re-routing on a payload-integrity
  failure and only advances on a reachability failure. Generic retry/failover
  loops do not make this distinction and can re-route a corrupted payload.
- **A single byte-identical envelope across heterogeneous transports.** The
  message is produced once and handed unchanged to an identity-first overlay or a
  location-first DNS/HTTPS path alike, with no per-transport re-signing or
  re-wrapping. Multi-transport stacks typically re-frame the message per
  transport.
- **Liability and provenance bound to the credential digest.** The envelope binds
  accountability evidence to the same canonical digest as the credential, so an
  intermediary cannot deliver the credential while stripping the attestations.
  Signed-email and signed-payload schemes carry a signature over content but not a
  co-bound liability-and-provenance composite with this digest discipline.

### Relationship to UDNA

The identity-first transport used as one of the failover options may be UDNA
(Universal DID-Native Addressing) or any other overlay. This disclosure does not
claim DID-as-routing-primitive, the DID-fingerprint routing key, or the facet
model, which are UDNA's. The claimed method is the transport-agnostic,
trust-preserving failover discipline and its error taxonomy, which sit above any
particular overlay and apply equally to DNS/HTTPS.

---

## 5. Technical Implementation

A reference implementation ships in the Python SDK under `vouch.transport`:
`VouchEnvelope` / `build_envelope` produce the self-protecting envelope with an
`ENVELOPE_VERSION` and a JCS SHA-256 content digest over the payload;
`TransportManager.dispatch` performs the ordered walk and returns a
`DeliveryResult` carrying the winning transport name and the `attempts` path; the
`Transport` abstract base defines the `can_route` / `resolve` / `send` interface;
`TransportUnavailable` is the recoverable condition that advances failover and
`PayloadIntegrityError` is the fatal condition that stops it; `TransportError`
carries the terminal cause when all transports are exhausted. Two transports ship
(`UdnaTransport` identity-first, `HttpTransport` did:web over DNS/HTTPS), and a
deployable HTTPS rendezvous path is available; all use the same envelope and the
same digest, so the trust properties hold whichever delivers the bytes. The
canonicalization and digest reuse the SDK's shared JCS path, so an envelope is
verified identically across language SDKs.

---

## 6. Claims Summary

1. A method for delivering a trust-bearing message between agents in which a
   single envelope carrying a signed credential, one or more liability
   attestations, and provenance, together with a canonical content digest over
   that payload, is handed byte-for-byte to whichever of an ordered set of
   runtime-selected transports succeeds, so the trust properties are invariant
   under the choice of transport.
2. The method of claim 1 wherein delivery distinguishes a recoverable
   transport-availability failure, which advances to the next transport, from a
   fatal payload-integrity failure, which stops delivery, so a corrupted payload
   is never re-routed.
3. The method of claim 1 wherein the trust evidence is carried entirely within
   the signed envelope so that a receiver validates the message identically
   regardless of which transport delivered it.
4. The method of claim 1 wherein the ordered set includes an identity-first
   transport that routes by a decentralized identifier and a location-first
   transport that resolves a domain over DNS and HTTPS, and the delivery result
   records the sequence of transports attempted.
5. The method of claim 1 wherein the liability attestations and provenance are
   bound to the same canonical digest as the credential, so an intermediary
   cannot deliver the credential while stripping the accountability evidence.
6. The method of claim 1 wherein the envelope canonicalization and digest are
   shared across language SDKs, so the same envelope verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem.
