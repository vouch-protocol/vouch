# PAD-124: Binding Verifiable-Credential Trust to Delay-Tolerant Networking Bundle Custody

**Identifier:** PAD-124  
**Title:** Method by Which a Verifiable Credential and Its Freshness Are Bound to a Delay-Tolerant Networking Bundle and Its Custody-Transfer Chain, So a Store-Carry-Forward Message Carries Attributable, Verifiable Trust Across Intermittent Relays  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Delay-Tolerant Networking / Provenance / Standards Integration / Offline Verification  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-106 (Bounded-Staleness Revocation), PAD-107 (Presenter Proof of Freshness), PAD-002 (Chain of Custody), PAD-111 (Quorum-of-Orbits Trust Anchoring)  

---

## 1. Abstract

Delay-tolerant networks move data as store-carry-forward *bundles* (Bundle Protocol,
RFC 9171) that hop across intermittently-connected relays, with custody transferred hop
to hop. This method binds a Vouch Verifiable Credential — the identity and authority of
the bundle's originator, and the freshness of its trust state — into the bundle and its
custody-transfer chain, so a bundle arriving after a long, multi-hop, intermittent
journey carries attributable, offline-verifiable trust: who originated it, under what
authority, how fresh their standing was, and which relays held custody. It is the
concrete integration of Vouch's disconnected-edge trust with the standard DTN transport.

Key innovations:

- **Credential-bound bundles.** The originator's signed credential and intent are bound
  to the bundle's blocks, so a recipient verifies who sent it and what it authorizes,
  offline, after arbitrary delay.
- **Freshness carried in the bundle.** A presenter-side freshness proof (PAD-107) and/or
  a carried non-revocation witness (PAD-120) travel in the bundle, so the recipient
  judges freshness under a consequence-scaled gate (PAD-106) without a live authority.
- **Custody chain as verifiable provenance.** Each custody transfer is signed by the
  accepting relay, producing an attributable chain of who carried the bundle, so an
  incident traces to the responsible hop.

---

## 2. Problem Statement

### 2.1 DTN custody is about delivery, not trust

Bundle Protocol custody transfer establishes reliable hand-off of the bytes; it says
nothing about the identity or authority of the originator, nor the freshness of that
authority on arrival.

### 2.2 A long-delayed bundle needs self-contained trust

A bundle may arrive days later through relays the recipient does not trust. It must carry
everything needed to verify origin, authority, and freshness offline.

### 2.3 Accountability across relays is missing

When a bundle causes an effect, the recipient needs to know which relays carried it and
that none tampered, which plain custody signaling does not provide as verifiable
provenance.

---

## 3. Solution (The Invention)

The originator binds a Vouch credential (identity, intent/authority) to the bundle by
signing over its payload and relevant blocks, and includes freshness evidence — a
presenter-side freshness token (PAD-107) and/or a carried non-revocation witness
(PAD-120). Each relay that accepts custody signs a custody-transfer record binding the
bundle identifier, the previous custodian, itself, and the epoch, extending an
attributable custody chain (the DTN instance of the chain-of-custody pattern, PAD-002).
On receipt, the recipient verifies the originator's credential and payload binding, judges
the freshness evidence under the consequence-scaled staleness gate (PAD-106), and walks
the custody chain to see which relays carried it. Anchor/revocation state used in
verification is distributed with quorum diversity (PAD-111). The result is a
store-carry-forward message whose trust and provenance are verifiable entirely offline on
arrival, regardless of delay or the trustworthiness of intermediate relays.

---

## 4. Prior Art Differentiation

Bundle Protocol, Bundle Security Protocol (BPSec), and custody transfer are prior art.
This disclosure does **not** claim DTN transport or BPSec. What is differentiated is:

- **Binding a decentralized-identity Verifiable Credential and its consequence-scaled
  freshness evidence into a DTN bundle**, so origin, authority, and freshness are
  verifiable offline on arrival — beyond BPSec's hop and end-to-end integrity/confidentiality.
- **A signed, attributable custody-transfer chain as verifiable provenance** for the
  bundle, tying each hop to an accountable identity.
- **Composition with presenter freshness, carried non-revocation, staleness gating, and
  quorum anchor distribution** (PAD-107/120/106/111) as a coherent trust layer over the
  DTN standard.

BPSec secures a bundle's integrity and confidentiality between security sources and
acceptors; it does not carry decentralized-identity authority with consequence-scaled
freshness and an attributable custody-provenance chain for offline evaluation.

---

## 5. Technical Implementation

A reference design binds a Vouch credential and freshness evidence into bundle blocks,
defines a signed custody-transfer record per hop, and a recipient verifier combining
credential/payload verification, the PAD-106 freshness gate, and custody-chain walk.
Transport is standard Bundle Protocol; the open layer is the credential/freshness binding
and the custody-provenance record.

---

## 6. Claims Summary

1. A method by which a Verifiable Credential asserting an originator's identity and
   authority is bound to a delay-tolerant networking bundle so a recipient verifies origin
   and authority offline after arbitrary delay.
2. The method of claim 1 wherein freshness evidence carried in the bundle is judged under
   a consequence-scaled staleness gate with no live authority.
3. The method of claim 1 wherein each relay accepting custody signs a transfer record
   forming an attributable custody-provenance chain for the bundle.
4. The method of claim 1 wherein anchor and revocation state used in verification is
   distributed via a quorum of anchors from distinct independent failure domains.
5. The method of claim 1 wherein the recipient traces the custody chain to attribute the
   bundle's carriage to specific relays and detect tampering.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
