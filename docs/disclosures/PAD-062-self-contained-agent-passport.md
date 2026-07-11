# PAD-062: Self-Contained, Offline-Verifiable Agent Passport Stapled Into Transport Metadata

**Identifier:** PAD-062
**Title:** Method for a Self-Contained Software-Agent Passport Carrying the Full Signed Credential Inside the Interaction's Transport Metadata, Conveying Operator, Authorized Action Scope, Certification, and Live Standing, Verifiable Offline Without Any Registry Lookup
**Publication Date:** July 12, 2026
**Prior Art Effective Date:** July 12, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Agent Identity / Offline Verification / Transport Bindings
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-002 (Delegation Chains), PAD-070 (Scannable Offline Robot Passport)

---

## 1. Abstract

A method for a software agent to present a "passport": a compact signed Verifiable
Credential conveying the agent's identity, its responsible operator, its authorized
action scope, optional certification, and its current operational standing (active,
suspended, or decommissioned), carried in full inside the transport metadata of the
interaction itself (an HTTP message member, a tool-call metadata field, or an
inter-agent message extension), so that any counterparty can verify the passport's
signature and contents at the moment of interaction, offline, with no registry
query, no discovery round-trip, and no per-agent lookup.

Key innovations:

- **Self-contained stapled credential rather than a pointer.** The transport field
  carries the entire signed credential, not an identifier or URL to be resolved.
  Verification requires only the issuer's public key, resolved or cached out of
  band, so it succeeds with no connectivity to any registry and creates no
  verification-time correlation signal at a central service.
- **Software-agent passport semantics.** The credential subject binds the agent
  key to the facts a counterparty actually needs: the responsible operator, the
  authorized action scope, optional third-party certification, and a live standing
  field, so one verification answers "who is this agent, who answers for it, what
  may it do, and is it in good standing right now."
- **Full-chain stapling.** The passport composes with delegation-chain credentials
  and recognized-issuer credentials presented in the same envelope, so a verifier
  that pins a single root key can validate the entire chain from action to root
  offline, in one pass, with nothing fetched.
- **Transport bindings with proof-set awareness.** Bindings are defined for HTTP
  (request body member, or header where size permits), tool-invocation metadata in
  agent tool protocols, and inter-agent message envelopes; when the passport
  carries a post-quantum proof set, the binding directs it to body-carriage rather
  than headers because of signature size.

## 2. Problem Statement

### 2.1 Registry lookups fail exactly when and where trust is needed

Prevailing designs answer "who is this agent" with a lookup: a registry, a
directory, a discovery service, or an on-chain record. The counterparty must be
online, the registry must be up and honest, and every verification event is
visible to the registry operator. An agent interaction inside a private network,
an air-gapped environment, or a degraded-connectivity scenario cannot be verified
at all.

### 2.2 Verification-time lookups leak the interaction graph

When every counterparty resolves every agent at interaction time, the resolver
learns who talks to whom and when. This correlation surface is structural to the
lookup model and cannot be patched away.

### 2.3 Static identity documents do not carry standing or accountability

A signed identity card fetched once conveys who published an agent, not whether it
is still authorized, what it may do for this operator, or who is responsible for
its actions now. Between issuance and use, suspension and decommissioning are
invisible without yet another lookup.

## 3. Solution (The Invention)

An issuer (the agent's operator, or an authority the verifier recognizes) issues
an `AgentPassport` Verifiable Credential whose subject carries the agent DID, the
operator identity, `authorizedActions`, `status` (active, suspended, or
decommissioned), a bounded validity window, and optional certification claims. The
credential is signed with a Data Integrity proof (`eddsa-jcs-2022` by default; a
post-quantum proof set where policy requires it).

The full signed credential is then stapled into the interaction's transport
metadata:

- **HTTP:** a top-level member of the request body envelope, or a dedicated header
  for classical-proof passports small enough for header carriage.
- **Tool protocols:** a metadata field of the tool invocation, so every call
  arrives with the passport of the agent that made it.
- **Inter-agent messages:** an envelope extension member alongside the payload.

The verifier decodes the credential from the transport field, checks the Data
Integrity proof against the issuer key it has pinned or cached, checks the
validity window and `status`, and applies local policy to `authorizedActions`. No
network request is made at verification time. Short validity windows bound the
staleness of `standing`; re-issuance on renewal composes with liveness mechanisms
without changing the binding.

Where the verifier does not directly know the issuer, the same envelope staples
the recognition chain: the credential by which a pinned root recognizes the
issuer. Chain validation proceeds credential by credential, entirely from the
presented material.

## 4. Prior Art Differentiation

- **Registry and directory models** (agent registries, naming services, on-chain
  identity records) publish identity for lookup. This method inverts the flow: the
  agent carries its verifiable identity to the interaction, and verification is
  local. The two compose (a passport can cite a registry entry) but do not
  coincide.
- **Signed capability documents** published at a well-known location authenticate
  a publisher's description of an agent, fetched out of band. The passport is
  presented in band, per interaction, and carries operator binding and live
  standing rather than a capability description.
- **Bearer tokens and access tokens** authorize without identifying: they are
  opaque to intermediaries, bound to an authorization server rather than an
  accountable operator, and generally verifiable only online. The passport is a
  non-bearer, publicly verifiable statement of identity, scope, and standing.
- **PAD-070** discloses the embodied sibling of this method: the same passport
  semantics rendered into a scannable QR/NFC URI for a physical robot. This
  disclosure covers carriage of the passport inside software transport metadata,
  the full-chain stapling, and the proof-set-aware bindings.

## 5. Technical Implementation

`build_passport(...)` issues the `AgentPassport` credential over JCS-canonicalized
subject bytes using `data_integrity.build_proof`; a proof-set variant appends an
ML-DSA-44 proof over the same canonical bytes. `staple_passport(envelope, vc)`
inserts the credential (and any recognition-chain credentials) into the transport
envelope for the binding in use. `verify_passport(envelope, trust_anchors)`
extracts, canonicalizes, and verifies each proof against pinned or cached issuer
keys, evaluates validity window, `status`, and `authorizedActions`, and returns
the verified passport for policy evaluation. Because the credential uses the
shared JCS plus Data Integrity primitives, the same passport verifies across the
language SDKs, and the QR/NFC rendering of PAD-070 can carry the identical
credential for human-facing inspection of a software agent (a kiosk showing the
passport of the agent a user is about to authorize).

Variations covered by this disclosure include: carriage of the passport digest in
a header with the full credential in the body; passports issued per session versus
per deployment; standing conveyed by short validity windows versus stapled
revocation-status entries; single-proof, proof-set, and future-suite proofs; and
stapling depth from a bare passport to the full root-recognition chain.

## 6. Claims Summary

1. A method for conveying a software agent's identity, operator, authorized action
   scope, certification, and live standing as a single signed credential carried
   in full within the transport metadata of the interaction it authenticates.
2. The method of claim 1 where verification is performed entirely from the
   presented material and locally held keys, with no verification-time network
   request, registry query, or per-agent lookup.
3. The method of claim 1 where the envelope additionally staples the credentials
   by which a pinned root recognizes the passport's issuer, enabling offline
   validation of the full chain from interaction to root.
4. The method of claim 1 where the credential carries a set of independent proofs
   over the same canonicalized bytes, and the transport binding selects header or
   body carriage according to the proof set's size.
5. The method of claim 1 where the identical credential is alternatively rendered
   as a scannable URI for human-facing inspection, unifying the software and
   embodied passport presentations.

## Prior Art Declaration

This document is a defensive publication establishing prior art as of the
publication date above. The described methods are published under the Apache 2.0
license as part of the Vouch Protocol project to ensure they remain freely
implementable by the ecosystem.
