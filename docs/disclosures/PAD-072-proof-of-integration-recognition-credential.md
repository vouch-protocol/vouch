# PAD-072: Proof-of-Integration Recognition Credential Gated by a Live Keyed Challenge-Response

**Identifier:** PAD-072  
**Title:** Method for Issuing a Recognition Credential Only After a Cryptographic Challenge-Response in Which the Candidate Answers a Fresh Nonce Through Its Own Live Protocol Surface Using the Key Bound to Its Claimed Decentralized Identifier, So the Credential Proves a Working, Keyed Deployment Rather Than an Asserted or Manually Reviewed Integration  
**Publication Date:** July 3, 2026  
**Prior Art Effective Date:** July 3, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Agent Accountability / Verifiable Credentials / Recognition / Proof of Capability  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-002 (Chain of Custody Delegation), PAD-016 (Heartbeat), PAD-039 (JCS Deterministic Multi-Party Trust State), PAD-071 (Commit-Before-Outcome Verdict Credential)  

---

## 1. Abstract

A recognition credential, for example a badge attesting that an independent
system integrates a protocol, is normally issued on the issuer's assertion or on
a one-time manual review. Such a credential says an integration exists but does
not prove that the recognized party operates a working, keyed deployment. This
method gates issuance on a cryptographic challenge-response. Before issuing, the
recognition authority generates a fresh nonce and requires the candidate to
answer it through the candidate's own live protocol surface, signing the nonce
with the private key bound to the decentralized identifier (DID) the candidate
claims. The authority resolves the candidate's published DID document, verifies
the response against it, and only then mints a credential that embeds the
challenge, a digest of the signed response, the probed live-surface locator, and
the observation time, itself chained to a delegated issuing authority. The result
is a recognition credential that is also a proof of capability: any later
verifier can confirm that, at issuance, the holder controlled the DID key and
served a conforming live surface.

Key innovations:

- **Issuance gated by demonstrated capability.** The credential is not signed
  until the candidate proves, live, that it holds the key for its claimed DID and
  serves a working endpoint. A badge cannot be aspirational or fabricated because
  the working system is a precondition of issuance.
- **Answered over the holder's own protocol surface.** The response is served
  from the candidate's declared endpoint and signed by the candidate's DID-bound
  key, so the proof is of that deployment, not of a name, an account, or an
  offline claim.
- **Capability-specific challenge.** The challenge MAY require the candidate to
  return a valid protocol artifact of exactly the type the badge attests, so the
  credential proves the deployment performs the recognized function, not merely
  that it is reachable.
- **Embedded, re-checkable proof.** The challenge nonce, a digest of the signed
  response, and the surface locator are carried inside the issued credential, so
  the capability proof is independently re-verifiable long after issuance,
  against the candidate's own DID, without trusting the authority's word.

---

## 2. Problem Statement

### 2.1 A recognition credential is issued on assertion

Open Badges and Verifiable Credentials attest a claim by the issuer's signature.
The issuer's honesty and diligence are the only guard. A badge can be
aspirational, mistaken, or fabricated, and nothing in it proves the recognized
system exists or works.

### 2.2 Domain or account control is not integration capability

Proofs of domain control (ACME) or account control (OIDC) show that the holder
controls a name or a login. They do not show that the holder operates a working,
keyed deployment of a particular protocol, still less that the deployment
performs the specific function being recognized.

### 2.3 A one-time manual review binds to nothing

Human review at issuance is unrepeatable and unverifiable later. The resulting
credential carries no artifact a third party can re-check, so a reader must trust
that a review happened and was correct.

---

## 3. Solution (The Invention)

The recognition authority runs a challenge-response before issuance:

1. **Challenge.** The authority generates a fresh random nonce and a challenge
   descriptor naming the expected live surface and the capability to demonstrate.
2. **Response over the live surface.** The candidate answers by returning, from
   its own published protocol endpoint, a signed object binding the nonce, the
   candidate's DID, and optionally a protocol artifact of the recognized type,
   signed with the candidate's DID-bound key.
3. **Verification.** The authority resolves the candidate's DID document, verifies
   the signature over the nonce against the published verification method,
   confirms the response came from the declared live surface, and, when a
   capability artifact is required, verifies that artifact under the protocol's
   own rules.
4. **Issuance.** Only on success does the authority mint the recognition
   credential, embedding the challenge nonce, a digest of the candidate's signed
   response, the probed surface locator, the verification-method identifier used,
   and the observation timestamp. The credential is chained to the root authority
   through the delegation the issuing authority already holds.

Because the embedded proof references the candidate's own DID and signed nonce, a
later verifier re-checks it without trusting the authority: resolve the candidate
DID, confirm the embedded response verifies under it, and confirm the nonce
matches. The recognition is thereby evidence that, at issuance, the holder
controlled the claimed key and served a conforming surface.

---

## 4. Prior Art Differentiation

Challenge-response authentication, proof-of-possession, domain-control
validation, and Verifiable Credential badges are each established prior art. This
disclosure does **not** claim those general mechanisms. What is differentiated is
their composition into a recognition primitive whose issuance proves live, keyed
integration:

- **Recognition bound to demonstrated capability rather than assertion.** Unlike
  an Open Badge, which is valid on the issuer's signature alone, this credential
  cannot be issued until the candidate proves a live keyed deployment, so the
  working system is a structural precondition of the badge.
- **Answered over the holder's own protocol surface with the DID-bound key.**
  Generic proof-of-possession or OIDC proves control of a key or account in the
  abstract. Here the response is served from the recognized deployment itself
  and, optionally, is a valid protocol artifact of the recognized type, so it
  proves that this deployment does the recognized thing.
- **Embedded, independently re-verifiable proof.** The challenge and signed
  response are carried in the issued credential, so the capability proof is
  re-checkable indefinitely against the candidate's DID. A manual review leaves
  no such artifact.
- **Chained to a delegated recognition authority.** The issuing key is a
  namespace-scoped delegate of a root authority, so the recognition traces to the
  root while the root key is never used for routine issuance.
- **Cross-language verification.** Challenge, response, and credential use the
  shared RFC 8785 JCS canonicalization and eddsa-jcs-2022 Data Integrity path, so
  the same proof verifies across language SDKs.

---

## 5. Technical Implementation

A reference implementation ships in the Python SDK. `build_integration_challenge`
returns a challenge object carrying a CSPRNG nonce, the expected live-surface
locator, and the required capability descriptor. The candidate answers with
`answer_integration_challenge`, which returns an eddsa-jcs-2022 signed object over
the JCS-canonical form of `{nonce, did, artifactDigest}`, signed by the
candidate's DID-bound key and served from the candidate's endpoint.
`verify_integration_response` resolves the candidate DID document (did:web or
did:key), verifies the signature against the published verification method,
checks the nonce, and, when required, verifies the returned protocol artifact.
The issuance path embeds a `ProofOfIntegration` block, holding the nonce, a
multibase digest of the signed response, the surface locator, the
verification-method identifier, and the observation time, in the recognition
credential's subject, alongside the delegation that chains it to the root
authority. Fetching the live surface is out of band; the embedded locator lets a
verifier re-probe.

---

## 6. Claims Summary

1. A method for issuing a recognition credential in which issuance is gated by a
   challenge-response that proves the candidate operates a live deployment holding
   the key bound to its claimed decentralized identifier.
2. The method of claim 1 wherein the candidate answers the challenge through its
   own published protocol surface, and the authority verifies the signed response
   against the candidate's resolved DID document before issuing.
3. The method of claim 1 wherein the challenge requires the candidate to return a
   valid protocol artifact of the type the credential attests, so the credential
   proves the deployment performs the recognized function.
4. The method of claim 1 wherein the challenge nonce, a digest of the signed
   response, and the live-surface locator are embedded in the issued credential,
   so the capability proof is independently re-verifiable against the candidate's
   DID after issuance.
5. The method of claim 1 wherein the issuing authority is a namespace-scoped
   delegate of a root authority, so the recognition chains to the root without the
   root key performing routine issuance.
6. The method of claim 1 wherein the challenge, response, and credential use
   canonicalization and signature primitives shared across language SDKs, so the
   same proof verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem.
