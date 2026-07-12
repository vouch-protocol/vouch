# PAD-073: Liveness-Conformance-Decaying Recognition Credential with Automatic Revocation

**Identifier:** PAD-073  
**Title:** Method for a Recognition or Reputation Credential Whose Consumable Trust Continuously Decays as a Function of Elapsed Time Since the Last Independently Verified Liveness-Conformance Observation of the Holder's Deployment, With Signed Conformance Receipts That Make the Decay Recomputable and Automatic Revocation When Conformance Lapses Beyond a Threshold  
**Publication Date:** July 3, 2026  
**Prior Art Effective Date:** July 3, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Agent Accountability / Reputation / Verifiable Credentials / Revocation  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-016 (Heartbeat), PAD-030 (ZK Reputation Portability), PAD-032 (Cryptographic Mortality), PAD-036 (Aggregated Reputation Scoring via Verifiable State Receipts), PAD-071 (Commit-Before-Outcome Verdict Credential), PAD-072 (Proof-of-Integration Recognition Credential)  

---

## 1. Abstract

A point-in-time recognition or reputation credential stays valid after the
recognized system goes offline, stops conforming, or is decommissioned, so the
trust it displays becomes stale. This method binds a credential's consumable
trust to a continuously updated liveness-conformance signal. An automated prober
periodically checks the holder's live surface against published conformance
criteria and emits a signed conformance receipt per observation. The credential
carries a decay function and its parameters (for example a half-life) and the
time of last confirmed conformance. At read time the consumable trust is computed
as a function of elapsed time since that last confirmed conformance, so a
credential no longer backed by a live conforming deployment loses trust on its
own. When conformance lapses beyond a threshold, the credential is auto-revoked
through the status list. Because each observation is a signed receipt, the decay
is recomputable from evidence rather than asserted.

Key innovations:

- **Validity as a continuous function of third-party liveness-conformance.** The
  trust a verifier consumes is not a stored constant but a value computed from how
  recently the holder's deployment was independently observed to still conform.
- **Recomputable decay from signed conformance receipts.** Each probe emits a
  signed receipt, so any verifier can reconstruct the decay curve from evidence
  rather than trust a displayed number.
- **Conformance-lapse-driven automatic revocation.** Revocation is triggered by
  the failure of continuous external conformance, not by a manual event, so a
  quietly dead deployment loses its credential without anyone filing a revocation.
- **Probe over the holder's own surface using the protocol's own conformance
  test.** The liveness signal is a re-run of the same conformance the credential
  attests, against the holder's declared endpoint, so decay tracks the exact
  property recognized.

---

## 2. Problem Statement

### 2.1 A badge outlives the thing it certifies

A recognition credential issued once remains cryptographically valid even after
the recognized deployment stops responding or stops conforming. A reader sees a
valid badge for a system that no longer works.

### 2.2 Revocation is event-driven and manual

Certificate revocation lists, OCSP, and status lists flip on an explicit event
that some party must initiate. Nobody files a revocation because a site quietly
went dark, so stale recognition persists.

### 2.3 A displayed score is asserted, not evidenced over time

A trust value stored in or alongside a credential is a number a reader must
trust. Without periodic, signed, independent observation, there is no evidence
that the recognized property still holds.

---

## 3. Solution (The Invention)

1. **Conformance criteria and prober.** The credential names the conformance
   criteria and the holder's live surface. An automated prober, run by a neutral
   party, periodically re-checks the surface against those criteria, reusing the
   protocol's own conformance test.
2. **Signed conformance receipt.** Each observation produces a signed
   `ConformanceReceipt` binding the holder, the surface, the criteria, the
   observed result, and the time. Receipts are appended to a recomputable log so a
   verifier can replay the observation history.
3. **Embedded decay function.** The credential carries a decay function and its
   parameters (for example a half-life) and the time of last confirmed
   conformance.
4. **Read-time trust.** A verifier computes consumable trust as a function of
   elapsed time since the last confirmed-conformance receipt, so the value falls
   automatically as observations age and rises again when a fresh passing receipt
   arrives.
5. **Automatic revocation on lapse.** When conformance fails, or no passing
   receipt arrives, for longer than a configured threshold, the credential is
   revoked through the status list, so it reads as revoked and not merely
   low-trust.

The liveness cadence reuses the heartbeat mechanism, the decay reuses the
state-verifiability trust-entropy model, and the receipts are the same verifiable
state receipts that aggregated reputation already consumes, so the same evidence
feeds both a live decay and an aggregate score.

---

## 4. Prior Art Differentiation

Certificate monitoring, revocation lists, credential renewal, and reputation
scoring from receipts are each established prior art. This disclosure does **not**
claim them generally. What is differentiated is binding a recognition credential's
validity to continuous third-party liveness-conformance:

- **Decay on liveness lapse rather than detection of mis-issuance.** Certificate
  Transparency and monitoring detect that a bad certificate exists. They do not
  make a credential's trust fall because the recognized deployment stopped
  conforming.
- **Revocation driven by conformance lapse rather than an explicit event.** CRL,
  OCSP, and status lists revoke when a party acts. Here revocation is the
  automatic consequence of failed or absent continuous conformance.
- **Computed decay rather than re-issuance.** Heartbeat renewal (PAD-016) keeps a
  credential fresh by re-signing it. Here the credential's own trust is a computed
  function of externally observed conformance over time, and lapse triggers
  revocation rather than expiry.
- **Receipts of a specific deployment's liveness-conformance.** Aggregated
  reputation (PAD-036) scores from state receipts in general. Here the receipts
  are liveness-conformance observations of the exact deployment the credential
  recognizes, and they drive both the decay and the revocation of that credential.
- **Recomputable trust.** Because the decay is reconstructable from signed
  receipts, the trust shown is evidence a verifier can replay, not an asserted
  number.

---

## 5. Technical Implementation

A reference implementation ships in the Python SDK. A prober loop re-runs the
conformance check (or a surface probe) against the holder's declared endpoint and
emits a `ConformanceReceipt`, an eddsa-jcs-2022 credential signed by the prober
authority, appended to the holder's record through the existing Merkle-backed
log. `consumable_trust(record, at_time)` computes the decayed value using the
existing trust-entropy half-life over the elapsed time since the last passing
receipt. A configured lapse threshold triggers a `build_status_list_entry`
revocation through the existing BitstringStatusList path. The probe cadence
reuses the heartbeat scheduler, and receipts share the JCS canonicalization and
signature primitives used across the SDK, so the same receipts verify
cross-language and can be consumed by aggregated reputation.

---

## 6. Claims Summary

1. A method for a recognition or reputation credential whose consumable trust is
   computed as a function of elapsed time since the last independently verified
   liveness-conformance observation of the holder's deployment.
2. The method of claim 1 wherein an automated prober periodically checks the
   holder's live surface against published conformance criteria and emits a signed
   conformance receipt for each observation.
3. The method of claim 2 wherein the decay of consumable trust is recomputable by
   a verifier from the signed conformance receipts.
4. The method of claim 1 wherein the credential is automatically revoked through a
   status list when conformance fails, or no passing observation arrives, for
   longer than a configured threshold.
5. The method of claim 1 wherein the credential embeds the decay function, its
   parameters, and the time of last confirmed conformance.
6. The method of claim 1 wherein the liveness signal reuses the protocol's own
   heartbeat cadence and conformance test, and the receipts share canonicalization
   and signature primitives across language SDKs so they verify cross-language and
   feed aggregated reputation.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem.
