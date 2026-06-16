# PAD-069: Confidential, Tamper-Evident Robot Black-Box with Separable Confidentiality and Integrity

**Identifier:** PAD-069  
**Title:** Method for a Robot Flight-Recorder Log Whose Entry Payloads Are Encrypted While the Log's Integrity Is Independently Verifiable Without the Decryption Key, with a Signable Chain Head Anchoring the Whole Log  
**Publication Date:** June 15, 2026  
**Prior Art Effective Date:** June 15, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Tamper-Evident Logging / Encrypted Audit / Verifiable Credentials  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-065 (Model and Config Provenance), PAD-068 (Kill-Switch Credential)  

---

## 1. Abstract

A method for a robot black-box (flight recorder) in which each event entry's
payload is encrypted with AES-256-GCM and hash-linked to the previous entry, so
the log is at once confidential and tamper-evident, and crucially the two
properties are **separable**: any party can verify the integrity of the entire
chain over the encrypted entries **without the decryption key**, while only a
holder of the black-box key can read the payloads. The current chain head can be
signed to anchor an arbitrarily long log to an identity and a point in time with
a single signature.

Key innovations:

- **Separable confidentiality and integrity.** Integrity verification (the hash
  chain over encrypted entries) requires no key; only reading a payload requires
  the key. A forensic investigator, regulator, or counterparty can prove the log
  was not altered without being given access to its sensitive contents.
- **Encrypted-yet-verifiable entries.** Each entry's hash is computed over the
  encrypted body (sequence number, timestamp, event label, ciphertext, and link
  to the prior entry), so tampering with the ciphertext, reordering entries, or
  dropping one is detected without ever decrypting.
- **Single-signature anchoring of the whole log.** Signing only the current chain
  head anchors every prior entry, so a long-running recorder does not need a
  signature per entry to be attributable and time-anchored.

---

## 2. Problem Statement

### 2.1 Robot logs must be both private and tamper-evident

A robot flight recorder captures operational data that is often sensitive
(proprietary sensor streams, internal state, customer-site detail) yet must be
trustworthy after an incident. Encrypting the log normally makes independent
integrity verification impossible without sharing the key; leaving it in
plaintext for verifiability exposes the sensitive content. These goals appear to
conflict.

### 2.2 Third parties cannot verify an encrypted log without the key

After an incident, an investigator or counterparty must be able to confirm "this
log was not altered" without the operator handing over a key that also reveals
everything in the log.

### 2.3 Anchoring a long log is expensive

Attributing and time-anchoring a long log typically requires a signature per
entry, or reliance on a trusted external logging service.

---

## 3. Solution (The Invention)

A `BlackBoxLog` holds a 32-byte key. Each `append(event, payload)`:

```
entry = {
  "version", "seq", "timestamp", "event",
  "ciphertext": multibase( nonce || AES-256-GCM(payload) ),
  "prevHash":  <entryHash of the previous entry, or genesis>,
}
entry["entryHash"] = multibase( SHA-256( JCS(entry without entryHash) ) )
```

Two independent operations follow:

1. **Integrity, no key required.** `verify_blackbox_chain(entries)` walks the
   entries checking sequence monotonicity, that each `prevHash` links to the prior
   `entryHash`, and that each `entryHash` recomputes over the (still encrypted)
   body. Any tampering, reordering, or omission fails. The verifier never needs
   the key.
2. **Confidentiality, key required.** `open_entry(entry, key)` decrypts a single
   payload. Only a key holder can read content.

The current `head()` hash can be signed with a Vouch signer (eddsa-jcs-2022) to
anchor the entire log to an identity and time in one signature. Because the chain
and anchor use the shared JCS plus SHA-256 primitives, they verify byte-identically
across the language SDKs.

---

## 4. Prior Art Differentiation

- **Tamper-evident / Merkle / append-only logs.** Provide integrity but generally
  over plaintext, or require the verifier to see the content. The present method
  verifies integrity over ciphertext, decoupled from read access.
- **Encrypted databases and WORM storage.** Provide confidentiality and
  append-only behavior but no portable, key-free integrity proof a third party can
  check independently.
- **Aircraft FDR/CVR.** Provide physical tamper resistance, not cryptographic
  proof, and no separable confidentiality/integrity for third parties.
- **PAD-068 (kill switch).** Shares the module and the credential format but
  addresses emergency-stop authorization, a distinct method.

---

## 5. Technical Implementation

A reference implementation provides `BlackBoxLog` (`append`, `head`, `entries`,
`open_entry`), the module-level `open_entry`, and `verify_blackbox_chain`, using
AES-256-GCM, multibase encoding, and the shared JCS plus SHA-256 hashing. This
ships the formats and reference library; hosted black-box storage and fleet-scale
infrastructure are out of scope and left to the deployer.

---

## 6. Claims Summary

1. A method for a robot event log wherein each entry's payload is encrypted and
   hash-linked to the prior entry, such that the integrity of the whole chain is
   verifiable without the decryption key.
2. The method of claim 1 wherein only a holder of the key can decrypt payloads, so
   confidentiality and integrity are separable properties of the same log.
3. The method of claim 1 wherein each entry's hash is computed over the encrypted
   entry body, so ciphertext tampering, reordering, or omission is detected without
   decryption.
4. The method of claim 1 wherein signing the current chain head anchors the entire
   log to an identity and time with a single signature.
5. The method of claim 1 wherein the chain and anchor use canonicalization and
   hashing primitives shared across language SDKs, so the log verifies
   cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the robotics community.
