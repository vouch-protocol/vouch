# PAD-040: Hybrid Composite Signature Bound to Same Canonical Bytes (Ed25519 + ML-DSA-44 over JCS)

**Identifier:** PAD-040
**Title:** Method for Hybrid Classical/Post-Quantum Composite Digital Signatures Where Both Signatures Are Computed Over Identical Canonical Bytes for Graceful Verifier Downgrade
**Publication Date:** April 27, 2026
**Prior Art Effective Date:** April 27, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Post-Quantum Cryptography / Composite Signatures / Verifier Compatibility / Migration / Agent Identity
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-033 (ZK PQ Signature Compression), PAD-034 (Composite Threshold Swarm Consensus), PAD-035 (Async Chunked Edge PQ Signatures)

---

## 1. Abstract

A method for constructing hybrid classical/post-quantum digital signatures
in which both signature components (Ed25519 and ML-DSA-44) are computed
over **identical canonical bytes** of a W3C Verifiable Credential, rather
than over separately-hashed or separately-serialized variants of the same
logical payload. The cryptosuite identifier
`hybrid-eddsa-mldsa44-jcs-2026` defines the construction.

The same-bytes property enables three operationally critical verifier
behaviors that prior PQ/T composite signature designs do not provide:

1. **Graceful classical-only verification.** A verifier that has not yet
   deployed ML-DSA-44 verification logic can verify the Ed25519
   component in isolation, against the same canonical bytes, and obtain
   the same security guarantee as a classical-only deployment, without
   re-canonicalizing or re-issuing the credential.

2. **Graceful post-quantum-only verification.** A verifier that has
   migrated past Ed25519 (regulatory mandate, trust-store policy) can
   verify only the ML-DSA-44 component against the same canonical bytes.

3. **Both-required verification.** A regulated verifier requires both
   signatures to validate. The verifier hashes the canonical bytes once,
   runs both verification algorithms against the single hash, and accepts
   only on simultaneous success.

In all three cases, the verifier examines the same byte sequence. There
is no risk of payload divergence between the classical and post-quantum
proofs, eliminating an entire class of bind-each-algorithm-to-different-
serialization attacks.

## 2. Problem Statement

NIST CNSA 2.0, U.S. NSM-10, and CNSSP-15 require migration to
quantum-resistant signatures on phased timelines. Standardization efforts
(`draft-ietf-jose-pq-composite-sigs`, COSE composite drafts, X.509
composite drafts) have proposed hybrid PQ/T signatures, but the
predominant pattern is:

- **Sign each algorithm over its own hash.** The classical signature
  signs `H_classical(payload)` and the PQ signature signs
  `H_pq(payload)`, where the two hash functions or pre-image
  preparations may differ. This complicates downgrade and increases the
  protocol surface area.

- **Sign each algorithm over its own serialization.** The classical
  signature is computed over a JWS Compact payload and the PQ signature
  over a separately-encoded payload, requiring verifiers to handle two
  different byte representations of "the same" credential.

Both patterns make graceful verifier downgrade fragile: a verifier that
implements only one algorithm cannot independently verify because it
cannot reconstruct the other algorithm's signed bytes.

## 3. The Novel Mechanism

### 3.1 Same-Bytes Construction

The signing pipeline is:

```
1. Build credential as W3C VC (no proof yet).
2. Build unsigned proof object with cryptosuite =
   "hybrid-eddsa-mldsa44-jcs-2026".
3. Attach unsigned proof to credential.
4. Run JCS canonicalization (RFC 8785) once. Output: canonical bytes B.
5. Compute SHA-256 once: H = SHA-256(B).
6. Compute Ed25519 signature S_ed = Ed25519.Sign(privEd, H).
7. Compute ML-DSA-44 signature S_pq = ML-DSA-44.Sign(privPq, H).
8. Encode proof.proofValue =
   multibase("z" + base58btc(S_ed || S_pq)).
9. Replace proof.proofValue back into the credential.
```

Steps 6 and 7 take the **same** input H. There is no separate hash, no
separate canonicalization, no separate pre-image preparation per
algorithm.

### 3.2 Verification Modes

A verifier receives the credential and the multibase-encoded
`proofValue`. It splits the decoded bytes at the fixed Ed25519 length
(64 bytes), yielding `S_ed` (first 64 bytes) and `S_pq` (remaining 2,420
bytes). The verifier then:

- **Mode A (classical-only):** Decode H from the canonical form, run
  Ed25519.Verify(pubEd, H, S_ed). Accept on success.

- **Mode B (post-quantum-only):** Decode H from the canonical form,
  run ML-DSA-44.Verify(pubPq, H, S_pq). Accept on success.

- **Mode C (both required):** Run both, accept on simultaneous success.

The DID Document publishes both `pubEd` and `pubPq` as separate
Multikey-encoded `verificationMethod` entries. The verifier selects
Mode A, B, or C based on its own policy.

### 3.3 Graceful Migration Property

A protocol deployment can transition through these phases without
re-issuing credentials:

| Phase | Verifier behavior | Issuer behavior |
|---|---|---|
| Pre-PQ | Mode A (Ed25519 only) | `eddsa-jcs-2022` |
| Hybrid rollout | Mode A or C (deployments choose) | `hybrid-eddsa-mldsa44-jcs-2026` |
| PQ-mandated | Mode C, eventually Mode B | `hybrid-eddsa-mldsa44-jcs-2026` |
| Post-classical | Mode B | `mldsa44-jcs-2026` (classical fully retired) |

The same credential issued during the hybrid rollout phase is verifiable
by any of these verifier states without re-issuance, because all
verifiers operate over the same canonical bytes.

### 3.4 Comparison to Prior Approaches

| Pattern | Signs same bytes? | Graceful downgrade? | Verifier complexity |
|---|---|---|---|
| Per-algorithm hash | No | Hard | High |
| Per-algorithm serialization | No | Hard | High |
| **Same-bytes JCS (this disclosure)** | **Yes** | **Trivial** | **Low** |

## 4. Embodiments

**Embodiment 1: Cross-implementation hybrid signature.** The Python,
TypeScript, and Go implementations all canonicalize the credential
identically (per PAD-039), so a credential issued by the Go signer is
byte-identical to what the Python or TypeScript signer would have
produced for the same input. Verifiers in any language verify the same
hash.

**Embodiment 2: Regulated healthcare deployment.** A hospital deploys
a Mode C verifier required by HIPAA-aligned policy. Its agent vendors
issue `hybrid-eddsa-mldsa44-jcs-2026` credentials. As the post-quantum
migration deadline approaches, the hospital flips its verifier to Mode B
without requiring vendors to re-issue credentials.

**Embodiment 3: Edge device with limited PQ capacity.** A constrained
verifier (mobile, IoT) verifies in Mode A only. The same credentials
that satisfy the regulated hospital also satisfy the edge device, with
no additional issuance burden on the agent vendor.

**Embodiment 4: Forward compatibility for new PQ algorithms.** When
ML-DSA-65 or ML-DSA-87 is adopted, the same-bytes construction extends
naturally: the new cryptosuite identifier defines a new signature
component computed over the same canonical bytes. The verifier
infrastructure adds a new mode but does not re-canonicalize.

## 5. Non-Obviousness

Existing PQ/T composite signature drafts permit (and frequently
specify) per-algorithm hash or per-algorithm serialization variants.
The non-obvious element of this disclosure is the explicit choice to
constrain both signatures to share a single canonical input, sacrificing
some flexibility in algorithm-specific pre-image preparation in exchange
for trivial verifier downgrade and elimination of the bind-each-
algorithm-to-different-serialization attack class. The combination with
W3C Data Integrity (`eddsa-jcs-2022` cryptosuite as the structural
parent) and JCS canonicalization makes the same-bytes property
implementable across heterogeneous runtimes without ambiguity.

## 6. Disclaimer

This disclosure is published as defensive prior art under the Apache
2.0 License. It is intended to prevent assertion of patents covering
the disclosed mechanism. The author claims no exclusive rights to the
described invention.

---

*Published as prior art to ensure ecosystem freedom for hybrid post-quantum
agent identity migration.*
