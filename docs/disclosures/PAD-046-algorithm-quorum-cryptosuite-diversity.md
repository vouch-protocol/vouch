# PAD-046: Algorithm Quorum Verification via M-of-N Cryptosuite Diversity

**Identifier:** PAD-046
**Title:** Method for Defending AI Agent Identity Against Algorithm-Specific Compromise via M-of-N Diversity Across Independent Cryptographic Algorithms
**Publication Date:** April 29, 2026
**Prior Art Effective Date:** April 29, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Post-Quantum Cryptography / Algorithm Diversity / Threat Resilience / Defense in Depth / Agent Identity
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-040 (Same-Bytes Hybrid Composite Signature), PAD-041 (Multikey Algorithm-Agnostic Verification), PAD-043 (Cryptographic Weight Binding)

---

## 1. Abstract

A method for defending an AI agent's cryptographic identity against
algorithm-specific zero-day compromise by binding the same logical
identity to **M signatures from N distinct, independent cryptographic
algorithm families**, where M ≤ N. A verifier requires at least M of
the N signatures to validate. Even if a future cryptanalytic breach
fully compromises one or more algorithm families, the agent's
identity remains valid as long as M independent algorithms remain
unbroken.

This generalizes the hybrid composite construction of PAD-040 (Ed25519
+ ML-DSA-44, fixed at 2-of-2) to an M-of-N quorum construction where
the algorithm panel can include lattice-based, hash-based, code-based,
isogeny-based, and classical elliptic-curve schemes. The mechanism
provides genuine *defense in depth* against the failure mode where a
single algorithm family proves unsafe.

The mechanism is published openly so that algorithm diversity remains
available to every agent identity deployment, not gated behind
vendor-specific signing infrastructure.

## 2. Problem Statement

The current Vouch base profile (`eddsa-jcs-2022`) and the hybrid
post-quantum profile (`hybrid-eddsa-mldsa44-jcs-2026`) provide strong
guarantees under the assumption that Ed25519 is classically secure
and ML-DSA-44 is post-quantum secure. Both algorithms are currently
believed safe.

History shows that "currently believed safe" is a moving target:

- **MD5** was widely deployed for over a decade before practical
  collision attacks emerged in 2004.
- **SHA-1** was the standard for digital signatures until practical
  attacks were demonstrated in 2017.
- **SIDH/SIKE**, a post-quantum candidate, was broken in 2022 in
  hours of CPU time after years of NIST consideration.
- **CECPQ2** (Cloudflare's hybrid TLS) had to be deprecated when
  Saber was withdrawn from NIST round 3.

Even ML-DSA-44, the current NIST post-quantum signature standard,
could in principle be broken by future cryptanalysis. If Vouch
agents are deployed under the hybrid 2-of-2 profile and ML-DSA-44 is
later found unsafe, every deployed credential reverts to Ed25519-only
security, which itself becomes invalid post-quantum.

What is needed is a mechanism where the agent's identity does not
catastrophically fail under any single algorithm break, but instead
**degrades gracefully** as long as M independent algorithm families
remain secure.

## 3. The Novel Mechanism

### 3.1 The Algorithm Quorum Construction

An agent's verification method publishes N independent Multikey
verification methods, each backed by a distinct algorithm family:

```json
{
  "id": "did:web:agent.example.com",
  "verificationMethod": [
    { "id": "...#key-ed25519", "type": "Multikey",
      "publicKeyMultibase": "z6Mk..." },        // Curve25519 ECDSA
    { "id": "...#key-mldsa44", "type": "Multikey",
      "publicKeyMultibase": "zM..." },           // Lattice (FIPS 204)
    { "id": "...#key-slhdsa128s", "type": "Multikey",
      "publicKeyMultibase": "zSl..." },          // Hash-based (FIPS 205)
    { "id": "...#key-falcon512", "type": "Multikey",
      "publicKeyMultibase": "zF..." },           // Lattice-NTRU (FN-DSA)
    { "id": "...#key-bls12-381", "type": "Multikey",
      "publicKeyMultibase": "zB..." }            // Pairing-based BLS
  ],
  "vouchAlgorithmQuorum": {
    "M_required": 3,
    "N_total": 5,
    "algorithm_family_constraint": true
  }
}
```

The `M_required` and `N_total` parameters define the quorum. The
`algorithm_family_constraint` flag, when true, requires that the M
satisfying signatures come from M *distinct algorithm families* (not
just M instances of the same algorithm family with different keys).

### 3.2 Algorithm Family Taxonomy

For the purposes of the diversity constraint, algorithm families are:

| Family | Examples | Hardness assumption |
|---|---|---|
| Elliptic curve | Ed25519, ECDSA P-256, secp256k1 | Discrete log on curves |
| Pairing-based | BLS12-381 | Bilinear pairing problems |
| Lattice (Module-LWE) | ML-DSA-44/65/87 | Module Learning With Errors |
| Lattice (NTRU) | Falcon (FN-DSA) | NTRU lattice problems |
| Hash-based | SLH-DSA (SPHINCS+) | One-way hash functions |
| Code-based | Classic McEliece (key encap), HQC | Decoding random linear codes |
| Isogeny-based | (none currently in NIST signature track) | Supersingular isogeny problems |

A break in one family does not cascade to others. Hash-based schemes
in particular rely only on hash function security, which is the
weakest assumption that survives quantum attack.

### 3.3 Cryptosuite Identifier

The new cryptosuite identifier is constructed parametrically:

```
quorum-{M}of{N}-{algorithm_family_codes}-jcs-2026
```

Examples:

- `quorum-2of3-edmldsahash-jcs-2026`: Ed25519 + ML-DSA-44 + SLH-DSA, 2-of-3 required
- `quorum-3of5-edmldsahashfalconbls-jcs-2026`: 5 algorithms, 3 required
- `quorum-2of2-edmldsa-jcs-2026`: equivalent to existing PAD-040 hybrid

### 3.4 Signing Procedure

Issuance under the quorum profile produces M signatures over the
**same** JCS-canonicalized credential bytes (preserving the
same-bytes property of PAD-040):

1. Build the credential with unsigned proof (cryptosuite name encodes
   M, N, and the algorithm family list).
2. JCS-canonicalize.
3. SHA-256 once. (For hash-based schemes with their own internal hash,
   the same SHA-256 digest is used as the message input.)
4. Sign the digest under M algorithms (out of N available), each
   producing a signature in its native format.
5. Assemble the proofValue as a length-prefixed concatenation:

```
proofValue = "z" + base58btc(
    1 byte:  M_required
    1 byte:  N_total
    For each of M signatures present:
        1 byte:  algorithm_family_code
        2 bytes: signature_length (big-endian)
        signature_bytes
)
```

The length-prefix structure allows the verifier to skip unknown or
unsupported algorithm family codes, supporting forward compatibility.

### 3.5 Verification Procedure

A verifier reads the M_required and N_total parameters from the
proofValue, then iterates the included signatures:

1. For each signature, look up the algorithm family code, the
   corresponding verification method in the DID Document, and the
   verification function.
2. Verify the signature against the SHA-256 digest of the canonical
   credential.
3. Count successful verifications.
4. Accept the credential iff at least M_required signatures verify.

The verifier MAY enforce a stricter local policy (e.g., "for
healthcare workloads, require at least one lattice-based plus one
hash-based signature to verify") by examining the included algorithm
family codes.

### 3.6 Graceful Degradation Property

If algorithm family X is later compromised, deployments simply lower
their effective trust on signatures from family X. As long as M-1
other family signatures verify, the credential remains accepted. The
issuer can rotate to a new algorithm family at the next credential
issuance without re-issuing prior credentials.

### 3.7 Post-Compromise Recovery

If algorithm X is publicly broken at time T, all credentials issued
before T under a quorum that included X retain their other M-1
signatures, which still hold. The issuer publishes an updated DID
Document removing X's verification method and adding a new family Y.
Future credentials are issued under M-of-N including Y. Past
credentials remain verifiable under the (M-1) remaining algorithms,
preserving non-repudiation across the algorithm-break event.

## 4. Embodiments

**Embodiment 1: Critical infrastructure deployment.** A power grid
control agent issues credentials under
`quorum-3of5-edmldsahashfalconbls-jcs-2026`. The agent's identity
remains valid even if any two of the five algorithm families are
later broken. Operations continue without re-issuance.

**Embodiment 2: Long-retention insurance contracts.** An insurance
underwriting agent issues credentials under
`quorum-2of3-edmldsahash-jcs-2026`. A claim filed in 2055 against a
2026 underwriting decision verifies even if Ed25519 or ML-DSA-44 is
broken in the intervening decades, because SLH-DSA (hash-based) is
quantum-secure as long as SHA-256 is.

**Embodiment 3: Algorithm-rotation research.** A research agent
issues all credentials under a wide quorum (5-of-7 or higher) so
that researchers studying algorithm-specific cryptanalysis have
ground-truth credentials they can test against partial breaks
without risking the agent's identity.

**Embodiment 4: Defense-in-depth verifier policy.** A regulated
verifier accepts any quorum credential where at least one signature
is hash-based (post-quantum and conservative). The issuer publishes
under N=5 with one hash-based slot, allowing the issuer to satisfy
both regulated and non-regulated verifiers from a single credential
issuance.

## 5. Non-Obviousness

Existing approaches to algorithm diversity in digital signatures fall
into three categories:

1. **Single-algorithm with rotation**: keys rotated periodically;
   does not survive an algorithm break, only key compromise.
2. **Hybrid composite (2-of-2)**: PAD-040 and IETF JOSE composite
   drafts; both signatures must verify, no graceful degradation.
3. **Threshold within single algorithm**: M-of-N keys, but all keys
   are the same algorithm; does not survive an algorithm break.

The non-obvious elements are:

1. **M-of-N across distinct algorithm families.** Prior threshold
   schemes operate within a single algorithm. This disclosure
   requires the M satisfying signatures to come from M *different
   algorithm families*, providing genuine defense-in-depth.

2. **Length-prefixed proofValue structure for forward compatibility.**
   Verifiers skip unknown algorithm codes gracefully, allowing new
   algorithm families to be added to the panel without breaking
   existing verifiers.

3. **Family-aware verifier policies.** A verifier can enforce
   stricter local policies than the issuer's M_required minimum,
   e.g., requiring at least one hash-based family to verify, without
   coordination with the issuer.

4. **Same-bytes preservation.** All M signatures sign the same
   JCS-canonicalized credential bytes (preserving PAD-040's
   same-bytes property), so the M signatures all attest to the same
   logical credential rather than M parallel variants.

The combination is non-obvious relative to:

- IETF `draft-ietf-jose-pq-composite-sigs` (fixed 2-of-2, no family
  diversity requirement).
- PAD-040 (fixed 2-of-2 Ed25519 + ML-DSA-44 hybrid).
- Threshold signature schemes (M-of-N within single algorithm).
- TLS cipher-suite negotiation (algorithm selected per-session, no
  multi-signature attestation).

## 6. Disclaimer

This disclosure is published as defensive prior art under the Apache
2.0 License. It is intended to prevent assertion of patents covering
the disclosed mechanism. The author claims no exclusive rights to the
described invention. The mechanism is published openly because the
ability to defend agent identity against algorithm-specific zero-day
compromise should be available to every regulated deployment, not
gated behind any commercial signing infrastructure.

---

*Published as prior art to ensure that algorithm-quorum defense in
depth remains available to every AI agent identity deployment.*
