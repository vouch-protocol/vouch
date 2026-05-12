# PAD-041: Algorithm-Agnostic Verification Method Resolution via Multikey Multicodec Discrimination

**Identifier:** PAD-041
**Title:** Method for Zero-Coordination Algorithm Migration in Decentralized Agent Identity via Multikey Multicodec Discrimination
**Publication Date:** April 27, 2026
**Prior Art Effective Date:** April 27, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Decentralized Identity / Verification Method Resolution / Algorithm Migration / Multikey / Agent Identity
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-039 (JCS Multi-Party Trust State), PAD-040 (Hybrid Composite Signature Same-Bytes)

---

## 1. Abstract

A method for resolving the verification algorithm of a Decentralized
Identifier's signing key directly from the key's encoding, without
out-of-band agreement, JOSE `alg` header negotiation, or protocol
version coordination. The method uses Multikey
(multibase + multicodec) such that the first two bytes after the
multibase prefix unambiguously identify the cryptographic algorithm. A
verifier reads the prefix, selects the algorithm, and proceeds.
Algorithm migration (Ed25519 -> ML-DSA-44 -> any future post-quantum)
becomes a key-publication event, not a protocol-version-bump event.

This eliminates a class of failures common to JOSE-based identity
systems where issuers and verifiers must agree on the `alg` header
value out-of-band, and where introducing a new algorithm requires
versioning the protocol or extending the registry of accepted
algorithm identifiers in every verifier.

## 2. Problem Statement

Conventional digital signature verification requires the verifier to
know which algorithm to apply. The verifier learns this from one of:

- A protocol-level constant (the verifier hardcodes "always Ed25519").
- A signed envelope header (e.g., JOSE `alg`, X.509 `signatureAlgorithm`).
- An accept-list configured per-issuer.

When migrating to a new algorithm (e.g., post-quantum), each of these
mechanisms requires coordination:

- Hardcoded algorithm: requires verifier code change and redeployment.
- Signed envelope header: requires the verifier to accept and validate
 the new header value. Algorithm-confusion attacks are a known class
 of vulnerability when verifiers blindly trust the header.
- Accept-list per issuer: requires operational coordination per issuer
 per migration phase.

None of these are zero-coordination. All require the verifier to be
told, somehow, that a new algorithm is now in scope.

## 3. The Novel Mechanism

### 3.1 Multikey-Encoded Verification Methods

Every verification method in a DID Document is encoded as Multikey:

```
publicKeyMultibase = "z" + base58btc(multicodec_prefix || raw_key_bytes)
```

The 2-byte multicodec prefix is the algorithm identifier:

| Algorithm | Multicodec Prefix | Raw Key Length |
|---|---|---|
| Ed25519 (public) | `0xed01` | 32 bytes |
| Secp256k1 (public) | `0xe701` | 33 bytes |
| P-256 (public) | `0x1200` | 33 bytes |
| ML-DSA-44 (public) | `0x1207` | 1,312 bytes |
| ML-DSA-65 (public) | (registered) | 1,952 bytes |
| ML-DSA-87 (public) | (registered) | 2,592 bytes |

The verifier:

1. Reads the verification method's `publicKeyMultibase` from the DID
  Document.
2. Decodes the multibase prefix (`z` -> base58btc).
3. Reads the first 2 bytes of the decoded payload.
4. Looks up the algorithm in a table.
5. Uses the remaining bytes as the algorithm-specific public key.
6. Runs the algorithm's verification function.

There is no `alg` header in the proof, no version negotiation, no
out-of-band coordination. The signing algorithm and the verification
algorithm are defined by the key encoding itself.

### 3.2 Zero-Coordination Algorithm Migration

A regulated agent issuer migrates from Ed25519 to ML-DSA-44 by:

1. Generating a new ML-DSA-44 keypair.
2. Publishing the new public key in the DID Document as a Multikey
  verification method (`#key-2`).
3. Issuing future credentials that point at `#key-2` in their `proof.
  verificationMethod` field.

Verifiers that already implement ML-DSA-44 begin verifying immediately,
without any coordination. Verifiers that have not yet implemented
ML-DSA-44 see the unrecognized multicodec prefix and reject the
credential as "unsupported algorithm" (a fail-secure behavior).

The issuer's existing Ed25519 verification method (`#key-1`) remains
published. Credentials issued before the migration continue to verify.
Credentials issued during the migration window can use either key, and
verifiers that support both algorithms accept either.

### 3.3 Algorithm-Confusion Attack Surface Removed

In JOSE-based systems, algorithm-confusion attacks (the verifier is
tricked into using the wrong algorithm by manipulating the `alg`
header) are a recurring class of vulnerability. The `alg=none`
attack and HMAC-vs-RSA confusion are well-documented.

In Multikey-based verification, the algorithm is not declared in the
proof envelope. It is intrinsic to the key encoding. An attacker
cannot manipulate a header to coerce algorithm selection; doing so
would require manipulating the DID Document itself (a much higher
bar, gated by DID resolution and TLS).

### 3.4 Comparison to Prior Approaches

| Mechanism | Algorithm declaration | New algorithm rollout | Algorithm-confusion attack surface |
|---|---|---|---|
| Hardcoded | Compile-time | Code release per verifier | None (algo not negotiable) |
| JOSE `alg` header | Per-message | Verifier accept-list update | High (header is attacker-controlled) |
| X.509 signatureAlgorithm | Per-cert | CA + verifier coordination | Medium |
| **Multikey multicodec (this disclosure)** | **Per-key, intrinsic** | **DID Document publication only** | **None (algo derived from key bytes)** |

## 4. Embodiments

**Embodiment 1: Hybrid post-quantum migration without verifier
coordination.** A regulated agent issuer publishes both an Ed25519
Multikey (`#key-1`) and an ML-DSA-44 Multikey (`#key-2`) in its DID
Document. Existing verifiers continue to verify Ed25519-bound
credentials. Newly-deployed verifiers with PQ support automatically
verify ML-DSA-44-bound credentials. No coordination is required.

**Embodiment 2: Heterogeneous verifier fleet with mixed algorithm
support.** An enterprise verifier fleet contains a mix of constrained
(Ed25519-only) and full-featured (Ed25519 + ML-DSA-44) nodes. The
issuer's hybrid `hybrid-eddsa-mldsa44-jcs-2026` credentials (per
PAD-040) carry both signatures over the same canonical bytes. Each
verifier's mode (Mode A, B, or C from PAD-040) is selected by the
verifier's local Multikey support.

**Embodiment 3: Forward compatibility for new post-quantum algorithms.**
When ML-DSA-65 or any future post-quantum algorithm is registered with
a multicodec prefix, an issuer can publish a new Multikey verification
method without changing the protocol, the credential format, the proof
structure, or any wire-level convention. Verifiers gain support for
the new algorithm by adding a single entry to their multicodec lookup
table.

**Embodiment 4: Algorithm deprecation without breaking issued
credentials.** When an algorithm is deprecated (e.g., a specific
elliptic curve found weak), the issuer simply stops publishing the
corresponding Multikey verification method in its current DID Document.
Already-issued credentials remain verifiable against historical DID
Document snapshots, but no new credentials reference the deprecated key.

## 5. Non-Obviousness

The non-obvious element is the deliberate decision to remove algorithm
declaration from the message envelope entirely and place it in the key
encoding. Prior identity systems treat the algorithm as a property of
the message, declared per-signature. This disclosure treats the
algorithm as a property of the key, declared once per public-key
publication. The downstream effects (zero-coordination migration,
elimination of algorithm-confusion attack surface, forward
compatibility) follow from this single architectural decision and are
not obvious from the prior art. Combined with Data Integrity (where
the cryptosuite identifier in the proof maps the proof's structural
expectations) and the same-bytes hybrid construction (PAD-040), the
result is an identity verification surface that admits algorithm
migration as a routine key-rotation event.

## 6. Disclaimer

This disclosure is published as defensive prior art under the Apache
2.0 License. It is intended to prevent assertion of patents covering
the disclosed mechanism. The author claims no exclusive rights to the
described invention.

---

*Published as prior art to ensure ecosystem freedom for zero-coordination
post-quantum migration in decentralized agent identity.*
