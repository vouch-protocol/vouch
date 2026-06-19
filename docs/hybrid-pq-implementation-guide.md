# Hybrid Post-Quantum Profile: Implementation Guide

> Optional v1.6+ profile. Default deployments use `eddsa-jcs-2022`. Use
> the hybrid profile when your deployment is regulated under NIST
> CNSA 2.0, U.S. NSM-10, CNSSP-15, or a similar mandate that requires
> quantum-resistant signatures, or when the credentials you issue today
> may be litigated decades into the future (insurance, capital markets,
> clinical trials, government contracts).

## What it is

`hybrid-eddsa-mldsa44-jcs-2026` is a Data Integrity cryptosuite
that signs every Vouch Credential with **both** Ed25519 (classical)
and ML-DSA-44 (post-quantum) over the **same** JCS-canonicalized
bytes. A verifier can require both signatures to validate, only
Ed25519 (classical-only deployment), or only ML-DSA-44 (post-quantum
mandated), all without re-issuing the credential.

The technical novelty is the same-bytes property documented in
[PAD-040](./disclosures/PAD-040-hybrid-composite-signature-same-canonical-bytes.md):
a single SHA-256 of the canonical credential is signed by both
algorithms, eliminating the bind-each-algorithm-to-different-
serialization attack surface that other PQ/T composite drafts permit.

## When to use it

| Deployment type | Recommendation |
|---|---|
| Public web app, low-stakes agent | `eddsa-jcs-2022` (default) |
| Healthcare AI accessing PHI | Hybrid recommended |
| Banking or capital markets agents | Hybrid recommended |
| EU AI Act high-risk system | Hybrid recommended |
| Insurance claims authorization | Hybrid required for long-tail liability |
| FDA SaMD / clinical trials | Hybrid required for 21 CFR Part 11 long retention |
| Government / federal contracts | Required by CNSA 2.0 / NSM-10 timeline |
| IoT / edge devices | Default, hybrid only if mandated |

## Dependency setup

### Python

```bash
pip install vouch-protocol[pq]
```

The `[pq]` extra installs `pqcrypto`, which provides ML-DSA-44 keypair
generation, signing, and verification. The default `vouch-protocol`
install does NOT include this dependency.

### TypeScript

```bash
npm install vouch-protocol @noble/post-quantum
```

`@noble/post-quantum` (by Paul Miller, the same author as
`@noble/curves`) is a pure-JavaScript ML-DSA-44 implementation
suitable for browser and Node.js.

### Go

The Go sidecar uses `github.com/cloudflare/circl/sign/mldsa/mldsa44`,
which is already a transitive dependency via
`github.com/cloudflare/circl`. No additional install is required.

## Issuing a hybrid credential

### Python

```python
from vouch import Signer

signer = Signer(private_key=jwk_str, did="did:web:agent.example.com")

# Issue under the hybrid profile. The signer transparently generates
# the ML-DSA-44 keypair if one is not already provisioned.
credential = signer.sign_credential_hybrid(intent={
  "action": "submit_clinical_finding",
  "target": "trial:NCT00000001",
  "resource": "https://fda-submissions.example.com/api/findings",
})

# The credential's proof.cryptosuite is "hybrid-eddsa-mldsa44-jcs-2026".
# proof.proofValue is the multibase-encoded concatenation of the
# Ed25519 signature (64 bytes) and the ML-DSA-44 signature (2,420 bytes).
```

### TypeScript

```typescript
import { Signer, generateMLDSA44KeyPair } from 'vouch-protocol';

const mldsaKeys = await generateMLDSA44KeyPair();
const signer = new Signer({ privateKey, did, mldsa44: mldsaKeys });

const credential = await signer.signCredentialHybrid({
 intent: {
  action: 'submit_clinical_finding',
  target: 'trial:NCT00000001',
  resource: 'https://fda-submissions.example.com/api/findings',
 },
});
```

### Go

```go
import "github.com/vouch-protocol/vouch/go-sidecar/signer"

s, _ := signer.New(signer.Config{
  DID: "did:web:agent.example.com",
  Ed25519Seed: ed25519Seed, // 32-byte seed
})

cred, _ := s.SignCredentialHybrid(signer.SignCredentialOptions{
  Intent: map[string]any{
    "action": "submit_clinical_finding",
    "target": "trial:NCT00000001",
    "resource": "https://fda-submissions.example.com/api/findings",
  },
})
```

## Three verifier modes

A receiving service chooses one of three verification modes. The same
issued credential satisfies all three, depending on the verifier's
local policy.

### Mode A: classical-only (Ed25519 only)

For verifiers that have not yet deployed ML-DSA-44 verification logic.
Splits the proofValue at byte 64, takes the first 64 bytes as the
Ed25519 signature, ignores the ML-DSA-44 portion.

```python
# Python
is_valid, passport = Verifier.verify_credential(
  credential,
  public_key=ed25519_public_key,
  hybrid_mode="classical_only",
)
```

### Mode B: post-quantum only (ML-DSA-44 only)

For verifiers operating under regulatory mandate that no longer
accepts classical signatures. Splits the proofValue at byte 64, takes
the remaining 2,420 bytes as the ML-DSA-44 signature, ignores the
Ed25519 portion.

```python
is_valid, passport = Verifier.verify_credential(
  credential,
  public_key=mldsa44_public_key,
  hybrid_mode="pq_only",
)
```

### Mode C: both required (default for regulated)

The default for regulated deployments. Both signatures must validate
against the same canonical bytes for the credential to be accepted.

```python
is_valid, passport = Verifier.verify_credential(
  credential,
  public_key=(ed25519_public_key, mldsa44_public_key),
  hybrid_mode="both_required",
)
```

## DID Document for hybrid agents

A hybrid-issuing agent publishes both keys in its DID Document:

```json
{
 "@context": [
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/multikey/v1"
 ],
 "id": "did:web:agent.example.com",
 "verificationMethod": [
  {
   "id": "did:web:agent.example.com#key-1",
   "type": "Multikey",
   "controller": "did:web:agent.example.com",
   "publicKeyMultibase": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
  },
  {
   "id": "did:web:agent.example.com#key-2",
   "type": "Multikey",
   "controller": "did:web:agent.example.com",
   "publicKeyMultibase": "zM<...long base58btc string for ML-DSA-44, ~1.8 KB...>"
  }
 ],
 "authentication": ["did:web:agent.example.com#key-1", "did:web:agent.example.com#key-2"],
 "assertionMethod": ["did:web:agent.example.com#key-1", "did:web:agent.example.com#key-2"]
}
```

The `proof.verificationMethod` field of the credential points at
`#key-1`. The verifier infers from the `cryptosuite` field that
`#key-2` is the corresponding ML-DSA-44 verification method.

## Performance and size considerations

| Property | `eddsa-jcs-2022` | `hybrid-eddsa-mldsa44-jcs-2026` |
|---|---|---|
| Ed25519 signature size | 64 bytes | 64 bytes |
| ML-DSA-44 signature size | 0 | 2,420 bytes |
| `proofValue` length (multibase z-prefix) | ~88 chars | ~3,375 chars |
| ML-DSA-44 public key size | 0 | 1,312 bytes |
| Multikey-encoded public key | ~48 chars | ~1,800 chars (ML-DSA-44 entry) |
| Sign latency (Python, M2 Mac) | ~150 microseconds | ~3 milliseconds |
| Verify latency (Python, M2 Mac) | ~250 microseconds | ~5 milliseconds |
| Total credential size (typical) | ~700 bytes | ~3,200 bytes |

The hybrid profile credentials exceed typical HTTP header size
budgets. **Always transmit hybrid credentials in the HTTP request
body** with `Content-Type: application/vc+vouch` (the prior
`application/vouch+credential+json` form is retained as a transitional
alias for backward compatibility). Header transport is not supported
for the hybrid profile.

## Migration path within the hybrid profile

| Phase | Issuer | Verifier |
|---|---|---|
| Today | Ed25519 only (`eddsa-jcs-2022`) | Mode A only |
| Next 6 months | Hybrid optional | Mode A or Mode C, configurable |
| 2027+ | Hybrid recommended for regulated | Mode C default for regulated |
| 2030+ | Hybrid required by NIST CNSA 2.0 phase 2 | Mode C universal |
| Future | Hybrid or ML-DSA-44-only (`mldsa44-jcs-2026`) | Mode C transitions to Mode B |

A credential issued today under the hybrid profile remains verifiable
through every phase of this migration without re-issuance.

## Cross-implementation interop

The cross-implementation interop test vector lives at
[`test-vectors/hybrid-eddsa-mldsa44/vector.json`](../test-vectors/hybrid-eddsa-mldsa44/vector.json).
A conforming Python, TypeScript, or Go implementation MUST verify the
included signed credential against the published Ed25519 and ML-DSA-44
public keys.

The vector exercises all three verification modes (classical-only,
PQ-only, both-required) and includes a tamper test confirming both
signatures fail when any byte of the canonical form is mutated.

## References

- [PAD-040: Hybrid Composite Signature Bound to Same Canonical Bytes](./disclosures/PAD-040-hybrid-composite-signature-same-canonical-bytes.md)
- [PAD-041: Algorithm-Agnostic Verification Method Resolution](./disclosures/PAD-041-multikey-algorithm-agnostic-verification.md)
- [PAD-033: ZK PQ Signature Compression](./disclosures/PAD-033-zk-pq-signature-compression.md)
- [PAD-035: Async Chunked Edge PQ Signatures](./disclosures/PAD-035-async-chunked-edge-pq-signatures.md)
- [Specification §13: Crypto-Agility and Quantum-Safe Profile](./specs/w3c-cg-report.md#13-crypto-agility-and-quantum-safe-profile)
- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST CNSA 2.0 announcement](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3608111/)
- [U.S. National Security Memorandum 10 (NSM-10)](https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/)
