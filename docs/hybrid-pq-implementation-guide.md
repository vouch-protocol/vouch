# Post-Quantum Profile: Implementation Guide

> Optional profile. Default deployments use `eddsa-jcs-2022`. Use the
> post-quantum profile when your deployment is regulated under NIST
> CNSA 2.0, U.S. NSM-10, CNSSP-15, or a similar mandate that requires
> quantum-resistant signatures, or when the credentials you issue today
> may be litigated decades into the future (insurance, capital markets,
> clinical trials, government contracts).

## What it is

The post-quantum profile of Vouch Protocol is a Data Integrity **proof set**.
The credential's `proof` is an array carrying two independent proofs:

| Cryptosuite | Algorithm | proofValue encoding |
|---|---|---|
| `eddsa-jcs-2022` | Ed25519 | base58btc multibase (`z`) |
| `mldsa44-jcs-2024` | ML-DSA-44 (FIPS 204) | base64url-nopad multibase (`u`) |

`mldsa44-jcs-2024` is the identifier from the W3C Quantum-Resistant
Cryptosuites work, and that specification is also where the base64url-nopad
proof value encoding comes from. The classical `eddsa-jcs-2022` suite is
specified separately and keeps base58btc.

Each proof is computed over the same unsecured document combined with its own
proof configuration, so each proof verifies on its own and a verifier that
understands one of the two cryptosuites can still check that proof. Both proofs
must verify for the credential to be accepted.

Credentials issued before this alignment keep verifying. The earlier
`mldsa44-jcs-2026` identifier and the earlier composite
`hybrid-eddsa-mldsa44-jcs-2026` proof, whose single `proofValue` concatenated
the two signatures, are both accepted on verification and are never emitted.

Binding both proofs to the same document is the property documented in
[PAD-040](./disclosures/PAD-040-hybrid-composite-signature-same-canonical-bytes.md):
an attacker cannot present a different serialization to one algorithm than to
the other.

## When to use it

| Deployment type | Recommendation |
|---|---|
| Public web app, low-stakes agent | `eddsa-jcs-2022` (default) |
| Healthcare AI accessing PHI | Post-quantum profile recommended |
| Banking or capital markets agents | Post-quantum profile recommended |
| EU AI Act high-risk system | Post-quantum profile recommended |
| Insurance claims authorization | Post-quantum profile required for long-tail liability |
| FDA SaMD / clinical trials | Post-quantum profile required for 21 CFR Part 11 long retention |
| Government / federal contracts | Required by CNSA 2.0 / NSM-10 timeline |
| IoT / edge devices | Default, post-quantum profile only if mandated |

## Dependency setup

### Python

```bash
pip install vouch-protocol[pq]
```

The `[pq]` extra installs `pqcrypto`, which provides ML-DSA-44 keypair
generation, signing, and verification.

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

## Issuing a post-quantum credential

### Python

```python
from vouch import Signer

signer = Signer(private_key=jwk_str, did="did:web:agent.example.com")

# Issue under the post-quantum profile. The signer transparently generates
# the ML-DSA-44 keypair if one is not already provisioned.
credential = signer.sign_hybrid(intent={
  "action": "submit_clinical_finding",
  "target": "trial:NCT00000001",
  "resource": "https://fda-submissions.example.com/api/findings",
})

# credential["proof"] is an array of two Data Integrity proofs, one
# "eddsa-jcs-2022" and one "mldsa44-jcs-2024", over the same document.
```

### TypeScript

```typescript
import { Signer, generateMLDSA44KeyPair } from 'vouch-protocol';

const mldsaKeys = await generateMLDSA44KeyPair();
const signer = new Signer({ privateKey, did, mldsa44: mldsaKeys });

const credential = await signer.signHybrid({
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

cred, _ := s.SignHybrid(signer.SignOptions{
  Intent: map[string]any{
    "action": "submit_clinical_finding",
    "target": "trial:NCT00000001",
    "resource": "https://fda-submissions.example.com/api/findings",
  },
})
```

## The wire format

```json
{
 "proof": [
  {
   "type": "DataIntegrityProof",
   "cryptosuite": "eddsa-jcs-2022",
   "verificationMethod": "did:web:agent.example.com#key-1",
   "proofPurpose": "assertionMethod",
   "created": "2026-05-13T10:00:00Z",
   "proofValue": "z..."
  },
  {
   "type": "DataIntegrityProof",
   "cryptosuite": "mldsa44-jcs-2024",
   "verificationMethod": "did:web:agent.example.com#key-2",
   "proofPurpose": "assertionMethod",
   "created": "2026-05-13T10:00:00Z",
   "proofValue": "u..."
  }
 ]
}
```

## What a verifier does

A receiving service iterates the `proof` array and matches on `cryptosuite`.

- **A verifier that understands `eddsa-jcs-2022` only** takes that proof out of
  the array and validates it on its own against the Ed25519 public key. This is
  the path for a service that has not deployed ML-DSA-44 verification yet.
- **A verifier that understands `mldsa44-jcs-2024` only** does the same with the
  ML-DSA-44 proof and the ML-DSA-44 public key. This is the path for a service
  operating under a mandate that calls for a quantum-resistant signature.
- **Vouch Protocol verification** validates both proofs and accepts the
  credential when both pass.

Decode each `proofValue` by its multibase prefix: `z` for base58btc on the
`eddsa-jcs-2022` proof, `u` for base64url-nopad on the `mldsa44-jcs-2024`
proof.

## DID Document for post-quantum agents

An agent issuing under the profile publishes both keys in its DID Document:

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
   "publicKeyMultibase": "z<...long base58btc string for ML-DSA-44, ~1.8 KB...>"
  }
 ],
 "authentication": ["did:web:agent.example.com#key-1", "did:web:agent.example.com#key-2"],
 "assertionMethod": ["did:web:agent.example.com#key-1", "did:web:agent.example.com#key-2"]
}
```

Multikey values are base58btc (`z`) for both keys. Each proof names its own
`verificationMethod`, so the Ed25519 proof points at `#key-1` and the ML-DSA-44
proof points at `#key-2`.

## Performance and size considerations

| Property | `eddsa-jcs-2022` alone | With the `mldsa44-jcs-2024` proof |
|---|---|---|
| Ed25519 signature size | 64 bytes | 64 bytes |
| ML-DSA-44 signature size | 0 | 2,420 bytes |
| ML-DSA-44 public key size | 0 | 1,312 bytes |
| Multikey-encoded public key | ~48 chars | ~1,800 chars (ML-DSA-44 entry) |
| Sign latency (Python, M2 Mac) | ~150 microseconds | ~3 milliseconds |
| Verify latency (Python, M2 Mac) | ~250 microseconds | ~5 milliseconds |
| Total credential size (typical) | ~700 bytes | ~3,200 bytes |

A credential carrying the proof set exceeds typical HTTP header size budgets.
**Always transmit it in the HTTP request body** with
`Content-Type: application/vc+vouch` (the prior
`application/vouch+credential+json` form is retained as a transitional alias for
backward compatibility).

## Migration path

| Phase | Issuer | Verifier |
|---|---|---|
| Today | Ed25519 only (`eddsa-jcs-2022`), the proof set optional | Validates the `eddsa-jcs-2022` proof, or both proofs |
| As CNSA 2.0 phases in | The proof set recommended for regulated sectors | Validates both proofs by default in regulated sectors |
| As classical signatures reach end-of-life | The proof set, or an ML-DSA-44 proof alone | Validates the `mldsa44-jcs-2024` proof |

A credential issued today under the profile remains verifiable through every
phase of this migration without re-issuance.

## Cross-implementation interop

The cross-implementation interop test vector lives at
[`test-vectors/hybrid-eddsa-mldsa44/vector.json`](../test-vectors/hybrid-eddsa-mldsa44/vector.json).
A conforming Python, TypeScript, or Go implementation MUST verify the
included signed credential against the published Ed25519 and ML-DSA-44
public keys.

The vector exercises each proof on its own and both together, and includes a
tamper test confirming both proofs fail when any byte of the canonical form is
mutated.

## References

- [PAD-040: Hybrid Composite Signature Bound to Same Canonical Bytes](./disclosures/PAD-040-hybrid-composite-signature-same-canonical-bytes.md)
- [PAD-041: Algorithm-Agnostic Verification Method Resolution](./disclosures/PAD-041-multikey-algorithm-agnostic-verification.md)
- [PAD-033: ZK PQ Signature Compression](./disclosures/PAD-033-zk-pq-signature-compression.md)
- [PAD-035: Async Chunked Edge PQ Signatures](./disclosures/PAD-035-async-chunked-edge-pq-signatures.md)
- [Specification §13: Crypto-Agility and Quantum-Safe Profile](./specs/w3c-cg-report.md#13-crypto-agility-and-quantum-safe-profile)
- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST CNSA 2.0 announcement](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3608111/)
- [U.S. National Security Memorandum 10 (NSM-10)](https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/)
