# Post-Quantum Reference

The post-quantum profile of Vouch Protocol is a Data Integrity proof set. The
credential's `proof` is an ARRAY carrying two independent proofs, one
`eddsa-jcs-2022` and one `mldsa44-jcs-2024`, each computed over the same
document with only its own proof configuration. Each proof verifies on its own,
and both must verify for the credential to be accepted.

## When to use it

- Regulated sectors with PQ migration mandates (NIST CNSA 2.0, NSM-10, CNSSP-15)
- Long-term audit trails (harvest-now-decrypt-later threats)
- Defense in depth: if Ed25519 cryptanalysis appears, ML-DSA-44 still holds

Costs: about 2.5 KB extra per credential, about 3 ms extra signing time
on M-series Apple silicon.

## Cryptosuite identifiers

| Cryptosuite | Algorithm | proofValue encoding |
|---|---|---|
| `eddsa-jcs-2022` | Ed25519 | base58btc multibase (`z`) |
| `mldsa44-jcs-2024` | ML-DSA-44 (FIPS 204) | base64url-nopad multibase (`u`) |

`mldsa44-jcs-2024` is the identifier from the W3C Quantum-Resistant
Cryptosuites work, and that specification is also where the base64url-nopad
proof value encoding comes from. The classical `eddsa-jcs-2022` suite is
specified separately and keeps base58btc.

Credentials issued before this alignment keep verifying. The earlier
`mldsa44-jcs-2026` identifier and the earlier composite
`hybrid-eddsa-mldsa44-jcs-2026` proof, whose single `proofValue` concatenated
the two signatures, are both accepted on verification and are never emitted.

## Wire format

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
            "verificationMethod": "did:web:agent.example.com#key-pq",
            "proofPurpose": "assertionMethod",
            "created": "2026-05-13T10:00:00Z",
            "proofValue": "u..."
        }
    ]
}
```

The Ed25519 signature is 64 bytes and the ML-DSA-44 signature is 2,420 bytes,
so the two proof values together carry 2,484 bytes of signature.

## How each proof is bound to the document

Each proof is computed over the same unsecured document (the credential with
`proof` removed) combined with that proof's own proof configuration, which is
the standard Data Integrity hashing algorithm. That is what makes a proof
independently verifiable: a verifier takes one proof out of the array, pairs it
with the document, and checks it with no knowledge of the other proof. Because
both proofs cover the same document, an attacker cannot present a different
payload to one algorithm than to the other.

## DID Document layout

Publish both keys side-by-side:

```json
{
    "id": "did:web:agent.example.com",
    "verificationMethod": [
        {
            "id": "did:web:agent.example.com#key-1",
            "type": "Multikey",
            "controller": "did:web:agent.example.com",
            "publicKeyMultibase": "z6Mkh..."
        },
        {
            "id": "did:web:agent.example.com#key-pq",
            "type": "Multikey",
            "controller": "did:web:agent.example.com",
            "publicKeyMultibase": "z87..."
        }
    ],
    "assertionMethod": [
        "did:web:agent.example.com#key-1",
        "did:web:agent.example.com#key-pq"
    ]
}
```

Multikey values are base58btc (`z`) in both cases, and the ML-DSA-44 key
carries multicodec prefix `0x1207`. The Vouch `multikey` modules handle
encoding and decoding. Note that the multibase used for a Multikey and the
multibase used for a `proofValue` are set by different specifications, so the
ML-DSA-44 key is `z`-prefixed while the ML-DSA-44 proof value is `u`-prefixed.

## What a verifier does

| Verifier | Behavior |
|---|---|
| Understands `eddsa-jcs-2022` only | Picks that proof out of the array and validates it on its own |
| Understands `mldsa44-jcs-2024` only | Picks that proof out of the array and validates it on its own |
| Vouch Protocol verification | Validates both proofs, and accepts the credential when both pass |

Verifiers iterate the `proof` array and match on `cryptosuite`, so a verifier
that has not adopted ML-DSA-44 yet still gets a meaningful classical result
from the same credential.

## Issuing post-quantum credentials

### Python

```bash
pip install 'vouch-protocol[pq]'
```

```python
from vouch import generate_identity, Signer

keys = generate_identity("agent.example.com")
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)
signed = signer.sign_hybrid(intent={
    "action": "submit_claim",
    "target": "claim:HC-001",
    "resource": "https://insurance.example.com/claims/HC-001",
})
```

### TypeScript

```bash
npm install @vouch-protocol-official/sdk @noble/post-quantum
```

```ts
import { Signer, generateIdentity } from '@vouch-protocol-official/sdk';

const keys = await generateIdentity('agent.example.com');
const signer = new Signer({ privateKey: keys.privateKeyJwk, did: keys.did });
const signed = await signer.signHybrid({
  intent: {
    action: 'submit_claim',
    target: 'claim:HC-001',
    resource: 'https://insurance.example.com/claims/HC-001',
  },
});
```

### Go

Post-quantum signing is built into the sidecar:

**macOS / Linux**

```bash
./vouch-sidecar --did did:web:agent.example.com --hybrid --port 8877
```

**Windows (PowerShell)**

```powershell
.\vouch-sidecar.exe --did did:web:agent.example.com --hybrid --port 8877
```

All `/sign` requests now produce credentials carrying the proof set.

## Test vector

Canonical post-quantum test vector at
`test-vectors/hybrid-eddsa-mldsa44/vector.json`. Python, TypeScript, and Go all
verify the same vector byte-identically. The vector includes the Ed25519 seed,
ML-DSA-44 keypair, signed credential, and expected SHA-256 of the canonical
form.

To regenerate:

```bash
cd test-vectors/hybrid-eddsa-mldsa44
PYTHONPATH=../.. python generate.py
```

## Migration sequence

The proof set is the middle step in a three-phase migration aligned with NIST
CNSA 2.0:

1. **Current**: classical Ed25519 default, the post-quantum proof set OPTIONAL
2. **As CNSA 2.0 phase-in advances**: the proof set becomes RECOMMENDED for regulated sectors
3. **Long-term**: classical-only signatures reach end-of-life; the proof set or a pure-PQ proof REQUIRED

Implementers in regulated sectors should adopt the proof set TODAY for
credentials that need long retention (multi-year audit trails). Classical-only
remains fine for short-lived ephemeral credentials.

## Implementation files

| File | Language | Purpose |
|---|---|---|
| `vouch/data_integrity_hybrid.py` | Python | Build and verify the proof set |
| `packages/sdk-ts/src/data-integrity-hybrid.ts` | TypeScript | Same surface |
| `go-sidecar/signer/data_integrity_hybrid.go` | Go | Same surface, uses Cloudflare CIRCL |
| `core/vouch-core/src/hybrid.rs` | Rust core | Same surface, feeds the wrapper SDKs and WASM |

The full implementation guide is at `docs/hybrid-pq-implementation-guide.md`.

## Performance numbers

On Apple M2 (2024):

| Operation | Ed25519 only | Post-quantum proof set |
|---|---|---|
| Sign | ~50 µs | ~3 ms |
| Verify | ~150 µs | ~3 ms |
| Credential size | ~700 bytes | ~3.2 KB |

The proof set is ~20-60x slower for signing and ~5x bigger on the wire. For
most agent workflows (one credential per minute or less), this is acceptable.
For high-throughput inner loops (>100 credentials/second), consider
classical-only and rotate the underlying key more frequently.

## HTTP header size

A credential carrying the proof set exceeds typical HTTP header size limits
(8 KB). Transmit credentials in the request body, not headers:

```
POST /api/action HTTP/1.1
Content-Type: application/vc+vouch

{...the full credential...}
```

## Common errors

- **`pip install vouch-protocol[pq]` fails on macOS**: the `pqcrypto`
  dependency needs `liboqs`. `brew install liboqs` and retry.
- **`pip install vouch-protocol[pq]` fails on Ubuntu**: needs
  `build-essential` and `libssl-dev`. `apt install build-essential libssl-dev`.
- **Verifier reads only the first proof**: `proof` is an array under this
  profile. Iterate it and match on `cryptosuite`.
- **Verifier decodes every proof value as base58**: decode by the multibase
  prefix instead. `eddsa-jcs-2022` proof values start with `z` (base58btc) and
  `mldsa44-jcs-2024` proof values start with `u` (base64url-nopad).
