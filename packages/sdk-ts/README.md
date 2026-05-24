# vouch-protocol

Official TypeScript SDK for the [Vouch Protocol](https://vouch-protocol.com).

The open standards-aligned standard for cryptographic identity and provenance of AI agents. Works in both **Browser** and **Node.js**.

## Installation

```bash
npm install vouch-protocol

# Optional: for the hybrid post-quantum profile
npm install @noble/post-quantum
```

## Two surfaces in one package

This package exports two complementary APIs:

1. **Cryptographic SDK** (v1.0+): issue and verify Verifiable Credentials with Data Integrity proofs (`eddsa-jcs-2022`), Multikey verification methods, and an optional hybrid post-quantum profile (`hybrid-eddsa-mldsa44-jcs-2026`). Use for direct cryptographic agent identity.
2. **Daemon Client**: a client library for delegating signing operations to a locally-running Vouch Bridge Daemon. Use when key material is centrally managed.

## Quick Start: Cryptographic SDK (v1.0+)

```typescript
import { Signer, Verifier, generateIdentity } from 'vouch-protocol';

// Generate a fresh agent identity
const keys = await generateIdentity('agent.example.com');

// Issue a Verifiable Credential bound to a specific intent
const signer = new Signer({
  privateKey: keys.privateKeyJwk,
  did: keys.did!,
});

const credential = await signer.signCredential({
  intent: {
    action: 'read_database',
    target: 'users_table',
    resource: 'https://api.example.com/v1/users',
  },
});

// Verify on the receiving side
const result = await Verifier.verifyCredential(credential, keys.publicKeyJwk);
if (result.isValid) {
  console.log('Verified agent:', result.passport!.iss);
  console.log('Authorized intent:', result.passport!.intent);
}
```

## Quick Start: Daemon Client

```typescript
import { VouchClient } from 'vouch-protocol';

const client = new VouchClient();

if (await client.connect()) {
  const result = await client.sign('Hello, World!', { origin: 'my-app' });
  console.log('Signature:', result.signature);
  console.log('DID:', result.did);
}
```

## Hybrid Post-Quantum Profile

Optional `hybrid-eddsa-mldsa44-jcs-2026` cryptosuite carries Ed25519 + ML-DSA-44 composite signatures over the same canonical bytes. Aligns with NIST CNSA 2.0 / NSM-10 migration timelines.

```typescript
import { Signer, generateMLDSA44KeyPair } from 'vouch-protocol';

const mldsaKeys = await generateMLDSA44KeyPair();
// ...sign and verify under the hybrid profile...
```

See the full implementation guide at [docs/hybrid-pq-implementation-guide.md](https://github.com/vouch-protocol/vouch/blob/main/docs/hybrid-pq-implementation-guide.md).

## What's exported

- `Signer`, `Verifier`, `generateIdentity`, credential issuance and verification (v1.0+)
- `buildVouchCredential`, `VouchCredential`, `Intent`, `DelegationLink`, credential construction primitives
- `canonicalize`, `canonicalizeToString`, RFC 8785 JCS canonicalization
- `encodeEd25519Public`, `encodeMLDSA44Public`, `decodeMultikey`, `multikeyAlgorithm`, Multikey verification methods
- `buildProof`, `verifyProof`, `eddsa-jcs-2022` Data Integrity primitives
- `buildHybridProof`, `verifyHybridProof`, `generateMLDSA44KeyPair`, hybrid post-quantum primitives
- `VouchClient` and the daemon client error types, daemon-delegation client

## License

MIT. See [LICENSE](https://github.com/vouch-protocol/vouch/blob/main/LICENSE) in the monorepo.

## Documentation

- specification draft: https://vouch-protocol.com/specs/SPEC/
- Hybrid Post-Quantum Implementation Guide: https://github.com/vouch-protocol/vouch/blob/main/docs/hybrid-pq-implementation-guide.md
- Defensive Prior Art Disclosures (CC0): https://github.com/vouch-protocol/vouch/tree/main/docs/disclosures

## Repository

[github.com/vouch-protocol/vouch](https://github.com/vouch-protocol/vouch) (monorepo, this package lives under `packages/sdk-ts/`).
