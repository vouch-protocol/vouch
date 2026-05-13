# TypeScript SDK Reference

`@vouch-protocol/core` on npm. Works in Node and browser. Produces
byte-identical credentials with the Python and Go SDKs.

## Install

```bash
npm install @vouch-protocol/core
# Optional post-quantum:
npm install @noble/post-quantum
```

## Identity

```ts
import { Signer, generateIdentity } from '@vouch-protocol/core';

// Generate
const keys = await generateIdentity('agent.example.com');

// Sign-ready
const signer = new Signer({
    privateKey: keys.privateKeyJwk,
    did: keys.did,
});

// Or load by DID (browser falls back to IndexedDB; Node uses platform key store)
const signer = await Signer.fromDid('did:web:agent.example.com');
```

## Credential issuance

```ts
import { buildVouchCredential } from '@vouch-protocol/core';

const credential = buildVouchCredential({
    issuerDid: 'did:web:agent.example.com',
    intent: {
        action: 'submit_claim',
        target: 'claim:HC-001',
        resource: 'https://insurance.example.com/claims/HC-001',
    },
    validSeconds: 300,
    reputationScore: 85,
    credentialStatus: {  // optional BitstringStatusList entry
        id: '...#42',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '42',
        statusListCredential: 'https://issuer.example/status/1',
    },
});

const signed = await signer.signCredential(credential);
```

## Hybrid post-quantum

```ts
import {
    buildHybridProof,
    generateMLDSA44KeyPair,
    HYBRID_CRYPTOSUITE_ID,
} from '@vouch-protocol/core';

// Caller manages MLDSA keys for now; see data-integrity-hybrid.ts
const mldsa = await generateMLDSA44KeyPair();

const proof = await buildHybridProof({
    credential,
    ed25519PrivateKey: signer.privateKey,
    mldsa44PrivateKey: mldsa.secretKey,
    verificationMethod: signer.verificationMethodId,
});

credential.proof = proof;
```

## Verification

```ts
import { Verifier } from '@vouch-protocol/core';

const verifier = new Verifier();
const result = await verifier.verifyCredential(signed);

if (result.valid) {
    console.log('OK', result.passport);
} else {
    console.log('Rejected', result.reasons);
}
```

## BitstringStatusList

```ts
import {
    StatusList,
    buildStatusListCredential,
    buildStatusListEntry,
    verifyStatus,
} from '@vouch-protocol/core';

const list = new StatusList({
    statusListId: 'https://issuer.example/status/1',
});

const idx = list.allocateIndex();
const entry = buildStatusListEntry({
    statusListCredential: 'https://issuer.example/status/1',
    statusListIndex: idx,
});

// Revoke
list.revoke(idx);

// Publish
const statusCredential = buildStatusListCredential({
    issuerDid: 'did:web:issuer.example',
    statusList: list,
});
```

## Persistence (issuer)

```ts
// Serialize StatusList state (includes encoded bitstring + nextIndex)
const state = list.toStateDict();
await redis.set(`status:${list.statusListId}`, JSON.stringify(state));

// On restart
const restored = StatusList.fromStateDict(JSON.parse(await redis.get(...)));
```

## Daemon client (talk to a sidecar)

If you run the Go sidecar, the TS SDK has a client:

```ts
import { VouchClient } from '@vouch-protocol/core';

const client = new VouchClient({ endpoint: 'http://localhost:8877' });
const signed = await client.sign({
    intent: { action: '...', target: '...', resource: '...' },
});
```

This keeps signing keys out of the TS / Node process entirely.

## Browser specifics

In the browser, `Signer.fromDid` falls back to IndexedDB for key storage,
with optional WebAuthn-gated unlock. For server-side key custody, pass a
KMS provider or use the daemon client.

## Modules quick-map

| Module | Purpose |
|---|---|
| `signer` | Credential issuance (Signer class) |
| `verifier` | Verification (Verifier class) |
| `vc` | `buildVouchCredential` |
| `data-integrity` | eddsa-jcs-2022 proof |
| `data-integrity-hybrid` | hybrid-eddsa-mldsa44-jcs-2026 proof |
| `multikey` | Multikey encode / decode |
| `jcs` | RFC 8785 canonicalization |
| `status-list` | BitstringStatusList (issuer + verifier) |
| `vouch-client` | Daemon client for sidecar |
| `types` | TypeScript types |
