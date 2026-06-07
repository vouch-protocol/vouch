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

// Sign-ready (constructor takes the private key JWK and the DID)
const signer = new Signer({
    privateKey: keys.privateKeyJwk,
    did: keys.did,
});

// To reload an existing identity, read its stored privateKeyJwk and did
// and construct a Signer the same way:
const reloaded = new Signer({
    privateKey: storedPrivateKeyJwk,
    did: 'did:web:agent.example.com',
});
```

## Credential issuance

```ts
// signCredential takes an options object whose required field is `intent`.
const signed = await signer.signCredential({
    intent: {
        action: 'submit_claim',
        target: 'claim:HC-001',
        resource: 'https://insurance.example.com/claims/HC-001',
    },
    validSeconds: 300,
    reputationScore: 85,
});
// `signed` is a full Verifiable Credential dict with a Data Integrity proof.
```

## Hybrid post-quantum

```ts
// The Signer manages its own ML-DSA-44 keypair. Call signCredentialHybrid
// with the same options shape as signCredential.
const signedHybrid = await signer.signCredentialHybrid({
    intent: {
        action: 'submit_claim',
        target: 'claim:HC-001',
        resource: 'https://insurance.example.com/claims/HC-001',
    },
});
// signedHybrid.proof.cryptosuite === 'hybrid-eddsa-mldsa44-jcs-2026'
```

## Verification

```ts
import { Verifier } from '@vouch-protocol/core';

// verifyCredential returns { isValid, passport, error }
const result = await Verifier.verifyCredential(signed);

if (result.isValid) {
    console.log('OK', result.passport);
} else {
    console.log('Rejected', result.error);
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

In the browser, construct the `Signer` from a private key JWK you load out
of IndexedDB (optionally WebAuthn-gated). For server-side key custody, keep
the key in a sidecar and use the daemon client below.

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
