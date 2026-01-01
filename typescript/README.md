# Vouch Protocol - TypeScript SDK

The official TypeScript/JavaScript SDK for [Vouch Protocol](https://github.com/vouch-protocol/vouch).

## Installation

```bash
npm install vouch-protocol
# or
yarn add vouch-protocol
```

## Quick Start

### Signing (Agents)

```typescript
import { Signer, generateIdentity } from 'vouch-protocol';

// Generate a new identity
const { privateKeyJwk, publicKeyJwk, did } = await generateIdentity('my-agent.com');

// Create signer
const signer = new Signer({
  privateKey: privateKeyJwk,
  did: did // 'did:web:my-agent.com'
});

// Sign an action
const token = await signer.sign({
  action: 'read_database',
  target: 'users_table'
});

// Use token in Vouch-Token header
fetch('/api/resource', {
  headers: { 'Vouch-Token': token }
});
```

### Verification (Gatekeepers)

```typescript
import { Verifier } from 'vouch-protocol';

// Static verification with public key
const publicKeyJwk = '{"kty":"OKP","crv":"Ed25519","x":"..."}';
const { isValid, passport } = await Verifier.verify(token, publicKeyJwk);

if (isValid) {
  console.log('Agent:', passport.sub);
  console.log('Action:', passport.payload);
}
```

### Trusted Roots

```typescript
import { Verifier } from 'vouch-protocol';

// Create verifier with trusted DIDs
const verifier = new Verifier({
  trustedRoots: {
    'did:web:trusted-agent.com': publicKeyJwk
  }
});

// Verify token (automatically uses trusted root)
const result = await verifier.checkVouch(token);
```

## API Reference

### `Signer`

| Method | Description |
|--------|-------------|
| `new Signer(config)` | Create a new signer |
| `sign(payload, expiry?)` | Sign a payload, returns JWS token |
| `getDid()` | Get the signer's DID |
| `getPublicKeyJwk()` | Get public key in JWK format |

### `Verifier`

| Method | Description |
|--------|-------------|
| `Verifier.verify(token, publicKey?)` | Static verification |
| `new Verifier(config)` | Create verifier with trusted roots |
| `checkVouch(token)` | Verify using trusted roots |
| `addTrustedRoot(did, key)` | Add a trusted DID dynamically |

### `Passport` (Returned by verify)

| Field | Description |
|-------|-------------|
| `sub` | Subject DID |
| `iss` | Issuer DID |
| `iat` | Issued at timestamp |
| `exp` | Expiration timestamp |
| `jti` | Unique token ID |
| `payload` | Signed payload object |

## License

AGPL-3.0
