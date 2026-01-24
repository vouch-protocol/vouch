# @vouch-protocol/sdk

Official TypeScript SDK for the [Vouch Protocol](https://vouch-protocol.com).

A clean, environment-agnostic client library for communicating with the Vouch Bridge Daemon. Works in both **Browser** and **Node.js**.

## Installation

```bash
npm install @vouch-protocol/sdk
```

## Quick Start

```typescript
import { VouchClient } from '@vouch-protocol/sdk';

const client = new VouchClient();

// Connect to the local daemon
if (await client.connect()) {
    console.log('Connected to Vouch Daemon!');
    
    // Sign text content
    const result = await client.sign('Hello, World!', { origin: 'my-app' });
    console.log('Signature:', result.signature);
    console.log('DID:', result.did);
}
```

## API Reference

### `new VouchClient(config?)`

Create a new client instance.

```typescript
const client = new VouchClient({
    daemonUrl: 'http://127.0.0.1:21000',  // Default
    timeout: 5000,                         // Connection timeout (ms)
    requestTimeout: 120000,                // Request timeout for media (ms)
});
```

### `connect(): Promise<boolean>`

Connect to the Vouch Daemon.

```typescript
const connected = await client.connect();

if (connected) {
    console.log('Ready to sign!');
} else {
    console.log('Daemon not running. Please start vouch-bridge.');
}
```

### `sign(content, metadata?): Promise<SignResult>`

Sign text content. **Triggers user consent popup.**

```typescript
try {
    const result = await client.sign('Hello, World!', {
        origin: 'my-app',
    });
    
    console.log({
        signature: result.signature,
        publicKey: result.public_key,
        did: result.did,
        timestamp: result.timestamp,
        contentHash: result.content_hash,
    });
} catch (error) {
    if (error instanceof UserDeniedSignatureError) {
        console.log('User clicked Deny in the consent popup');
    }
}
```

### `signBlob(file, filename, metadata?): Promise<MediaSignResult>`

Sign binary files (images, videos, audio, PDFs). **Triggers user consent popup with preview.**

```typescript
// Browser: from file input
const input = document.querySelector('input[type="file"]');
const file = input.files[0];

const result = await client.signBlob(file, file.name, {
    origin: 'photo-studio',
});

// Download signed file
const url = URL.createObjectURL(result.data);
const a = document.createElement('a');
a.href = url;
a.download = result.filename;
a.click();

// Node.js: from file system
import { readFileSync, writeFileSync } from 'fs';

const buffer = readFileSync('/path/to/photo.jpg');
const result = await client.signBlob(buffer, 'photo.jpg');

writeFileSync('/path/to/photo_signed.jpg', result.data);
```

### `getPublicKey(): Promise<PublicKeyInfo>`

Get the user's public key and DID.

```typescript
const key = await client.getPublicKey();

console.log({
    publicKey: key.public_key,
    did: key.did,              // did:key:z6Mkv...
    fingerprint: key.fingerprint,
});
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `isConnected` | `boolean` | Whether connected to daemon |
| `daemonStatus` | `DaemonStatus \| null` | Last known daemon status |

## Error Handling

```typescript
import { 
    VouchClient,
    UserDeniedSignatureError,
    DaemonNotAvailableError,
    NoKeysConfiguredError,
} from '@vouch-protocol/sdk';

const client = new VouchClient();

try {
    await client.connect();
    await client.sign('content');
} catch (error) {
    if (error instanceof DaemonNotAvailableError) {
        console.log('Start the daemon: vouch-bridge');
    } else if (error instanceof NoKeysConfiguredError) {
        console.log('Generate keys first: POST /keys/generate');
    } else if (error instanceof UserDeniedSignatureError) {
        console.log('User clicked Deny in consent popup');
    }
}
```

## Browser Usage (Non-Module)

```html
<script src="https://unpkg.com/@vouch-protocol/sdk"></script>
<script>
    const client = new VouchClient();
    
    client.connect().then(connected => {
        if (connected) {
            console.log('Ready!');
        }
    });
</script>
```

## Environment Support

| Environment | Transport | Notes |
|-------------|-----------|-------|
| Browser | `fetch` | Native fetch API |
| Node.js 18+ | `fetch` | Native fetch API |
| Node.js 16-17 | `fetch` | Requires `node-fetch` polyfill |

## Requirements

- **Vouch Bridge Daemon** running on `localhost:21000`
- Node.js 18+ for native fetch (or polyfill for older versions)

## Security

- The SDK communicates only with `localhost` (127.0.0.1)
- Private keys never leave the daemon's system keyring
- All signing requests trigger a user consent popup
- The user sees a preview of what they're signing

## License

MIT © Ramprasad Anandam Gaddam

## Links

- [Vouch Protocol](https://vouch-protocol.com)
- [GitHub](https://github.com/vouch-protocol/vouch)
- [Documentation](https://github.com/vouch-protocol/vouch#readme)
