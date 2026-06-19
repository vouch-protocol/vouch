# vouch-sdk

Official Python SDK for the [Vouch Protocol](https://vouch-protocol.com).

A clean client library for communicating with the Vouch Bridge Daemon. Supports both **synchronous** and **asynchronous** operations using `httpx`.

## Installation

```bash
pip install vouch-sdk
```

## Quick Start

### Synchronous Client

```python
from vouch_sdk import VouchClient

client = VouchClient()

# Connect to daemon
if client.connect():
    print("Connected to Vouch Daemon!")
    
    # Sign text content
    result = client.sign("Hello, World!", origin="my-app")
    print(f"Signature: {result.signature}")
    print(f"DID: {result.did}")
    
    # Sign a file
    media = client.sign_file("/path/to/photo.jpg")
    with open("/path/to/photo_signed.jpg", "wb") as f:
        f.write(media.data)
```

### Async Client (for FastAPI, Antigravity, etc.)

```python
from vouch_sdk import AsyncVouchClient

async with AsyncVouchClient() as client:
    if await client.connect():
        result = await client.sign("Hello, World!")
        print(f"Signature: {result.signature}")
```

## API Reference

### VouchClient / AsyncVouchClient

Both clients have the same methods (sync vs async):

| Method | Description |
|--------|-------------|
| `connect()` | Connect to daemon, returns `bool` |
| `sign(content, origin)` | Sign text, returns `SignResult` |
| `sign_file(path, origin)` | Sign file from disk, returns `MediaSignResult` |
| `sign_bytes(data, filename)` | Sign binary data, returns `MediaSignResult` |
| `get_public_key()` | Get identity, returns `PublicKeyInfo` |
| `disconnect()` | Disconnect from daemon |
| `close()` | Close HTTP client |

### Configuration

```python
client = VouchClient(
    daemon_url="http://127.0.0.1:21000",  # Default
    timeout=5.0,                           # Connection timeout
    request_timeout=120.0,                 # Media signing timeout
)
```

### Error Handling

```python
from vouch_sdk import (
    VouchClient,
    VouchConnectionError,
    UserDeniedSignatureError,
    NoKeysConfiguredError,
)

client = VouchClient()

try:
    client.connect()
    result = client.sign("content")
except VouchConnectionError:
    print("Daemon not running. Start: vouch-bridge")
except NoKeysConfiguredError:
    print("Generate keys: POST /keys/generate")
except UserDeniedSignatureError:
    print("User clicked Deny in consent popup")
```

### Data Classes

```python
@dataclass
class SignResult:
    signature: str      # Base64 signature
    public_key: str     # Base64 public key
    did: str           # did:key:z6Mkv...
    timestamp: str     # ISO 8601
    content_hash: str  # SHA-256

@dataclass
class MediaSignResult:
    data: bytes        # Signed file content
    did: str
    timestamp: str
    hash: str
    filename: str
    mime_type: str

@dataclass
class PublicKeyInfo:
    public_key: str
    did: str
    fingerprint: str
```

## Context Manager Support

Both clients support context managers:

```python
# Sync
with VouchClient() as client:
    client.connect()
    client.sign("content")
# Automatically closes

# Async
async with AsyncVouchClient() as client:
    await client.connect()
    await client.sign("content")
# Automatically closes
```

## Use Cases

### Antigravity IDE

```python
from vouch_sdk import AsyncVouchClient

class AntigravitySigningService:
    def __init__(self):
        self.client = AsyncVouchClient()
    
    async def sign_code_change(self, diff: str) -> str:
        if not self.client.is_connected:
            await self.client.connect()
        
        result = await self.client.sign(diff, origin="antigravity-ide")
        return result.signature
```

### CLI Tool

```python
import click
from vouch_sdk import VouchClient, VouchConnectionError

@click.command()
@click.argument("file")
def sign(file):
    """Sign a file with Vouch."""
    with VouchClient() as client:
        if not client.connect():
            raise click.ClickException("Daemon not running")
        
        result = client.sign_file(file)
        output = f"signed_{file}"
        
        with open(output, "wb") as f:
            f.write(result.data)
        
        click.echo(f"✅ Signed: {output}")
        click.echo(f"   DID: {result.did}")
```

### FastAPI Backend

```python
from fastapi import FastAPI, HTTPException
from vouch_sdk import AsyncVouchClient, UserDeniedSignatureError

app = FastAPI()
vouch = AsyncVouchClient()

@app.on_event("startup")
async def startup():
    await vouch.connect()

@app.post("/sign")
async def sign_content(content: str):
    try:
        result = await vouch.sign(content, origin="my-api")
        return {"signature": result.signature, "did": result.did}
    except UserDeniedSignatureError:
        raise HTTPException(403, "User denied signature")
```

## Requirements

- Python 3.10+
- Vouch Bridge Daemon running on localhost:21000

## License

MIT © Ramprasad Anandam Gaddam
