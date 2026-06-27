# Upstream improvement proposal: `sirraya-udna-sdk`

Vouch integrates `sirraya-udna-sdk` (import `udna_sdk`) as an optional
identity-first transport (see `docs/HYBRID_TRANSPORT.md`). While integrating we
read the v1.0.3 source and found one **security-critical** issue and several
smaller gaps. This document records them and proposes fixes, so that (a) Vouch's
adapter documents *why* it currently treats the UDNA channel as non-confidential,
and (b) the findings can be contributed upstream.

These notes are about the **external** package, not Vouch code. Vouch's own
guarantees do not depend on them: a Vouch envelope carries a signed credential,
so payload integrity and authenticity hold end-to-end regardless of transport.

---

## 1. CRITICAL — the handshake provides no confidentiality

`udna_sdk/udna.py :: NoiseHandshake.finalize_handshake` derives the session key
from **public values only**:

```python
key_material = (
    str(session['local_did']).encode() +
    str(session['remote_did']).encode() +
    session['ephemeral_private_key'].public_key().public_bytes(Raw, Raw) +  # PUBLIC
    remote_ephemeral                                                         # PUBLIC
)
session_key = hashlib.sha256(key_material).digest()
```

Both DIDs and both ephemeral **public** keys travel in the clear inside the
handshake JSON. No private key material and no Diffie-Hellman ever enter the
KDF. Therefore **any passive observer of the handshake can recompute the exact
session key** and decrypt every subsequent `SecureMessaging` (ChaCha20-Poly1305)
frame. The code comments confirm it is a placeholder:

> `# In a full Noise implementation, this would perform DH key exchange`
> `# For demo, we'll derive a session key from the DIDs and ephemeral keys`

Impact: the "end-to-end encrypted messaging" claim does not hold. Peer
authenticity *is* present (ephemeral keys are signed by the DID keys), but
channel secrecy and forward secrecy are absent.

### Proposed fix — real ephemeral ECDH (X25519), keep Ed25519 for auth

Ed25519 identity keys can't do DH, so add an ephemeral **X25519** keypair per
handshake and sign its public key with the Ed25519 DID key (Noise-IK / X3DH
shape):

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# initiate / respond: generate an ephemeral X25519 key, send its public bytes,
# and authenticate it with the static Ed25519 DID key:
eph = X25519PrivateKey.generate()
eph_pub = eph.public_key().public_bytes(Raw, Raw)
auth_sig = ed25519_did_key.sign(eph_pub + str(remote_did).encode())  # binds eph→identity

# finalize (both sides): verify the peer's auth_sig against their did:key,
# then derive the key from the DH shared secret + a transcript hash:
shared = eph.exchange(X25519PublicKey.from_public_bytes(remote_eph_pub))
session_key = HKDF(
    algorithm=hashes.SHA256(), length=32,
    salt=transcript_hash,            # H(init_msg ‖ response_msg)
    info=b"udna-noise-v2",
).derive(shared)
```

This yields confidentiality, forward secrecy, and mutual authentication, and is
a localized change to the three `NoiseHandshake` methods. The wire format gains
an `x25519_ephemeral` field alongside the existing signed Ed25519 ephemeral.

---

## 2. No transport / overlay — only an in-memory demo DHT

`DhtNode` is a single-process dict (`store`/`lookup`), so the SDK cannot
actually deliver bytes between hosts. Vouch works around this with a pluggable
`UdnaChannel`. Upstream would benefit from a documented `Transport` interface
(e.g. `async def send(address, frame) -> frame`) with at least one real backend
(QUIC/libp2p/websocket relay), so integrators don't each reinvent delivery.

## 3. `create_address` only works for SDK-generated DIDs

`create_address` requires the DID to be in `self._active_keys`, i.e. created by
`UdnaSDK.create_did()`. There is no public way to register an externally-held
key, so an agent that already owns an Ed25519 identity (the common case for
Vouch) cannot mint an SDK address for it. Proposed: an
`import_identity(did, private_key)` / `register_key(did, signer)` entry point,
or accept a signing callback.

## 4. Minor

- **Version mismatch:** `udna_sdk/__init__.py` sets `__version__ = "1.0.2"`
  while the distribution is `1.0.3`. Source the version from one place.
- **Address timestamps are unauthenticated:** `UdnaAddressInfo.created_at` is
  set from `datetime.now()` at *parse* time, not signed into the address, so it
  conveys nothing verifiable. Either sign it or drop it from the verified view.
- **`verify_address` swallows all errors into `is_valid=False`:** useful for
  callers, but consider distinguishing "malformed" from "signature mismatch" in
  `VerificationResult.error` for debuggability (it partly does this already).

---

## What Vouch does in the meantime

- The adapter (`vouch/transport/udna.py :: SirrayaUdnaNode`) carries an explicit
  warning that the v1.0.x channel is authenticated but **not confidential**.
- Vouch never relies on UDNA channel encryption for security; envelope payloads
  are signed credentials, so tampering and forgery are caught regardless.
- For confidential payloads, encrypt at the application layer before sealing, or
  use a transport with real channel encryption, until item 1 lands upstream.
