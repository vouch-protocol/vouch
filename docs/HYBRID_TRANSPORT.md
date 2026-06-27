# Hybrid Transport Architecture (UDNA + HTTP)

Vouch credentials say *what* an agent intends and *who* is accountable. The
transport layer decides *how* that statement reaches a peer. This document
describes Vouch's modular, DID-addressed transport layer (`vouch.transport`),
which lets an agent dispatch a message to a peer's **identity** and remain
agnostic about whether it travelled over an identity-first overlay (UDNA) or
standard DNS/IP + HTTP.

## Why

Standard routing resolves an identity *down to a location* — `did:web` → domain
→ IP — and then trusts whoever answers that IP. Location is the weak link:
domains get seized, DNS gets poisoned, IPs get hijacked.

**UDNA (Universal DID-Native Addressing)** inverts the stack. The DID itself is
the routing primitive; delivery rides a Noise-encrypted channel straight to the
key that owns the DID. There is no location to spoof — the peer you reach is, by
construction, the peer whose key matches the DID.

UDNA is powerful but not universal: not every peer is on the overlay. So Vouch
treats it as an **optional, preferred** transport with **graceful fallback** to
HTTP. Agents get identity-first routing when both ends support it and
location-first reachability everywhere else, behind a single API.

## Module layout

```
vouch/transport/
├── __init__.py          Public API surface
├── base.py              Transport ABC, PeerAddress, DeliveryResult, errors
├── envelope.py          VouchEnvelope — payload-preserving message container
├── did_key.py           did:key generation/parsing (UDNA's native identity)
├── http_transport.py    HttpTransport — DNS/IP + HTTPS (did:web), the fallback
├── udna.py              UdnaTransport — Sirraya UDNA SDK adapter (Noise)
└── manager.py           TransportManager — fallback routing middleware
```

## Components

### `Transport` (abstract base)

Every transport implements three methods, all keyed on DID, never on location:

| Method | Purpose |
| --- | --- |
| `can_route(did) -> bool` | Cheap pre-filter: could this transport plausibly reach this DID? |
| `resolve(did) -> PeerAddress \| None` | Turn the DID into a concrete address, or `None` to trigger fallback. |
| `send(envelope, peer) -> dict` | Deliver the payload; return the peer reply. |

A transport signals **"not me, try the next one"** by raising
`TransportUnavailable` or returning `None` from `resolve`. It signals a
**corrupted payload** (fatal, never retried) by raising
`PayloadIntegrityError`. The manager keys its fallback-vs-fail decision on
exactly that distinction.

### `VouchEnvelope` — payload preservation

The envelope carries three compartments verbatim across any transport boundary:

- `payload` — the signed Vouch credential, complete with its `eddsa-jcs-2022`
  (or hybrid PQ) Data Integrity `proof`. Stored by reference, never
  re-serialized lossily.
- `attestations` — liability attestations (outcome commitments, penalty
  receipts, delegation links).
- `provenance` — provenance metadata (content hashes, C2PA pointers, capture
  context).

Integrity is enforced by `content_digest()`: a SHA-256 over the **JCS
canonicalization** (RFC 8785) of those three compartments. Because the digest
is computed over the canonical form rather than the wire bytes, an envelope
survives a UDNA→HTTP transition, re-indentation, or key reordering with its
signatures intact. `from_wire()` re-verifies the seal on receipt and raises
`PayloadIntegrityError` on any mismatch.

### `UdnaTransport` — identity-first

Wraps the core concepts of `sirraya-udna-sdk`:

- **DID generation** — derives a `did:key` from the agent's existing Ed25519
  identity via `vouch.multikey` (no new key material, no registry).
- **UDNA address creation** — projects a DID and a *facet* (a named capability
  lane, default `vouch.message`) into a `udna://<did>/<facet>` address.
- **Secure messaging** — hands the sealed envelope to the SDK node, which
  performs the Noise handshake, verifies the peer's DID, and delivers the bytes.

The SDK is an **optional dependency** (`pip install vouch-protocol[udna]`). All
SDK interaction goes through the minimal `UdnaNode` protocol, so the transport
is fully testable without the SDK and the rest of Vouch imports it
unconditionally. When the SDK is absent and no node is injected, the transport
is **dormant**: it routes nothing and the manager falls back to HTTP. UDNA being
unavailable is never an error — that is the point of the hybrid design.

### `HttpTransport` — location-first fallback

The universal lowest common denominator. Resolves `did:web` → domain via
DNS/IP, discovers the peer's inbox (an explicit `VouchInbox` service in the DID
Document, else the conventional `/.well-known/vouch/inbox`), and POSTs the
sealed envelope over TLS. Every outbound URL is screened by `vouch.ssrf`
(https-only, public IPs only, redirects disabled) because the target host is
derived from a potentially attacker-controlled DID.

### `TransportManager` — fallback middleware

The single entry point for agents. Holds an ordered list of transports
(UDNA preferred, HTTP behind) and exposes one method, `dispatch(envelope)`,
that walks them in order:

1. skip if `can_route` is false (cheap pre-filter);
2. skip if `resolve` returns `None` (peer doesn't support this transport);
3. attempt `send` if resolution succeeded.

`TransportUnavailable` at any step → move to the next transport.
`PayloadIntegrityError` → stop immediately (never re-route a corrupt payload).
All transports exhausted → raise `TransportError` carrying the last failure.
The **same** envelope instance is handed to whichever transport wins, so the
credential, proof, attestations, and provenance are never re-signed or stripped.

## Usage

```python
from vouch import Signer, generate_identity
from vouch.transport import TransportManager, build_envelope

kp = generate_identity(domain="agent.example.com")
signer = Signer(private_key=kp.private_key_jwk, did=kp.did)

credential = signer.sign_credential(intent={
    "action": "settle_invoice",
    "target": "invoice-42",
    "resource": "https://api.example.com/invoices/42",
})

envelope = build_envelope(
    from_did=kp.did,
    to_did="did:web:peer.example.com",
    payload=credential,
    attestations=[...],   # liability
    provenance={...},     # provenance
)

# UDNA preferred, HTTP fallback. UDNA auto-wires if the SDK is installed.
manager = TransportManager.default(private_key_jwk=kp.private_key_jwk)
result = await manager.dispatch(envelope)

print(result.transport)   # "udna" or "http"
print(result.attempts)    # e.g. ["udna", "http"] — the fallback path taken
```

A runnable, network-free demo lives at
[`examples/hybrid_transport_demo.py`](../examples/hybrid_transport_demo.py).

## Extending

To add a transport (libp2p, Tor, a message bus), subclass `Transport`,
implement the three methods, and insert it into the manager's preference list.
Agents and the envelope are unaffected — that is the whole point of the
abstraction.
