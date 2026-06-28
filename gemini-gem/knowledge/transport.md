# Identity-Native Transport Reference

Vouch addresses a peer by its DID, not its IP or domain. The transport
layer (`vouch.transport`) prefers identity-first routing over UDNA
(Universal DID-Native Addressing) and falls back to standard DNS and HTTPS
when a peer is not on the overlay. An agent dispatches a message to a DID
and stays agnostic about how the bytes are routed.

This is optional and experimental. It is aligned with the W3C UDNA
Community Group and is dormant unless you opt in.

## Why it exists

Agents are ephemeral, spawn sub-agents, and move across hosts and clouds.
They rarely hold a stable domain or IP, but they always hold a key, so a
DID is the only stable handle. Identity-first routing matches how agents
actually run. Vouch already makes a DID accountable (identity, reputation,
liability); UDNA answers how to reach it.

## How it routes

`TransportManager` holds an ordered list of transports and tries them in
preference order:

1. `UdnaTransport` (identity-first) when the peer is on the overlay.
2. `HttpTransport` (did:web, DNS, HTTPS) as the universal fallback.

A transport that cannot reach a peer raises `TransportUnavailable`, and the
manager moves to the next one. `DeliveryResult.attempts` records the path
taken, for example `["udna", "http"]`.

## What "route by DID" means

The DID Document (the json with the DID and public key) is a key store, not
a routing target. Its job is to give you the public key so you can verify
signatures. Location comes from elsewhere. In `did:web`, the location is a
`serviceEndpoint` you fetch over DNS and HTTPS. In UDNA, the agent publishes
a signed route record under its DID, and a resolver maps the DID to the
agent's current endpoint, so there is no domain to seize and no DNS to
poison. The key is the constant; the location is dynamic and self-published.

## Payload preservation

The message is a `VouchEnvelope` that carries three things unchanged: the
signed Vouch credential (with its Data Integrity proof), liability
attestations, and provenance metadata. A JCS-canonical SHA-256 content
digest is verified on receipt, so the trust properties hold whichever path
the bytes take. Switching from UDNA to HTTP never re-signs or strips the
payload.

## Quick start

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
)

manager = TransportManager.default(private_key_jwk=kp.private_key_jwk)
result = await manager.dispatch(envelope)
print(result.transport)   # "udna" or "http"
```

Install the optional dependency with `pip install vouch-protocol[udna]`.
Without it, the UDNA transport stays dormant and dispatch falls through to
HTTP, so the code above runs unchanged.

## Security note

The reference UDNA SDK (`udna_sdk` v1.0.x) authenticates the peer during
its handshake but does not provide channel confidentiality: its session key
is derived from public values, so the channel should not be treated as
private yet. Vouch does not rely on it. Envelope payloads are signed
credentials, so their integrity and authenticity hold end to end no matter
which transport carries them. For confidential payloads, encrypt at the
application layer before sealing, or use a transport with real channel
encryption.

## See also

- `docs/HYBRID_TRANSPORT.md` for the architecture.
- `docs/udna-upstream-proposal.md` for the security finding and a proposed
  fix (ephemeral X25519 with HKDF, keeping Ed25519 for authentication).
