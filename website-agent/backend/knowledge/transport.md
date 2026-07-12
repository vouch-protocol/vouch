# Identity-Native Transport Reference

Vouch addresses a peer by its DID, not its IP or domain. The transport
layer (`vouch.transport`) routes a message to an identity and stays agnostic
about how the bytes get there. It ships its own identity-first resolver that
works today over commodity HTTPS, builds on UDNA (Universal DID-Native
Addressing) as a general identity-native substrate when one is present, and
falls back to standard DNS and HTTPS for any `did:web` peer.

This is optional. The identity-first path is opt-in, and the HTTP fallback
means an agent is always reachable. Vouch develops the resolver in the open
and tracks the W3C UDNA Community Group so the two interoperate as UDNA's
baseline lands.

## Why it exists

Agents are ephemeral, spawn sub-agents, and move across hosts and clouds.
They rarely hold a stable domain or IP, but they always hold a key, so a
DID is the only stable handle. Identity-first routing matches how agents
actually run. Vouch already makes a DID accountable (identity, reputation,
liability); the transport layer answers how to reach it.

## How it routes

`TransportManager` holds an ordered list of transports and tries them in
preference order:

1. Identity-first routing (resolve the DID to the agent's current endpoint)
   when the peer has published a route.
2. `HttpTransport` (did:web, DNS, HTTPS) as the universal fallback.

A transport that cannot reach a peer raises `TransportUnavailable`, and the
manager moves to the next one. `DeliveryResult.attempts` records the path
taken, for example `["udna", "http"]`.

## Reaching an agent by DID, today

`did:web` answers "where is this domain." It cannot answer the question an
agent actually has, "where is this identity right now," without a domain and
DNS. The rendezvous resolver answers it directly, and it ships now:

- An agent binds its DID to a current endpoint, signs that binding with the
  DID's own key (a `RouteRecord`), and publishes it.
- A sender that knows only the DID resolves it to the live endpoint and
  verifies that the agent itself asserted the route.
- The routing key on the wire is `sha256(did)`, so a lookup never leaks the
  DID itself.

Two backends ship behind the same record format and the same verification: an
in-memory resolver for tests and single-process use, and a deployable HTTPS
rendezvous (`RendezvousService` / `build_rendezvous_app` on the server,
`HttpRendezvousResolver` / `HttpRendezvousChannel` on the client) that runs the
whole path over plain HTTPS with no DNS binding the agent to a location.

The rendezvous is untrusted. It stores and serves signed records but never has
to be believed: the client re-verifies every record's signature locally and
checks the record's DID against the one it asked for. A malicious or
compromised rendezvous can withhold a record or serve a stale one, but it
cannot forge a route or substitute another identity's, because it does not hold
the agent's key. Swapping the single rendezvous for a real overlay (libp2p, or
UDNA's DHT when its baseline lands) reuses this record format and verification
unchanged and plugs in behind the same channel seam.

## What "route by DID" means

The DID Document (the json with the DID and public key) is a key store, not
a routing target. Its job is to give you the public key so you can verify
signatures. Location comes from elsewhere. In `did:web`, the location is a
`serviceEndpoint` you fetch over DNS and HTTPS. In identity-first routing, the
agent publishes a signed route record under its DID and a resolver maps the DID
to the agent's current endpoint, so there is no domain to seize and no DNS to
poison. The key is the constant; the location is dynamic and self-published.

## Payload preservation

The message is a `VouchEnvelope` that carries three things unchanged: the
signed Vouch credential (with its Data Integrity proof), liability
attestations, and provenance metadata. A JCS-canonical SHA-256 content
digest is verified on receipt, so the trust properties hold whichever path
the bytes take. Switching transports never re-signs or strips the payload.

## Quick start

```python
from vouch import Signer, generate_identity
from vouch.transport import TransportManager, build_envelope

kp = generate_identity(domain="agent.example.com")
signer = Signer(private_key=kp.private_key_jwk, did=kp.did)
credential = signer.sign(intent={
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

To reach an agent by DID over a rendezvous instead of did:web:

```python
from vouch.transport import (
    HttpRendezvousResolver, HttpRendezvousChannel, build_route_record,
)

# The agent announces its current inbox, signed under its DID.
resolver = HttpRendezvousResolver("https://rendezvous.example.com")
await resolver.announce(build_route_record(
    did=agent_did, endpoint="https://agent.example/inbox", private_key=agent_ed25519,
))

# A sender that knows only the DID resolves it and delivers, verifying locally.
channel = HttpRendezvousChannel(resolver)
reply = await channel.exchange(f"udna://{agent_did}/vouch.message", frame)
```

The UDNA SDK is an optional extra (`pip install vouch-protocol[udna]`). Without
it, the SDK-backed path stays dormant and dispatch falls through to HTTP or the
rendezvous, so the code above runs unchanged.

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

- `docs/HYBRID_TRANSPORT.md` for the architecture and the rendezvous resolver.
- `docs/udna-upstream-proposal.md` for interoperability notes, including the
  handshake confidentiality finding and an ephemeral-X25519-with-HKDF approach.
