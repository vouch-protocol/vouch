"""
Vouch Protocol: identity-first routing over commodity HTTPS.

The rendezvous resolver, made deployable. An agent announces a signed route
under its did:key to an HTTPS rendezvous; a sender that knows only the DID
resolves it to the agent's current inbox and delivers a sealed envelope. No DNS
binds the agent to a location, and the rendezvous is never trusted: the sender
re-verifies the signed record itself, so a lying rendezvous cannot forge a route.

This runs the real client against the real server logic over an in-process
transport, so it needs no network and no running server.

Run:  python examples/http_rendezvous_demo.py
"""

import asyncio
import json

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto.common import base64url_decode

from vouch import Signer, generate_identity
from vouch.transport import (
    HttpRendezvousChannel,
    HttpRendezvousResolver,
    RendezvousService,
    build_envelope,
    build_route_record,
    route_fingerprint,
    udna_address,
)
from vouch.transport.did_key import did_key_from_public_jwk
from vouch.transport.http_rendezvous import RECORDS_PATH


def _priv(private_key_jwk: str) -> Ed25519PrivateKey:
    seed = base64url_decode(json.loads(private_key_jwk)["d"])
    return Ed25519PrivateKey.from_private_bytes(seed)


async def main():
    print("\nIdentity-first routing over HTTPS (no DNS, untrusted rendezvous)\n" + "=" * 62)

    agent = generate_identity()
    agent_did = did_key_from_public_jwk(agent.public_key_jwk)
    agent_priv = _priv(agent.private_key_jwk)
    print(f"Agent DID:    {agent_did[:40]}...")
    print(
        f"Routing key:  {route_fingerprint(agent_did)[:16]}...  (sha256 of the DID, sent on the wire)"
    )

    service = RendezvousService()
    received = {}

    # One in-process transport stands in for both the rendezvous and the agent's
    # HTTPS inbox, so the demo needs no open ports.
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == RECORDS_PATH:
            status, body = service.put(json.loads(request.content))
            return httpx.Response(204) if status == 204 else httpx.Response(status, json=body)
        if request.method == "GET" and path.startswith(RECORDS_PATH + "/"):
            fingerprint = path.rsplit("/", 1)[1]
            facet = request.url.params.get("facet", "vouch.message")
            status, body = service.get(fingerprint, facet)
            return httpx.Response(status, json=body)
        if request.method == "POST" and path == "/inbox":
            received["frame"] = request.content
            print(
                f"   agent inbox received envelope for {json.loads(request.content)['to'][:32]}..."
            )
            return httpx.Response(200, json={"status": "delivered"})
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    resolver = HttpRendezvousResolver(
        "https://rv.example.com", client=client, validate_target=False
    )
    channel = HttpRendezvousChannel(resolver, client=client, validate_endpoint=False)

    # 1. The agent announces its current HTTPS inbox, signed under its DID.
    record = build_route_record(
        did=agent_did, endpoint="https://agent.example/inbox", private_key=agent_priv
    )
    await resolver.announce(record)
    print("\n[1] Agent announced a signed route to the rendezvous")
    print(f"    endpoint:  {record.endpoint}")
    print(f"    signature: {record.signature[:20]}...  (Ed25519 over the record)")

    # 2. A sender that knows only the DID resolves it, with no DNS.
    addr = udna_address(agent_did)
    print("\n[2] Sender resolves the DID over HTTPS, verifying the record itself")
    print(f"    udna address: {addr[:48]}...")
    print(f"    resolved to:  {await resolver.resolve(agent_did)}")
    print(f"    reachable:    {await channel.reachable(addr)}")

    # 3. Deliver a sealed Vouch envelope over the resolved route.
    signer = Signer(private_key=agent.private_key_jwk, did="did:web:sender.example.com")
    credential = signer.sign_credential(
        intent={
            "action": "settle_invoice",
            "target": "invoice-42",
            "resource": "https://api.example.com/invoices/42",
        }
    )
    envelope = build_envelope(
        from_did="did:web:sender.example.com", to_did=agent_did, payload=credential
    )
    print("\n[3] Sender delivers a sealed envelope over the resolved HTTPS route")
    reply = await channel.exchange(addr, json.dumps(envelope.to_wire()).encode("utf-8"))
    print(f"    reply: {json.loads(reply)}")
    delivered = json.loads(received["frame"])
    print(f"    proof preserved end to end: {delivered['payload']['proof'] == credential['proof']}")

    await channel.close()
    print("\nDone.\n")


if __name__ == "__main__":
    asyncio.run(main())
