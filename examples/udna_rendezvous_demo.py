"""
Vouch Protocol: identity-first routing demo (rendezvous resolver)

Shows the piece UDNA needs and the reference SDK does not have yet: resolving a
DID to where the agent is right now, with the route signed by the agent, and no
DNS in the path.

  1. A receiving agent announces a signed route record under its did:key.
  2. A sender, knowing only the DID, resolves it to the current endpoint.
  3. The sender delivers a sealed Vouch envelope, and the proof is preserved.

Run:  python examples/udna_rendezvous_demo.py
"""

import asyncio
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto.common import base64url_decode

from vouch import Signer, generate_identity
from vouch.transport import (
    RendezvousChannel,
    RendezvousRegistry,
    build_envelope,
    build_route_record,
    route_fingerprint,
    udna_address,
)
from vouch.transport.did_key import did_key_from_public_jwk


def _priv(private_key_jwk: str) -> Ed25519PrivateKey:
    seed = base64url_decode(json.loads(private_key_jwk)["d"])
    return Ed25519PrivateKey.from_private_bytes(seed)


async def main():
    print("\nIdentity-first routing demo (no DNS)\n" + "=" * 40)

    # The receiving agent's identity, as a did:key derived from its Vouch key.
    agent = generate_identity()
    agent_did = did_key_from_public_jwk(agent.public_key_jwk)
    agent_priv = _priv(agent.private_key_jwk)
    print(f"Agent DID:        {agent_did[:40]}...")
    print(f"Routing key:      {route_fingerprint(agent_did)[:16]}...  (sha256 of the DID)")

    registry = RendezvousRegistry()
    channel = RendezvousChannel(registry)

    # 1. The agent registers an inbox and announces its current route, signed.
    async def inbox(frame: bytes) -> bytes:
        msg = json.loads(frame)
        print(f"   inbox received envelope for {msg['to'][:32]}...")
        return json.dumps({"status": "delivered"}).encode("utf-8")

    channel.register_inbox("inproc://agent-node-7", inbox)
    record = build_route_record(
        did=agent_did, endpoint="inproc://agent-node-7", private_key=agent_priv
    )
    registry.announce(record)
    print("\n[1] Agent announced a signed route record")
    print(f"    endpoint:  {record.endpoint}")
    print(f"    signature: {record.signature[:20]}...  (Ed25519 over the record)")

    # 2. A sender knows only the DID. Resolve it to the live endpoint.
    addr = udna_address(agent_did)
    print("\n[2] Sender resolves the DID, with no DNS")
    print(f"    udna address: {addr[:48]}...")
    print(f"    reachable:    {await channel.reachable(addr)}")

    # 3. Deliver a sealed Vouch envelope; the proof must survive.
    signer = Signer(private_key=agent.private_key_jwk, did="did:web:sender.example.com")
    credential = signer.sign(
        intent={
            "action": "settle_invoice",
            "target": "invoice-42",
            "resource": "https://api.example.com/invoices/42",
        }
    )
    envelope = build_envelope(
        from_did="did:web:sender.example.com", to_did=agent_did, payload=credential
    )
    print("\n[3] Sender delivers a sealed envelope over the resolved route")
    reply = await channel.exchange(addr, json.dumps(envelope.to_wire()).encode("utf-8"))
    print(f"    reply: {json.loads(reply)}")

    # 4. Tamper check: a forged route cannot be announced.
    print("\n[4] A forged route record is rejected")
    record.endpoint = "inproc://attacker"
    try:
        registry.announce(record)
        print("    ERROR: forged record accepted")
    except ValueError as exc:
        print(f"    rejected: {exc}")

    print("\nDone.\n")


if __name__ == "__main__":
    asyncio.run(main())
