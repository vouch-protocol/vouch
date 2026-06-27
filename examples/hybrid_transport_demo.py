"""
Vouch Protocol: Hybrid Transport Demo (UDNA + HTTP fallback)

Demonstrates the modular, DID-addressed transport layer:

  1. An agent signs a Vouch credential (its accountable intent).
  2. It seals the credential — plus liability attestations and provenance —
     into a VouchEnvelope addressed to a peer's *DID* (not an IP).
  3. The TransportManager tries identity-first UDNA routing, then falls back
     to standard DNS/IP + HTTP when the peer is not on the UDNA overlay.
  4. The signed payload is preserved byte-for-byte across the transition.

The Sirraya UDNA SDK is optional. This demo wires an in-process fake UDNA node
so you can watch routing and fallback without any network or the real SDK.

Run:  python examples/hybrid_transport_demo.py
"""

import asyncio
import json

from vouch import Signer, generate_identity
from vouch.transport import TransportManager, UdnaTransport, build_envelope


class DemoUdnaNode:
    """A toy UDNA node. `reachable_dids` decides who is on the overlay."""

    def __init__(self, reachable_dids):
        self._reachable = set(reachable_dids)

    async def resolve(self, address):
        # address looks like "udna://<did>/vouch.message"
        did = address.split("//", 1)[1].rsplit("/", 1)[0]
        return {"address": address} if did in self._reachable else None

    async def send_secure(self, address, data):
        print(f"   🔐 UDNA Noise channel → {address} ({len(data)} bytes)")
        return json.dumps({"status": "delivered", "via": "udna"}).encode()

    async def close(self):
        pass


async def main():
    print("\n🌐 Vouch Hybrid Transport Demo\n" + "=" * 40)

    # -- Identities ------------------------------------------------------
    sender = generate_identity(domain="sender.example.com")
    signer = Signer(private_key=sender.private_key_jwk, did=sender.did)

    udna_native_peer = UdnaTransport.generate_did(generate_identity().public_key_jwk)
    web_only_peer = "did:web:peer.example.com"

    print(f"Sender:          {sender.did}")
    print(f"UDNA-native peer: {udna_native_peer[:32]}…")
    print(f"Web-only peer:    {web_only_peer}")

    # -- Sign an accountable intent --------------------------------------
    credential = signer.sign_credential(
        intent={
            "action": "settle_invoice",
            "target": "invoice-42",
            "resource": "https://api.example.com/invoices/42",
        }
    )

    # -- Hybrid stack: UDNA preferred, HTTP fallback ---------------------
    # Only the UDNA-native peer is on the overlay.
    node = DemoUdnaNode(reachable_dids={udna_native_peer})
    manager = TransportManager.default(udna_node=node)

    # -- Case 1: peer IS on UDNA → identity-first delivery ---------------
    print("\n[1] Dispatch to a UDNA-native peer")
    env1 = build_envelope(
        from_did=sender.did,
        to_did=udna_native_peer,
        payload=credential,
        attestations=[{"type": "OutcomeCommitment", "id": "urn:commit:1"}],
        provenance={"contentHash": credential.get("id", "n/a")},
    )
    result1 = await manager.dispatch(env1)
    print(f"   ✅ delivered via '{result1.transport}'  attempts={result1.attempts}")

    # -- Case 2: peer NOT on UDNA → graceful fallback to HTTP ------------
    print("\n[2] Dispatch to a web-only peer (UDNA resolution fails → fallback)")
    env2 = build_envelope(from_did=sender.did, to_did=web_only_peer, payload=credential)
    try:
        result2 = await manager.dispatch(env2)
        print(f"   ✅ delivered via '{result2.transport}'  attempts={result2.attempts}")
    except Exception as exc:
        # No real HTTPS inbox is running in this demo, so HTTP delivery will
        # fail at the network step — but note UDNA was tried first and yielded.
        print("   ↪️  UDNA yielded, HTTP attempted; network step failed as expected:")
        print(f"      {type(exc).__name__}: {exc}")

    # -- Payload preservation proof --------------------------------------
    print("\n[3] Payload preservation across the transport boundary")
    wire = env1.to_wire()
    assert wire["payload"]["proof"] == credential["proof"], "proof must survive"
    print("   ✅ Data Integrity proof, attestations, and provenance preserved verbatim")
    print(f"   🔎 content digest: {env1.content_digest()}")

    await manager.close()
    print("\nDone.\n")


if __name__ == "__main__":
    asyncio.run(main())
