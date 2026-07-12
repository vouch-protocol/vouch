"""
Executable caveats: a grantor's condition that binds an agent two hops down the
delegation chain and cannot be dropped.

Static delegation narrows action/target/resource. Caveats add live conditions
("only shipped orders", "under the customer's lifetime spend", "business hours")
that travel with the capability, accumulate down the chain, and that every
verifier must evaluate.

Run:
    python examples/caveats_demo.py
"""

from vouch import Signer, generate_identity
from vouch.caveats import (
    build_capability,
    chain_caveats,
    flag_true,
    time_window,
    value_ceiling,
    verify_capability,
)


def main() -> None:
    store_kp = generate_identity(domain="store.example.com")
    store = Signer(private_key=store_kp.private_key_jwk, did=store_kp.did)
    mgr_kp = generate_identity(domain="manager.example.com")
    mgr = Signer(private_key=mgr_kp.private_key_jwk, did=mgr_kp.did)
    agent_kp = generate_identity(domain="refund-agent.example.com")
    agent = Signer(private_key=agent_kp.private_key_jwk, did=agent_kp.did)

    keys = {
        store.get_did(): store_kp.public_key_jwk,
        mgr.get_did(): mgr_kp.public_key_jwk,
        agent.get_did(): agent_kp.public_key_jwk,
    }

    # store -> manager: may refund in the EU, but ONLY for shipped orders.
    link1 = build_capability(
        store,
        to=mgr.get_did(),
        attenuation={"action": "refund", "target": "store:eu"},
        caveats=[flag_true("shipped-only", field="shipped")],
    )
    # manager -> agent: attenuates to <= $200 and ADDS two more caveats.
    link2 = build_capability(
        mgr,
        to=agent.get_did(),
        attenuation={"action": "refund", "target": "store:eu", "resource": "usd:<=200"},
        caveats=[
            value_ceiling("under-200", field="amount", limit=200),
            time_window("business-hours", start=9, end=17),
        ],
        parent=link1,
    )
    chain = [link1, link2]
    print("chain: store -> manager (shipped-only) -> agent (+under-200, +business-hours)")
    print("agent's effective caveats:", [c["id"] for c in chain_caveats(chain)], "\n")

    def check(label, ctx):
        r = verify_capability(chain, keys.get, ctx, root_issuer=store.get_did())
        print(
            f"  {'ALLOW ' if r is None else 'DENY  '} {label}" + ("" if r is None else f"  -> {r}")
        )

    check("refund $120, shipped, 11:00", {"amount": 120, "shipped": True, "hour": 11})
    check("refund $120 on an UNSHIPPED order", {"amount": 120, "shipped": False, "hour": 11})
    check("refund $5000 (over the $200 ceiling)", {"amount": 5000, "shipped": True, "hour": 11})
    check("refund $120 at 22:00 (out of hours)", {"amount": 120, "shipped": True, "hour": 22})

    # Attack: the agent presents ONLY its own link, trying to shed 'shipped-only'.
    print("\nAttack: present a chain that does not root at the store (drops shipped-only):")
    r = verify_capability(
        [link2],
        keys.get,
        {"amount": 120, "shipped": False, "hour": 11},
        root_issuer=store.get_did(),
    )
    print(f"  DENY   shortened chain -> {r}  (cannot shed an ancestor caveat)")

    print(
        "\nThe store's condition travels with the capability and binds an agent two\n"
        "hops away. No downstream holder can drop it, and the verifier must run\n"
        "every accumulated caveat, offline, with no policy server."
    )


if __name__ == "__main__":
    main()
