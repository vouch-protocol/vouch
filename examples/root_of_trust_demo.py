"""
Root of Trust for Machine Identity: end-to-end demo.

Shows Vouch Protocol acting as the trust anchor for AI agent identity. A
verifier pins ONE root, then verifies an agent it has never seen before,
entirely offline, and rejects a forgery.

Run:  python examples/root_of_trust_demo.py
"""

from vouch.signer import Signer
from vouch.root_of_trust import (
    ACTION_ISSUE_AGENT_IDENTITY,
    build_agent_identity,
    build_recognized_issuer,
    build_root_of_trust,
    generate_did_key_identity,
    verify_identity_chain,
)


def signer(label: str) -> Signer:
    keys = generate_did_key_identity()
    print(f"  {label:<24} {keys.did}")
    return Signer.from_keypair(keys)


def main() -> None:
    print("Identities (each self-generated, no external CA):")
    root = signer("Vouch root")
    acme = signer("Acme (an issuer)")
    agent = signer("Acme's agent #1007")
    print()

    # The root recognizes Acme as an issuer allowed to attest agent identity.
    recognition = build_recognized_issuer(
        root, issuer_did=acme.did, recognized_actions=[ACTION_ISSUE_AGENT_IDENTITY]
    )

    # Acme issues agent #1007 an identity binding its key to real attributes.
    identity = build_agent_identity(
        acme,
        subject_did=agent.did,
        attributes={"owner": "Acme", "model": "gpt-x", "capabilityClass": "shopping"},
    )

    # The agent signs an action with its own key.
    action = agent.sign(
        intent={
            "action": "buy",
            "target": "store",
            "resource": "https://store.example/item/headphones",
        }
    )

    # A verifier that pins ONLY the root DID verifies the whole chain offline.
    result = verify_identity_chain(
        identity,
        recognition,
        trusted_root=root.did,
        action_credential=action,
    )
    print("Legitimate agent:")
    print(f"  verified   : {result.ok}")
    print(f"  agent      : {result.agent_did}")
    print(f"  issuer     : {result.issuer_did}")
    print(f"  attributes : {result.attributes}")
    print(f"  action     : {result.action.action} -> {result.action.resource}")
    print()

    # A forger stands up their own root and recognizes themselves. It fails
    # because the verifier only trusts the real root it pinned.
    forger_root = signer("Forger's own root")
    forged_recognition = build_recognized_issuer(forger_root, issuer_did=acme.did)
    forged = verify_identity_chain(identity, forged_recognition, trusted_root=root.did)
    print("Forged recognition (signed by a root the verifier did not pin):")
    print(f"  verified   : {forged.ok}")
    print(f"  reason     : {forged.reason}")


if __name__ == "__main__":
    main()
