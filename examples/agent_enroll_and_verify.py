"""
Enroll an agent and verify its portable identity bundle.

Shows the one-command handoff Vouch Protocol gives the Root of Trust for Machine
Identity. An operator recognized by a root enrolls an agent into a single
portable bundle. A verifier that pins only the root DID checks the bundle
offline, and rejects a bundle that chains to a root it never pinned.

The recognized issuer is always the operator's own key, a parameter, never a
fixed authority. Anyone can stand up their own root and recognize their own
issuers, so the model stays self-sovereign.

Run:  python examples/agent_enroll_and_verify.py
"""

from vouch.signer import Signer
from vouch.root_of_trust import (
    ACTION_ISSUE_AGENT_IDENTITY,
    build_agent_identity,
    build_identity_bundle,
    build_recognized_issuer,
    build_root_of_trust,
    generate_did_key_identity,
    verify_bundle,
)


def signer(label: str) -> Signer:
    keys = generate_did_key_identity()
    print(f"  {label:<24} {keys.did}")
    return Signer.from_keypair(keys)


def main() -> None:
    print("Identities (each self-generated, no external CA):")
    root = signer("Root")
    operator = signer("Operator (an issuer)")
    agent = signer("Operator's agent")
    print()

    # The root self-describes and recognizes the operator as an issuer that may
    # attest agent identity.
    root_cred = build_root_of_trust(root, name="Vouch Machine Identity Root")
    recognition = build_recognized_issuer(
        root, issuer_did=operator.did, recognized_actions=[ACTION_ISSUE_AGENT_IDENTITY]
    )

    # Enroll: the operator attests the agent's identity, then packages the
    # identity, the recognition, and the root into one portable bundle.
    identity = build_agent_identity(
        operator,
        subject_did=agent.did,
        attributes={"owner": "Acme", "model": "gpt-x", "capabilityClass": "shopping"},
    )
    action = agent.sign(
        intent={
            "action": "buy",
            "target": "store",
            "resource": "https://store.example/item/headphones",
        }
    )
    bundle = build_identity_bundle(
        identity=identity, recognition=recognition, action=action, root=root_cred
    )

    # A verifier that pins ONLY the root DID checks the whole bundle offline.
    result = verify_bundle(bundle, trusted_root=root.did)
    print("Enrolled agent (bundle pinned to the real root):")
    print(f"  verified   : {result.ok}")
    print(f"  agent      : {result.agent_did}")
    print(f"  issuer     : {result.issuer_did}")
    print(f"  attributes : {result.attributes}")
    print(f"  action     : {result.action.action} -> {result.action.resource}")
    print()

    # A forger stands up their own root and hands out a bundle. It fails because
    # the verifier only trusts the root it pinned out of band.
    forger_root = signer("Forger's own root")
    forged_recognition = build_recognized_issuer(forger_root, issuer_did=operator.did)
    forged_bundle = build_identity_bundle(identity=identity, recognition=forged_recognition)
    forged = verify_bundle(forged_bundle, trusted_root=root.did)
    print("Forged bundle (chains to a root the verifier did not pin):")
    print(f"  verified   : {forged.ok}")
    print(f"  reason     : {forged.reason}")


if __name__ == "__main__":
    main()
