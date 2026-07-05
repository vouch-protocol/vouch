"""
Action Transparency: an append-only log that can't hide or rewrite an action.

Consequential actions are submitted to a public Merkle log. The log signs its
size and root (a Signed Tree Head). Anyone can then demand proof that a specific
action is in the log, and that an older tree head is a strict prefix of a newer
one, so the log cannot quietly drop or rewrite history.

Run:
    python examples/transparency_demo.py
"""

from vouch import Signer, generate_identity
from vouch.transparency import (
    TransparencyLog,
    check_consistency,
    check_inclusion,
    sign_tree_head,
)


def main() -> None:
    log_kp = generate_identity(domain="log.example.com")
    log_op = Signer(private_key=log_kp.private_key_jwk, did=log_kp.did)

    log = TransparencyLog()
    actions = [
        {"agent": "did:web:agent-a", "action": "transfer_funds", "amount": "usd:5000"},
        {"agent": "did:web:agent-b", "action": "publish", "target": "blog"},
        {"agent": "did:web:agent-a", "action": "delete", "target": "db:staging-3"},
    ]
    for a in actions:
        log.append(a)

    old_sth = sign_tree_head(log_op, log)
    print("logged", old_sth["credentialSubject"]["treeSize"], "actions")
    print("root:", old_sth["credentialSubject"]["rootHash"][:22], "...")

    # A verifier demands proof that a specific action is in the log.
    proof = log.inclusion_proof(0)
    ok = check_inclusion(actions[0], 0, old_sth, proof, log_public_key=log_kp.public_key_jwk)
    print("\nwire $5000 is in the log?    ", "yes" if ok is None else f"no ({ok})")

    # An action that was never submitted cannot be proven in.
    r = check_inclusion({"agent": "did:web:rogue", "action": "exfiltrate"}, 0, old_sth, proof)
    print("a never-logged action proves in?", "no ·", r)

    # The log grows. A monitor checks the new head is a prefix of the old one.
    for a in [{"agent": "did:web:agent-c", "action": "email", "target": "vendor"}]:
        log.append(a)
    new_sth = sign_tree_head(log_op, log)
    cproof = log.consistency_proof(3)
    r = check_consistency(old_sth, new_sth, cproof, log_public_key=log_kp.public_key_jwk)
    print("\nlog appended-only (no rewrite)?", "yes" if r is None else f"no ({r})")

    # Now the log tries to REWRITE history: rebuild with entry 0 changed.
    forged = TransparencyLog()
    forged.append(
        {"agent": "did:web:agent-a", "action": "transfer_funds", "amount": "usd:50"}
    )  # was 5000
    for a in actions[1:] + [{"agent": "did:web:agent-c", "action": "email", "target": "vendor"}]:
        forged.append(a)
    forged_sth = sign_tree_head(log_op, forged)
    r = check_consistency(old_sth, forged_sth, forged.consistency_proof(3))
    print("log rewrote an old entry?      ", "detected ·", r)

    print(
        "\nPublishing every action in an append-only log makes an omitted or altered\n"
        "action impossible to hide: inclusion proofs stop silent omission, consistency\n"
        "proofs stop history rewriting, and a monitor comparing tree heads across\n"
        "observers catches a split view."
    )


if __name__ == "__main__":
    main()
