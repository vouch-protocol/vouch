"""
Reasoned Action Proofs: bind an agent's justification to the action it takes.

Vouch proves *who* acted and *under what authority*. This demo adds the *why*: the
agent states a structured justification, anchors every reason to a real artifact,
commits it to a neutral escrow BEFORE acting, and signs an action credential that
carries the commitment. An auditor can then prove the reasoning was not fabricated
and not rewritten after the fact.

Run:
    python examples/reasoned_action_demo.py
"""

from datetime import datetime, timedelta, timezone

from vouch import Signer, generate_identity
from vouch.reasoning import (
    LocalEscrow,
    build_justification,
    evidence_anchor,
    justification_digest,
    sign_reasoned_action,
    verify_justification,
    verify_reasoned_action,
)


def main() -> None:
    # Three parties: the controller who delegated, the agent, and a neutral escrow.
    controller_kp = generate_identity(domain="controller.example.com")
    controller = Signer(private_key=controller_kp.private_key_jwk, did=controller_kp.did)

    agent_kp = generate_identity(domain="agent.example.com")
    agent = Signer(private_key=agent_kp.private_key_jwk, did=agent_kp.did)

    escrow_kp = generate_identity(domain="escrow.example.com")
    escrow = LocalEscrow(Signer(private_key=escrow_kp.private_key_jwk, did=escrow_kp.did))

    # Real artifacts the agent is entitled to cite, each content-addressed.
    delegation_link = controller.sign(
        intent={"action": "delete", "target": "filesystem", "resource": "/tmp/*"}
    )
    user_message = {
        "from": "did:web:alice.example",
        "text": "please clean up the temp cache in /tmp",
    }

    # 1) The agent states WHY, anchoring each reason to an artifact by its hash.
    intent = {"action": "delete", "target": "/tmp/cache", "resource": "/tmp/cache/*"}
    justification = build_justification(
        intent,
        [
            evidence_anchor(
                "user requested cleanup of /tmp",
                ref="msg:conversation/c-42/turn-3",
                evidence=user_message,
                anchor_type="user_message",
            ),
            evidence_anchor(
                "delegation authorizes deleting /tmp/*",
                ref="cred:" + delegation_link["id"],
                evidence=delegation_link,
                anchor_type="delegation",
            ),
        ],
        commitment_level=3,
    )

    # 2) Commit the justification to escrow BEFORE acting (escrow sees only the digest).
    committed_at = datetime.now(timezone.utc)
    receipt = escrow.deposit(
        agent_did=agent.get_did(),
        committed_digest=justification_digest(justification),
        deposited_at=committed_at,
    )

    # 3) Execute: the action credential carries the commitment + the escrow receipt.
    action = sign_reasoned_action(
        agent,
        intent=intent,
        justification=justification,
        escrow_receipt=receipt,
        valid_from=committed_at + timedelta(seconds=1),
    )
    print("action credential id: ", action["id"])
    print(
        "commitment digest:    ",
        action["credentialSubject"]["justification"]["commitment"]["digest"][:20],
        "...",
    )

    # ---- Auditor, after the fact ----
    ok, subject = verify_reasoned_action(
        action,
        agent_kp.public_key_jwk,
        escrow_public_key=escrow_kp.public_key_jwk,
        require_escrow=True,
    )
    print("\naction verifies?      ", ok, "(proof valid, escrowed before execution)")

    # Resolve the cited artifacts and confirm the reasoning is genuine.
    resolver = {
        "msg:conversation/c-42/turn-3": user_message,
        "cred:" + delegation_link["id"]: delegation_link,
    }
    good, reason = verify_justification(justification, subject, resolver=resolver.get)
    print("justification genuine?", good, "(every reason resolves and hashes match)")

    # ---- Two attacks this defeats ----
    print("\nAttacks:")

    # A) Fabricate a reason with no real artifact behind it.
    forged = build_justification(
        intent,
        [
            evidence_anchor(
                "the CFO approved this by phone", ref="call:none", evidence={"fake": True}
            )
        ],
    )
    # The forged justification does not match the committed digest...
    _, r1 = verify_justification(forged, subject, resolver=resolver.get)
    print("  fabricated reason:  rejected ->", r1)

    # B) Rewrite the justification after acting (target /etc/passwd instead).
    rewritten = build_justification(
        {"action": "delete", "target": "/etc/passwd", "resource": "/etc/*"},
        justification["evidenceAnchors"],
    )
    _, r2 = verify_justification(rewritten, subject, resolver=resolver.get)
    print("  post-hoc rewrite:   rejected ->", r2)

    print(
        "\nResidual: a capable deceiver can still write a plausible reason anchored to\n"
        "real evidence. This PRICES deception (a false justification is provable\n"
        "perjury on the record); semantic quorum and behavioral bonds raise the price."
    )


if __name__ == "__main__":
    main()
