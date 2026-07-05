"""
Proof of Deliberation: make an agent wait, and let a human veto, before it does
something irreversible.

The one preventive control in Vouch: a reversible action runs instantly, but an
irreversible one (wiring funds) must announce its intent, wait out a challenge
window, and survive any veto before a verifier will accept it. The agent cannot
shorten the window and cannot clear its own veto.

Run:
    python examples/deliberation_demo.py
"""

from datetime import datetime, timedelta, timezone

from vouch import Signer, generate_identity
from vouch.deliberation import (
    CLASS_IRREVERSIBLE_FINANCIAL,
    CLASS_REVERSIBLE,
    check_execution,
    commit_intent,
    execute,
    requires_window,
    veto_intent,
)

WIRE = {"action": "transfer_funds", "target": "acct:vendor-1", "resource": "usd:5000"}


def main() -> None:
    agent_kp = generate_identity(domain="agent.example.com")
    agent = Signer(private_key=agent_kp.private_key_jwk, did=agent_kp.did)
    controller_kp = generate_identity(domain="controller.example.com")
    controller = Signer(private_key=controller_kp.private_key_jwk, did=controller_kp.did)

    # A) Reversible action: no ceremony, runs immediately.
    print("A) read a cache entry  (reversible)")
    print("   requires a deliberation window?", requires_window(CLASS_REVERSIBLE), "-> runs now\n")

    # The window for the irreversible wire: 15 minutes, controller may veto.
    opened = datetime.now(timezone.utc)
    intent = commit_intent(
        agent,
        intent=WIRE,
        reversibility_class=CLASS_IRREVERSIBLE_FINANCIAL,
        min_seconds=900,
        veto_authorities=[controller.get_did()],
        broadcast=["log://transparency.example/agent-actions"],
        opens_at=opened,
    )
    print("B) wire $5000  (irreversible-financial)")
    print(
        "   intent committed, window closes 15 min after",
        intent["credentialSubject"]["challengeWindow"]["opensAt"],
    )

    # B1) Agent tries to execute 1 minute in -> too early.
    early = execute(agent, intent_credential=intent, closed_at=opened + timedelta(minutes=1))
    r = check_execution(early, intent, agent_kp.public_key_jwk)
    print("   execute after 1 min:      rejected ->", r)

    # B2) Controller vetoes during the window -> blocked even after the window.
    veto_cred = veto_intent(
        controller, intent_credential=intent, reason="over unattended threshold"
    )
    after = execute(agent, intent_credential=intent, closed_at=opened + timedelta(minutes=20))
    r = check_execution(
        after,
        intent,
        agent_kp.public_key_jwk,
        vetoes=[veto_cred],
        veto_public_keys={controller.get_did(): controller_kp.public_key_jwk},
    )
    print("   execute after veto:       rejected ->", r)

    # B3) Clean run: window elapsed, no veto.
    clean = execute(agent, intent_credential=intent, closed_at=opened + timedelta(minutes=16))
    r = check_execution(clean, intent, agent_kp.public_key_jwk, vetoes=[], veto_public_keys={})
    print("   execute after 16 min, no veto:", "ACCEPTED" if r is None else f"rejected -> {r}")

    print(
        "\nThe verifier, not the agent, decides when the money can move. The agent\n"
        "cannot shorten the window (elapse is checked) and cannot clear its own veto\n"
        "(the veto authority is a different DID). Reversible actions pay no delay."
    )


if __name__ == "__main__":
    main()
