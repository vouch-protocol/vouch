#!/usr/bin/env python3
"""
The Rogue Agent: a 60-second demo of why AI agents need Vouch.

Run it:

    pip install vouch-protocol
    python 00_the_rogue_agent.py

It tells one story in three acts:
  1. A real agent acts, and the verifier accepts it.
  2. A rogue agent tries to impersonate it, and the verifier rejects it.
  3. An attacker tampers with a real credential, and the verifier rejects it.

Identity you cannot fake. Authority you cannot forge. Actions you cannot alter.
No servers, no setup, no keys to manage. Everything runs locally.
"""

import copy
import time

from vouch import Signer, Verifier, generate_identity

# Minimal ANSI styling so the story reads well in a terminal or a screenshot.
G = "\033[92m"   # green
R = "\033[91m"   # red
Y = "\033[93m"   # yellow
B = "\033[94m"   # blue
DIM = "\033[2m"
BOLD = "\033[1m"
END = "\033[0m"


def line(char="-", n=64):
    print(DIM + char * n + END)


def pause(seconds=0.6):
    time.sleep(seconds)


def verdict(accepted: bool):
    if accepted:
        return f"{G}{BOLD}ACCEPTED{END}"
    return f"{R}{BOLD}REJECTED{END}"


def main() -> None:
    print()
    print(f"{BOLD}THE ROGUE AGENT{END}  {DIM}a Vouch Protocol demo{END}")
    line("=")
    print("An AI agent is about to act on a real system. The only question")
    print("that matters: can we prove who it is and what it is allowed to do?")
    print()
    pause()

    # ------------------------------------------------------------------
    # Setup: one real agent, and the public key the verifier trusts for it.
    # ------------------------------------------------------------------
    agent = generate_identity(domain="support-agent.acme.com")
    agent_signer = Signer(private_key=agent.private_key_jwk, did=agent.did)
    # The verifier knows the agent's published public key (in production this
    # comes from the agent's DID Document, resolved over HTTPS or did:key).
    trusted_public_key = agent.public_key_jwk

    print(f"{B}The agent:{END} {agent.did}")
    print(f"{DIM}The verifier trusts only this agent's published public key.{END}")
    print()
    pause()

    # ------------------------------------------------------------------
    # ACT 1: the real agent does its job.
    # ------------------------------------------------------------------
    print(f"{BOLD}Act 1.{END} The real agent reads an order it was authorized to read.")
    line()
    real_credential = agent_signer.sign_credential(
        intent={
            "action": "read",
            "target": "order:1042",
            "resource": "https://api.acme.com/orders/1042",
        },
        valid_seconds=300,
        reputation_score=92,
    )
    ok, passport = Verifier.verify_credential(real_credential, public_key=trusted_public_key)
    print(f"  action     : read order:1042")
    print(f"  signed by  : {real_credential['issuer']}")
    print(f"  verifier   : {verdict(ok)}")
    if ok and passport is not None:
        print(f"  {G}proven{END}    : this action was authorized by {passport.sub}")
    print()
    pause()

    # ------------------------------------------------------------------
    # ACT 2: a rogue agent tries to impersonate the real one.
    # ------------------------------------------------------------------
    print(f"{BOLD}Act 2.{END} A rogue agent forges a credential in the real agent's name.")
    line()
    rogue = generate_identity(domain="rogue.evil.example")
    # The rogue claims to BE the real agent (same DID) but signs with its own
    # key. This is the classic impersonation attempt.
    impersonator = Signer(private_key=rogue.private_key_jwk, did=agent.did)
    forged_credential = impersonator.sign_credential(
        intent={
            "action": "refund",
            "target": "order:1042",
            "resource": "https://api.acme.com/orders/1042/refund",
        },
        valid_seconds=300,
        reputation_score=99,
    )
    ok_forged, _ = Verifier.verify_credential(forged_credential, public_key=trusted_public_key)
    print(f"  action     : refund order:1042  {R}(never authorized){END}")
    print(f"  claims to be: {forged_credential['issuer']}")
    print(f"  signed with : a different, attacker-controlled key")
    print(f"  verifier   : {verdict(ok_forged)}")
    print(f"  {G}why{END}        : the signature does not match the real agent's key.")
    print(f"               you cannot wear an identity you do not hold.")
    print()
    pause()

    # ------------------------------------------------------------------
    # ACT 3: an attacker tampers with a genuine credential.
    # ------------------------------------------------------------------
    print(f"{BOLD}Act 3.{END} An attacker intercepts a real credential and edits it.")
    line()
    tampered = copy.deepcopy(real_credential)
    # Quietly escalate the action from a harmless read to a destructive one.
    tampered["credentialSubject"]["intent"]["action"] = "delete_all_orders"
    tampered["credentialSubject"]["intent"]["resource"] = "https://api.acme.com/orders"
    ok_tampered, _ = Verifier.verify_credential(tampered, public_key=trusted_public_key)
    print(f"  original   : read order:1042")
    print(f"  altered to : {R}delete_all_orders{END}")
    print(f"  verifier   : {verdict(ok_tampered)}")
    print(f"  {G}why{END}        : the proof is bound to the exact bytes that were signed.")
    print(f"               change one field and the proof breaks.")
    print()
    pause()

    # ------------------------------------------------------------------
    # Close.
    # ------------------------------------------------------------------
    line("=")
    results_ok = ok and (not ok_forged) and (not ok_tampered)
    if results_ok:
        print(f"{G}{BOLD}Identity you cannot fake. Authority you cannot forge. Actions you cannot alter.{END}")
    else:
        print(f"{R}Demo invariant failed. Expected accept, reject, reject.{END}")
    print()
    print(f"{DIM}This is Vouch Protocol. Give your AI agents a verifiable identity.{END}")
    print(f"{DIM}https://github.com/vouch-protocol/vouch{END}")
    print()

    # Exit non-zero if the security invariants did not hold, so CI and the
    # build loop catch any regression.
    raise SystemExit(0 if results_ok else 1)


if __name__ == "__main__":
    main()
