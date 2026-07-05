#!/usr/bin/env python3
"""One command end to end: an AI agent authorizes real actions with Vouch.

    python demo/e2e/run_demo.py

What it shows, in one process tree:

  1. An identity is minted for the agent.
  2. The private key is handed to a *separate* signing sidecar (the published
     vouch-mcp server) and stays there. The agent process never holds it.
  3. The agent decides on an action and signs that intent through the sidecar
     over MCP. One line of Vouch code in the agent.
  4. A bank verifies the credential and enforces the exact intent binding.
  5. A replayed credential aimed at a different account is rejected.
  6. The same flow runs under the post-quantum profile.
  7. A trust-decaying session voucher (Heartbeat Protocol) is issued.

No API keys and no network are required. The agent logic is deterministic so
the cryptographic pipeline is the only thing on display. To drive it with a
real LLM agent (LangChain, CrewAI, Google ADK), wrap the single sidecar.sign
call as a tool; examples/05_integrations/ has the per-framework glue.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

# Run against the repo's vouch package (and make the sidecar child do the same),
# rather than any older copy installed in site-packages. This also lets the
# sibling role modules import each other from any working directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, _HERE)
os.environ["PYTHONPATH"] = os.pathsep.join(
    p for p in (_REPO_ROOT, os.environ.get("PYTHONPATH", "")) if p
)

from agent import BANK_API, make_payment  # noqa: E402
from bank import Bank  # noqa: E402
from vouch.keys import generate_identity  # noqa: E402
from vouch_sidecar import VouchSidecar  # noqa: E402


# ---- tiny terminal styling ---------------------------------------------------

_USE_COLOR = sys.stdout.isatty() and not os.getenv("NO_COLOR")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def cyan(t: str) -> str:
    return _c("36", t)


def green(t: str) -> str:
    return _c("32", t)


def red(t: str) -> str:
    return _c("31", t)


def yellow(t: str) -> str:
    return _c("33", t)


def dim(t: str) -> str:
    return _c("2", t)


def scene(title: str) -> None:
    print()
    print(cyan("━━━ " + title + " ━━━"))


def verdict(accepted: bool, reason: str) -> None:
    if accepted:
        print(green("  ACCEPTED: ") + reason)
    else:
        print(red("  REJECTED: ") + reason)


async def main() -> int:
    print(cyan("╔══════════════════════════════════════════════════════════╗"))
    print(cyan("║   Vouch Protocol: end to end agent authorization demo    ║"))
    print(cyan("╚══════════════════════════════════════════════════════════╝"))

    # -- Setup: the operator mints an identity for the agent. ------------------
    scene("1. Mint the agent's identity")
    kp = generate_identity(domain="acme-payments.agent.example")
    print("  DID: " + yellow(kp.did))
    print(dim("  The private key is about to go to the sidecar process only."))
    print(dim("  The agent code below never receives it."))

    # -- The bank knows the agent's public key (its trust registry). -----------
    bank = Bank(trusted_did=kp.did, trusted_public_key_jwk=kp.public_key_jwk)

    # -- Start the sidecar. The key lives in its environment, nowhere else. ----
    async with VouchSidecar(kp.private_key_jwk, kp.did) as sidecar:
        scene("2. The signing sidecar is running (separate process)")
        print("  " + await sidecar.get_identity())
        print(dim("  Key holder: the vouch-mcp child process. Not the agent."))

        # -- Scene 3: an authorized payment. -----------------------------------
        scene("3. Agent signs an intent and the bank verifies it")
        request = await make_payment(sidecar, amount=500, to_account="123")
        print("  agent plan:   " + request["plan"])
        print(dim("  target:       " + BANK_API))
        print(dim("  credential:   " + request["vouch_credential"][:72] + " ..."))
        verdict(*bank.handle(request))

        # -- Scene 4: replay the credential against a different account. -------
        scene("4. An attacker replays that credential to redirect the funds")
        stolen = dict(request)
        stolen["requested_resource"] = "account:999"
        print(dim("  same valid credential, but the request now targets account:999"))
        verdict(*bank.handle(stolen))
        print(dim("  The signature is genuine. The intent binding still blocks it."))

        # -- Scene 5: post-quantum profile. ------------------------------------
        scene("5. The same flow under the post-quantum profile")
        pq = await make_payment(sidecar, amount=500, to_account="123", post_quantum=True)
        cred = pq["vouch_credential"]
        if cred.lstrip().startswith("{"):
            doc = json.loads(cred)
            proof = doc.get("proof", {})
            intent = doc.get("credentialSubject", {}).get("intent", {})
            binding_ok = intent.get("resource") == pq["requested_resource"]
            print("  cryptosuite:  " + yellow(proof.get("cryptosuite", "unknown")))
            print("  signature:    " + str(len(proof.get("proofValue", "")))
                  + " base58 chars (Ed25519 and ML-DSA-44 composite)")
            print("  binding:      " + (green("intact") if binding_ok else red("mismatch")))
            print(dim("  One flag switched the whole flow to quantum-safe signing."))
            print(dim("  A verifier completes hybrid checks with the issuer's ML-DSA"))
            print(dim("  key, published in its DID document alongside the Ed25519 key."))
        else:
            print(yellow("  skipped: ") + "install 'vouch-protocol[pq]' to sign hybrid PQ.")
            print(dim("  detail: " + cred.strip().splitlines()[0]))

        # -- Scene 6: a trust-decaying session voucher (Heartbeat). ------------
        scene("6. A trust-decaying session voucher (Heartbeat Protocol)")
        voucher_json = await sidecar.create_session("payments_session", valid_seconds=3600)
        if voucher_json.lstrip().startswith("{"):
            voucher = json.loads(voucher_json)
            subject = voucher.get("credentialSubject", {})
            print("  purpose:      payments_session")
            print("  initial trust: " + str(subject.get("initialTrust", subject.get("trust", "1.0"))))
            print(dim("  trust decays over time; a verifier can refuse once it drops."))
        else:
            print(dim("  " + voucher_json.strip().splitlines()[0]))

    # -- Summary: the point of the whole thing. --------------------------------
    scene("What just happened")
    print("  " + green("Key isolation:  ") + "the private key stayed in the sidecar process.")
    print("  " + green("Agent tax:      ") + "one line of Vouch code in the agent (sidecar.sign).")
    print("  " + green("Binding:        ") + "a genuine credential cannot be redirected.")
    print("  " + green("Future proof:   ") + "post-quantum is one flag; heartbeat is one call.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
