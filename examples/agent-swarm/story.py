#!/usr/bin/env python3
"""BAT-AGENTS: Bruce Wayne is too busy being a billionaire to fight crime in
person, so he runs Gotham on a swarm of AI agents. It goes about as well as you
would expect.

    python examples/agent-swarm/story.py

Every time an agent acts, it signs. Every time the Batmobile, a gadget, or
Gotham's safety is on the line, someone verifies. No API keys, no network.
Read it top to bottom.

Every Vouch call here is one line:
    kp   = vouch.generate_identity(...)                           # who an agent is
    cred = vouch.sign(kp, action=..., target=..., resource=...)   # what it wants
    ok,  = vouch.verify(cred, kp.public_key_jwk)                  # is it allowed
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))  # run against this repo's vouch

import vouch  # noqa: E402
from vouch import (  # noqa: E402
    MemoryRevocationStore,
    RevocationRegistry,
    compute_trust_at,
)
from vouch.autosign import delegate  # noqa: E402
from vouch.signer import Signer  # noqa: E402
from vouch.vc import build_session_voucher  # noqa: E402

_C = sys.stdout.isatty() and not os.getenv("NO_COLOR")


def c(code, t):
    return f"\033[{code}m{t}\033[0m" if _C else t


def scene(n, title):
    print()
    print(c("36", f"━━━ {n}. {title} ━━━"))


def ok(t):
    print(c("32", "  PASS  ") + t)


def no(t):
    print(c("31", "  BLOCK ") + t)


def beat(t):
    print(c("2", "  " + t))


def main():
    print(c("35", "╔══════════════════════════════════════════════════════════════╗"))
    print(c("35", "║   BAT-AGENTS: Bruce Wayne runs Gotham on AI interns          ║"))
    print(c("35", "║   (a Vouch Protocol story, told in one-liners)               ║"))
    print(c("35", "╚══════════════════════════════════════════════════════════════╝"))

    # 1 -------------------------------------------------------------------------
    scene(1, "Bruce has 9 board meetings and unresolved trauma. Batman is an AI now.")
    batman = vouch.generate_identity(domain="the-batman.gotham")
    beat("Bruce: 'I cannot be in two places at once.'  Alfred: 'Sir, you have an agent for that.'")
    print("  Batman's identity (DID): " + c("33", batman.did))

    # 2 -------------------------------------------------------------------------
    scene(2, "Batman signs off on rolling the Batmobile to the docks")
    order = vouch.sign(
        batman,
        action="deploy",
        target="gcpd.gotham.gov",
        resource="batmobile:docks-pursuit",
    )
    beat("One line to sign the intent:")
    beat("order = vouch.sign(batman, action='deploy', target=..., resource=...)")
    print("  signed. cryptosuite: " + c("33", order["proof"]["cryptosuite"]))

    # 3 -------------------------------------------------------------------------
    scene(3, "Commissioner Gordon verifies before lighting a 40-foot spotlight")
    valid, who = vouch.verify(order, batman.public_key_jwk)
    beat("ok, who = vouch.verify(order, batman.public_key_jwk)")
    if valid:
        ok(f"deployment authorized by {who.iss}")
        beat("Gordon: 'It's really him. Light the signal.'")

    # 4 -------------------------------------------------------------------------
    scene(4, "The Joker deploys a fake Batman to send the Batmobile to his lair")
    joker = vouch.generate_identity(domain="totally-the-real-batman.joker-lol")
    fake = vouch.sign(
        joker,
        action="deploy",
        target="gcpd.gotham.gov",
        resource="batmobile:joker-lair",
    )
    # Gordon only trusts the real Batman's key. He checks the fake against it.
    valid, _ = vouch.verify(fake, batman.public_key_jwk)
    beat("Gordon checks 'Batman's' new order against the real Batman's key ...")
    if not valid:
        no("signature does not match Batman. Nice try, clown.")

    # 5 -------------------------------------------------------------------------
    scene(5, "Batman hires Robin, who may patrol and touch NOTHING else")
    robin = vouch.generate_identity(domain="robin.sidekick.gotham")
    grant = delegate(
        action="patrol",
        target="crime-alley.gotham",
        resource="beat:crime-alley",
        to=robin.did,
        signer=Signer.from_keypair(batman),
    )
    beat(
        "grant = vouch.delegate(action='patrol', target='crime-alley', resource='beat:crime-alley')"
    )
    a_patrol = vouch.sign(
        robin,
        action="patrol",
        target="crime-alley.gotham",
        resource="beat:crime-alley",
        parent_credential=grant,
    )
    valid, _ = vouch.verify(a_patrol, robin.public_key_jwk)
    if valid:
        ok("Robin patrols Crime Alley (chained under Batman's grant).")
    beat("Robin CANNOT requisition the Batwing: a child credential may only narrow")
    beat("the grant, never widen it (the resource-narrowing rule). Patrol stays patrol.")

    # 6 -------------------------------------------------------------------------
    scene(6, "Every gadget Batman deploys now auto-signs, with one decorator")

    @vouch.signed(action="deploy", target="batcave.armory")
    def deploy_gadget(resource, vouch_credential=None):
        # The credential is signed and injected before this body ever runs.
        return resource, (vouch_credential or {}).get("proof", {}).get("cryptosuite")

    res, suite = deploy_gadget(resource="gadget:grappling-hook")
    beat("@vouch.signed(action='deploy', target='batcave.armory') def deploy_gadget(...): ...")
    ok(f"deploy_gadget() auto-signed the {res} ({suite})")

    # 7 -------------------------------------------------------------------------
    scene(7, "Robin starts a vigilante side-hustle, tries to requisition a tank. Bench him.")
    store = MemoryRevocationStore()
    registry = RevocationRegistry(local_store=store)

    async def bench_and_check():
        await registry.revoke(
            robin.did,
            reason="unsanctioned side-hustle; attempted to requisition a tank",
            revoked_by=batman.did,
        )
        return await registry.is_revoked(robin.did)

    revoked = asyncio.run(bench_and_check())
    beat("await registry.revoke(robin.did, reason='went rogue')")
    if revoked:
        no("the armory checks is_revoked(robin) -> True. Robin is benched. Again.")

    # 8 -------------------------------------------------------------------------
    scene(8, "Batman signs Bruce Wayne's identity file, quantum-safe (secret forever)")
    pq = Signer.from_keypair(batman).sign_hybrid(
        {
            "action": "seal",
            "target": "batcomputer.batcave",
            "resource": "identity:bruce-wayne",
        }
    )
    beat("Signer.from_keypair(batman).sign_hybrid({...})")
    print("  cryptosuite: " + c("33", pq["proof"]["cryptosuite"]))
    beat("Ed25519 + ML-DSA-44: the Riddler will still be guessing in the year 3024.")

    # 9 -------------------------------------------------------------------------
    scene(9, "Batman has not slept in 72 hours, so we trust his judgment LESS by the hour")
    now = datetime.now(timezone.utc)
    voucher = build_session_voucher(
        subject_did=batman.did,
        validator_dids=[vouch.generate_identity(domain="alfred.batcave").did],
        decay_lambda=0.00007,
        initial_trust=1.0,
        max_ttl_seconds=86400,
        scope=["patrol"],
        valid_seconds=86400,
    )
    beat("Session trust decays (Heartbeat Protocol). compute_trust_at(voucher, t):")
    for hours in (0, 3, 9):
        t = compute_trust_at(voucher, now + timedelta(hours=hours))
        bar = "#" * max(1, int(t * 30))
        print(f"  +{hours:>2}h trust {t:0.2f}  {c('32' if t > 0.5 else '31', bar)}")
    beat("Below 0.5, Alfred revokes the shark-repellent until Master Wayne takes a nap.")

    # 10 ------------------------------------------------------------------------
    scene(10, "The rookie once tazed himself. His reputation throttles him.")
    rookie = vouch.generate_identity(domain="rookie.batcave")
    bid = vouch.sign(
        rookie,
        action="deploy",
        target="batcave.armory",
        resource="gadget:the-actually-dangerous-one",
        reputation_score=12,
    )
    _, passport = vouch.verify(bid, rookie.public_key_jwk)
    rep = getattr(passport, "reputation_score", None)
    beat("vouch.sign(rookie, ..., reputation_score=12)")
    no(f"armory sees reputation {rep}/100 and keeps the good gadgets locked. Stay in the van.")

    # Curtain ------------------------------------------------------------------
    scene("*", "The reveal: every Bat-agent, a different stack; Vouch, one line each")
    print(
        "  "
        + c("32", "Batman")
        + "     runs as an MCP sidecar; Alfred holds the key (never in the model)"
    )
    print("  " + c("32", "Robin") + "      is a LangChain agent")
    print("  " + c("32", "Oracle") + "     is a CrewAI crew")
    print("  " + c("32", "Bat-Signal") + " automation is an n8n workflow")
    print("  " + c("32", "the GCPD") + "   verifies at a Hasura gateway")
    beat("Same credentials, every framework. Glue in examples/05_integrations/")
    beat("and examples/mcp-vouch/. The cape is optional. The proof is not.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
