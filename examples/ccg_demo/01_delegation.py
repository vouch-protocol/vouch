#!/usr/bin/env python3
"""
Delegation that can only narrow.

Alice grants her assistant read and update on her calendar, with a spend cap of
$50. The assistant re-delegates to a sub-agent: read only, cap $20. Every case
below is decided by the verifier from the credential alone: the signed grants
travel inside the delegation chain, so no policy server is consulted.

Where a case is DENIED, two things are shown: the honest signer refuses to
issue the wider credential, and a credential built by hand to get around the
signer is still refused by the verifier.

Run: python3 examples/ccg_demo/01_delegation.py
"""

from __future__ import annotations

import base64
import copy
import json
import sys
from datetime import datetime, timedelta, timezone

from vouch import Signer, generate_identity, multikey
from vouch.verifier import Verifier, verify_delegation_chain

CALENDAR = "https://calendar.example.com/alice"
T0 = datetime(2026, 11, 10, 17, 0, 0, tzinfo=timezone.utc)  # fake clock
NOW = T0 + timedelta(minutes=1)

results = []
keypairs = {}  # label -> generated keypair, held in memory only, never printed


def identity(label: str) -> Signer:
    """A did:key identity: self-certifying, so it resolves with no network."""
    kp = generate_identity()
    keypairs[label] = kp
    raw = base64.urlsafe_b64decode(json.loads(kp.public_key_jwk)["x"] + "==")
    return Signer(
        private_key=kp.private_key_jwk, did="did:key:" + multikey.encode_ed25519_public(raw)
    )


alice = identity("alice")
assistant = identity("assistant")
sub_agent = identity("sub-agent")
grandchild = identity("grandchild")
mallory = identity("mallory")


def report(case: str, expected: str, actual: str, detail: str) -> None:
    mark = "ok" if expected == actual else "UNEXPECTED"
    results.append(expected == actual)
    print(f"  {case:<52} {actual:<8} {detail}  [{mark}]")


def verdict(credential, holder: Signer):
    """Verify the way a calendar API would: the holder's signature, its chain,
    and that the chain roots at Alice."""
    ok, _ = Verifier.verify(
        credential,
        public_key=holder.get_public_key_multikey(),
        trusted_roots=[alice.did],
        now=NOW,
    )
    reason = verify_delegation_chain(credential, trusted_roots=[alice.did], now=NOW)
    return ("ALLOWED" if ok else "DENIED"), (reason or "chain verified to alice")


def try_sign(signer: Signer, intent, parent):
    try:
        signer.sign(intent=intent, parent_credential=parent, valid_from=NOW)
        return "signer issued it"
    except ValueError as exc:
        return "signer refused (" + str(exc).split(":")[0].replace("Delegation ", "") + ")"


def hand_built(signer: Signer, intent, chain, *, mutate=None):
    """What a dishonest holder could send: its own signature over a chain it
    copied (and possibly edited), skipping its signer's checks."""
    links = copy.deepcopy(chain)
    if mutate:
        mutate(links)
    return signer.sign(intent=intent, delegation_chain=links, valid_from=NOW)


print("Grants")
root_grant = alice.sign(
    intent={
        "action": ["read", "update"],
        "target": "calendar",
        "resource": CALENDAR,
        "delegatee": assistant.did,
        "policy": {"maxSpend": 50},
    },
    valid_from=T0,
    valid_seconds=3600,
)
print("  alice -> assistant   read + update, maxSpend $50")
sub_grant = assistant.sign(
    intent={
        "action": "read",
        "target": "calendar",
        "resource": CALENDAR,
        "delegatee": sub_agent.did,
        "policy": {"maxSpend": 20},
    },
    parent_credential=root_grant,
    valid_from=T0,
    valid_seconds=3600,
)
print("  assistant -> sub-agent   read only, maxSpend $20")
chain = sub_agent.sign(
    intent={"action": "read", "target": "calendar", "resource": CALENDAR},
    parent_credential=sub_grant,
    valid_from=NOW,
)["credentialSubject"]["delegationChain"]

print("\nSub-agent actions")

# a) read
leaf = sub_agent.sign(
    intent={"action": "read", "target": "calendar", "resource": CALENDAR + "/events"},
    parent_credential=sub_grant,
    valid_from=NOW,
)
actual, why = verdict(leaf, sub_agent)
report("a) read the calendar", "ALLOWED", actual, why)

# b) spend $15 under the $20 cap
leaf = sub_agent.sign(
    intent={"action": "read", "target": "calendar", "resource": CALENDAR, "amount": 15},
    parent_credential=sub_grant,
    valid_from=NOW,
)
actual, why = verdict(leaf, sub_agent)
report("b) spend $15 (cap $20)", "ALLOWED", actual, why)

# c) update: outside the sub-agent's grant
update = {"action": "update", "target": "calendar", "resource": CALENDAR}
refused = try_sign(sub_agent, update, sub_grant)
actual, why = verdict(hand_built(sub_agent, update, chain), sub_agent)
report(
    "c) update the calendar (granted read only)", "DENIED", actual, f"{refused}; verifier: {why}"
)

# d) spend $30 over the $20 cap
over = {"action": "read", "target": "calendar", "resource": CALENDAR, "amount": 30}
refused = try_sign(sub_agent, over, sub_grant)
actual, why = verdict(hand_built(sub_agent, over, chain), sub_agent)
report("d) spend $30 (cap $20)", "DENIED", actual, f"{refused}; verifier: {why}")

print("\nRe-delegation by the sub-agent")


def regrant(intent_extra):
    intent = {
        "action": "read",
        "target": "calendar",
        "resource": CALENDAR,
        "delegatee": grandchild.did,
        "policy": {"maxSpend": 20},
    }
    intent.update(intent_extra)
    return intent


for case, extra, act in (
    ("e1) grandchild granted update", {"action": "update"}, {"action": "update"}),
    ("e2) grandchild granted a $100 cap", {"policy": {"maxSpend": 100}}, {"amount": 100}),
):
    wide = regrant(extra)
    refused = try_sign(sub_agent, wide, sub_grant)
    # The dishonest path: sub-agent signs the wider grant anyway, and the
    # grandchild acts under it.
    links = copy.deepcopy(chain)
    wide_grant = sub_agent.sign(intent=wide, delegation_chain=links, valid_from=NOW)
    g_intent = {"action": "read", "target": "calendar", "resource": CALENDAR}
    g_intent.update(act)
    link = {
        "issuer": sub_agent.did,
        "subject": grandchild.did,
        "intent": g_intent,
        "validFrom": wide_grant["validFrom"],
        "validUntil": wide_grant["validUntil"],
        "parentProofValue": wide_grant["proof"]["proofValue"][:64],
        "parentCredential": wide_grant,
    }
    g_leaf = grandchild.sign(intent=g_intent, delegation_chain=links + [link], valid_from=NOW)
    actual, why = verdict(g_leaf, grandchild)
    report(case, "DENIED", actual, f"{refused}; verifier: {why}")

print("\nAttacks on the chain itself")


def tamper(links):
    # Rewrite Alice's grant after she signed it.
    links[0]["parentCredential"]["credentialSubject"]["intent"]["action"] = [
        "read",
        "update",
        "delete",
    ]


read_intent = {"action": "read", "target": "calendar", "resource": CALENDAR}
actual, why = verdict(hand_built(sub_agent, read_intent, chain, mutate=tamper), sub_agent)
report("f) tampered parent (alice's grant edited)", "DENIED", actual, why)

# g) a grant that claims to be from Alice but was signed with Mallory's key.
forger = Signer(private_key=keypairs["mallory"].private_key_jwk, did=alice.did)
forged_root = forger.sign(
    intent={
        "action": ["read", "update", "delete"],
        "target": "calendar",
        "resource": CALENDAR,
        "delegatee": mallory.did,
        "policy": {"maxSpend": 1000},
    },
    valid_from=T0,
    valid_seconds=3600,
)
forged_leaf = mallory.sign(
    intent={"action": "delete", "target": "calendar", "resource": CALENDAR},
    parent_credential=forged_root,
    valid_from=NOW,
)
actual, why = verdict(forged_leaf, mallory)
report("g) forged parent (not signed by alice)", "DENIED", actual, why)

passed = sum(results)
print(f"\n{passed}/{len(results)} cases matched the expected outcome")
sys.exit(0 if passed == len(results) else 1)
