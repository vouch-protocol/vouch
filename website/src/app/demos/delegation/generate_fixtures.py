#!/usr/bin/env python3
"""
Generate fixtures.json for the delegation chain demo.

The story is the one in examples/ccg_demo/01_delegation.py. Every key is
generated fresh by this script and held in memory only (never printed or
written out). The output holds only public data: DIDs and signed credentials.
The browser verifies all of it live with the WASM core, so nothing in the
JSON is trusted by the page.

Run from the repository root:
    PYTHONPATH=. python3 website/src/app/demos/delegation/generate_fixtures.py
"""

from __future__ import annotations

import base64
import copy
import json
import pathlib
from datetime import datetime, timedelta, timezone

from vouch import Signer, generate_identity, multikey

CALENDAR = "https://calendar.example.com/alice"
T0 = datetime(2026, 11, 10, 17, 0, 0, tzinfo=timezone.utc)  # fake clock
NOW = T0 + timedelta(minutes=1)
OUT = pathlib.Path(__file__).with_name("fixtures.json")

keypairs = {}


def identity(label: str) -> Signer:
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


def try_sign(signer: Signer, intent, parent) -> str:
    """What the honest signer does when asked for a credential beyond its grant."""
    try:
        signer.sign(intent=intent, parent_credential=parent, valid_from=NOW)
        return "issued"
    except ValueError as exc:
        return str(exc)


def hand_built(signer: Signer, intent, chain):
    """A credential a dishonest holder signs itself, skipping the signer's checks."""
    return signer.sign(intent=intent, delegation_chain=copy.deepcopy(chain), valid_from=NOW)


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
chain = sub_agent.sign(
    intent={"action": "read", "target": "calendar", "resource": CALENDAR},
    parent_credential=sub_grant,
    valid_from=NOW,
)["credentialSubject"]["delegationChain"]

cases = []


def add(case_id, label, holder, expected, credential, refusal=None, tamper=None):
    cases.append(
        {
            "id": case_id,
            "label": label,
            "holder": holder.did,
            "expected": expected,
            "refusal": refusal,
            "tamper": tamper,
            "credential": credential,
        }
    )


def sub_agent_leaf(extra):
    intent = {"action": "read", "target": "calendar", "resource": CALENDAR}
    intent.update(extra)
    return sub_agent.sign(intent=intent, parent_credential=sub_grant, valid_from=NOW)


add("a", "Read the calendar", sub_agent, "ALLOWED",
    sub_agent_leaf({"resource": CALENDAR + "/events"}))
add("b", "Spend $15 (cap is $20)", sub_agent, "ALLOWED", sub_agent_leaf({"amount": 15}))

update = {"action": "update", "target": "calendar", "resource": CALENDAR}
add("c", "Update the calendar (granted read only)", sub_agent, "DENIED",
    hand_built(sub_agent, update, chain), refusal=try_sign(sub_agent, update, sub_grant))

over = {"action": "read", "target": "calendar", "resource": CALENDAR, "amount": 30}
add("d", "Spend $30 (cap is $20)", sub_agent, "DENIED",
    hand_built(sub_agent, over, chain), refusal=try_sign(sub_agent, over, sub_grant))


def regrant(extra):
    intent = {
        "action": "read",
        "target": "calendar",
        "resource": CALENDAR,
        "delegatee": grandchild.did,
        "policy": {"maxSpend": 20},
    }
    intent.update(extra)
    return intent


for case_id, label, extra, act in (
    ("e1", "Sub-agent grants a grandchild update", {"action": "update"}, {"action": "update"}),
    ("e2", "Sub-agent grants a grandchild a $100 cap", {"policy": {"maxSpend": 100}}, {"amount": 100}),
):
    wide = regrant(extra)
    refusal = try_sign(sub_agent, wide, sub_grant)
    wide_grant = sub_agent.sign(intent=wide, delegation_chain=copy.deepcopy(chain), valid_from=NOW)
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
    leaf = grandchild.sign(
        intent=g_intent, delegation_chain=copy.deepcopy(chain) + [link], valid_from=NOW
    )
    add(case_id, label, grandchild, "DENIED", leaf, refusal=refusal)

# f) a valid credential; the page edits Alice's grant after the fact.
add("f", "Alice's grant is edited after she signed it", sub_agent, "DENIED",
    sub_agent_leaf({}), tamper={"action": ["read", "update", "delete"]})

# g) a grant that claims to be Alice's but is signed with Mallory's key.
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
add("g", "A grant that claims to be Alice's, signed by someone else", mallory, "DENIED",
    forged_leaf)

fixtures = {
    "now": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "root": alice.did,
    "parties": {
        "alice": alice.did,
        "assistant": assistant.did,
        "subAgent": sub_agent.did,
        "grandchild": grandchild.did,
        "mallory": mallory.did,
    },
    "rootGrant": root_grant,
    "subGrant": sub_grant,
    "cases": cases,
}
OUT.write_text(json.dumps(fixtures, indent=2) + "\n")
print(f"wrote {OUT} ({len(cases)} cases)")
