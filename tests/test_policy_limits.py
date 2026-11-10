"""Numeric policy limits narrow in the right direction, and spend caps bind.

`max*` policy keys are ceilings (a lower child value is stricter), `min*` keys
are floors (a higher child value is stricter), and any other numeric key must
be restated unchanged. `policy.maxSpend` caps an action's `intent.amount`.
"""

from __future__ import annotations

import base64
import json

import pytest

from vouch import Signer, generate_identity, multikey
from vouch.attenuation import non_expansion
from vouch.verifier import Verifier, verify_delegation_chain

CAL = "https://calendar.example.com/team"


def _link(policy):
    return {"intent": {"action": "read"}, "policy": policy}


@pytest.mark.parametrize(
    "parent, child, expected",
    [
        ({"maxSpend": 50}, {"maxSpend": 20}, None),  # lower cap: stricter
        ({"maxSpend": 50}, {"maxSpend": 50}, None),  # restated
        ({"maxSpend": 50}, {"maxSpend": 100}, "policy"),  # raised cap: broader
        ({"minHeartbeatAgeSeconds": 300}, {"minHeartbeatAgeSeconds": 600}, None),
        ({"minHeartbeatAgeSeconds": 300}, {"minHeartbeatAgeSeconds": 100}, "policy"),
        ({"retries": 3}, {"retries": 3}, None),  # unnamed direction: equal only
        ({"retries": 3}, {"retries": 5}, "policy"),
        ({"retries": 3}, {"retries": 1}, "policy"),
    ],
)
def test_numeric_policy_direction(parent, child, expected):
    assert non_expansion(_link(parent), _link(child)) == expected


def _did_key_signer():
    kp = generate_identity()
    raw = base64.urlsafe_b64decode(json.loads(kp.public_key_jwk)["x"] + "==")
    return Signer(
        private_key=kp.private_key_jwk, did="did:key:" + multikey.encode_ed25519_public(raw)
    )


@pytest.fixture
def capped():
    """root grants a read+update, cap $50; a re-delegates read only, cap $20."""
    root, a, b = _did_key_signer(), _did_key_signer(), _did_key_signer()
    root_grant = root.sign(
        intent={
            "action": ["read", "update"],
            "target": "calendar",
            "resource": CAL,
            "delegatee": a.did,
            "policy": {"maxSpend": 50},
        },
        valid_seconds=3600,
    )
    a_grant = a.sign(
        intent={
            "action": "read",
            "target": "calendar",
            "resource": CAL,
            "delegatee": b.did,
            "policy": {"maxSpend": 20},
        },
        parent_credential=root_grant,
        valid_seconds=3600,
    )
    return root, a, b, root_grant, a_grant


def test_spend_within_cap_is_allowed(capped):
    _, _, b, _, a_grant = capped
    leaf = b.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL, "amount": 15},
        parent_credential=a_grant,
    )
    assert verify_delegation_chain(leaf) is None
    assert Verifier.verify(leaf, public_key=b.get_public_key_multikey())[0] is True


def test_spend_over_cap_is_refused_by_signer(capped):
    _, _, b, _, a_grant = capped
    with pytest.raises(ValueError, match="policy"):
        b.sign(
            intent={"action": "read", "target": "calendar", "resource": CAL, "amount": 30},
            parent_credential=a_grant,
        )


def test_spend_over_cap_is_refused_by_verifier(capped):
    _, _, b, _, a_grant = capped
    links = None
    ok_leaf = b.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL, "amount": 15},
        parent_credential=a_grant,
    )
    links = ok_leaf["credentialSubject"]["delegationChain"]
    over = b.sign(
        intent={"action": "read", "target": "calendar", "resource": CAL, "amount": 30},
        delegation_chain=links,
    )
    assert verify_delegation_chain(over) == "scope_exceeds_parent:policy"


def test_spend_cap_cannot_be_raised_by_a_sub_grant(capped):
    _, a, b, root_grant, _ = capped
    with pytest.raises(ValueError, match="policy"):
        a.sign(
            intent={
                "action": "read",
                "target": "calendar",
                "resource": CAL,
                "delegatee": b.did,
                "policy": {"maxSpend": 100},
            },
            parent_credential=root_grant,
        )


def test_amount_must_be_a_number_under_a_cap(capped):
    _, _, b, _, a_grant = capped
    with pytest.raises(ValueError, match="policy"):
        b.sign(
            intent={"action": "read", "target": "calendar", "resource": CAL, "amount": "15"},
            parent_credential=a_grant,
        )
