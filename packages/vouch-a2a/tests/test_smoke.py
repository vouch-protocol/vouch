"""Smoke tests for the vouch-a2a package."""

import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto.common import base64url_decode
import json

from vouch import Signer, generate_identity


def _pub(kp):
    return Ed25519PublicKey.from_public_bytes(base64url_decode(json.loads(kp.public_key_jwk)["x"]))


def test_package_exports():
    import vouch_a2a

    assert vouch_a2a.sign_agent_card is not None
    assert vouch_a2a.verify_agent_card is not None


def test_sign_and_verify_card():
    from vouch_a2a import sign_agent_card, verify_agent_card, VOUCH_CARD_FIELD

    kp = generate_identity()
    signer = Signer(private_key=kp.private_key_jwk, did="did:web:agents.acme.com")

    card = {"name": "BillingAgent", "url": "https://agents.acme.com/billing", "version": "1.0.0"}
    signed = sign_agent_card(signer, card)

    # input not mutated, credential added on the copy
    assert VOUCH_CARD_FIELD not in card
    assert VOUCH_CARD_FIELD in signed
    assert signed[VOUCH_CARD_FIELD]["proof"]["cryptosuite"] == "eddsa-jcs-2022"

    ok, passport = verify_agent_card(signed, public_key=_pub(kp))
    assert ok is True


def test_unsigned_card_fails_closed():
    from vouch_a2a import verify_agent_card

    ok, passport = verify_agent_card({"name": "NoCred"}, public_key=None)
    assert ok is False
    assert passport is None


def test_delegation_chain_on_card():
    from vouch_a2a import sign_agent_card, verify_agent_card

    org_kp = generate_identity()
    agent_kp = generate_identity()
    org = Signer(private_key=org_kp.private_key_jwk, did="did:web:acme.com")
    agent = Signer(private_key=agent_kp.private_key_jwk, did="did:web:agents.acme.com")

    # org issues a broad operate authority; agent narrows it onto its own card
    parent = org.sign_credential(
        intent={"action": "operate", "target": "https://agents.acme.com", "resource": "a2a:agent-card"}
    )
    card = {"name": "BillingAgent", "url": "https://agents.acme.com/billing"}
    signed = sign_agent_card(agent, card, parent_credential=parent)

    ok, _ = verify_agent_card(signed, public_key=_pub(agent_kp))
    assert ok is True
