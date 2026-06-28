"""
Tests for cross-device identity by per-device keys and delegation (vouch.fleet).

The model: a root identity delegates scoped, time-bound authority to a device's
own DID; the device signs with its own key chained under that grant; a verifier
ties the device's action back to the trusted root. The device key never travels.
"""

import pytest

from vouch import Agent, enroll_device, verify_delegated_chain


def _root_and_device():
    root = Agent("root.example")
    device = Agent()  # did:key minted on the device
    return root, device


def test_enroll_and_verify_chain():
    root, device = _root_and_device()
    grant = enroll_device(
        root,
        device_did=device.did,
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices",
    )
    action = device.sign(
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices/42",
        parent_credential=grant,
    )
    result = verify_delegated_chain(
        [grant, action],
        trusted_roots={root.did: root.public_key_jwk},
    )
    assert result.ok
    assert result.root_did == root.did
    assert result.leaf.issuer == device.did
    assert result.leaf.resource == "https://api.bank/invoices/42"


def test_untrusted_root_rejected():
    root, device = _root_and_device()
    grant = enroll_device(
        root,
        device_did=device.did,
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices",
    )
    action = device.sign(
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices/42",
        parent_credential=grant,
    )
    # No trusted root configured.
    result = verify_delegated_chain([grant, action], trusted_roots={})
    assert not result.ok
    assert "trusted_roots" in (result.reason or "")


def test_wrong_device_issuer_rejected():
    root, device = _root_and_device()
    grant = enroll_device(
        root,
        device_did=device.did,
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices",
    )
    # A different device signs, not the one the grant authorized.
    impostor = Agent()
    action = impostor.sign(
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices/42",
        parent_credential=grant,
    )
    result = verify_delegated_chain([grant, action], trusted_roots={root.did: root.public_key_jwk})
    assert not result.ok
    assert "delegatee" in (result.reason or "")


def test_resource_widening_rejected():
    root, device = _root_and_device()
    grant = enroll_device(
        root,
        device_did=device.did,
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices",
    )
    # Device tries to act outside the granted resource. sign_credential enforces
    # narrowing at issue time, so signing itself raises.
    with pytest.raises(ValueError):
        device.sign(
            action="charge",
            target="api.bank",
            resource="https://api.bank/payouts",
            parent_credential=grant,
        )


def test_tampered_action_rejected():
    root, device = _root_and_device()
    grant = enroll_device(
        root,
        device_did=device.did,
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices",
    )
    action = device.sign(
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices/42",
        parent_credential=grant,
    )
    action["credentialSubject"]["intent"]["resource"] = "https://api.bank/invoices/evil"
    result = verify_delegated_chain([grant, action], trusted_roots={root.did: root.public_key_jwk})
    assert not result.ok


def test_leaf_intent_policy():
    root, device = _root_and_device()
    grant = enroll_device(
        root,
        device_did=device.did,
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices",
    )
    action = device.sign(
        action="charge",
        target="api.bank",
        resource="https://api.bank/invoices/42",
        parent_credential=grant,
    )
    ok_result = verify_delegated_chain(
        [grant, action],
        trusted_roots={root.did: root.public_key_jwk},
        require_action="charge",
    )
    assert ok_result.ok
    bad_result = verify_delegated_chain(
        [grant, action],
        trusted_roots={root.did: root.public_key_jwk},
        require_action="refund",
    )
    assert not bad_result.ok


def test_did_key_root_resolves_without_trust_map_for_links():
    # Root is did:web (must be trusted explicitly); device is did:key (resolves).
    root, device = _root_and_device()
    grant = enroll_device(
        root,
        device_did=device.did,
        action="read",
        target="t",
        resource="https://x/y",
    )
    action = device.sign(
        action="read",
        target="t",
        resource="https://x/y/z",
        parent_credential=grant,
    )
    # Only the root key is supplied; the device link resolves from its did:key.
    result = verify_delegated_chain([grant, action], trusted_roots={root.did: root.public_key_jwk})
    assert result.ok
