"""
Tests for cross-device identity by per-device keys and delegation (vouch.fleet).

The model: a root identity delegates scoped, time-bound authority to a device's
own DID; the device signs with its own key chained under that grant; a verifier
ties the device's action back to the trusted root. The device key never travels.
"""

import pytest

from vouch import Agent, DeviceRegistry, enroll_device, verify_delegated_chain


def _root_and_device():
    root = Agent("root.example")
    device = Agent()  # did:key minted on the device
    return root, device


def _signed_chain(root, device):
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
    return grant, action


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
    # Device tries to act outside the granted resource. sign enforces
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


# ---------------------------------------------------------------------------
# Device revocation
# ---------------------------------------------------------------------------


def test_revoked_device_did_rejected():
    root, device = _root_and_device()
    grant, action = _signed_chain(root, device)
    roots = {root.did: root.public_key_jwk}

    # Before revocation: valid.
    assert verify_delegated_chain([grant, action], trusted_roots=roots).ok

    # Revoke the device DID: the chain through it stops verifying.
    result = verify_delegated_chain([grant, action], trusted_roots=roots, revoked={device.did})
    assert not result.ok
    assert "revoked" in (result.reason or "")


def test_revoked_grant_credential_id_rejected():
    root, device = _root_and_device()
    grant, action = _signed_chain(root, device)
    roots = {root.did: root.public_key_jwk}
    result = verify_delegated_chain([grant, action], trusted_roots=roots, revoked={grant["id"]})
    assert not result.ok


def test_revoked_predicate_callable():
    root, device = _root_and_device()
    grant, action = _signed_chain(root, device)
    roots = {root.did: root.public_key_jwk}
    blocked = {device.did}
    result = verify_delegated_chain(
        [grant, action], trusted_roots=roots, revoked=lambda i: i in blocked
    )
    assert not result.ok


def test_other_device_unaffected_by_revocation():
    root, device_a = _root_and_device()
    device_b = Agent()
    grant_b, action_b = _signed_chain(root, device_b)
    roots = {root.did: root.public_key_jwk}
    # Revoking device A does not affect device B's chain.
    result = verify_delegated_chain(
        [grant_b, action_b], trusted_roots=roots, revoked={device_a.did}
    )
    assert result.ok


def test_device_registry():
    root, device = _root_and_device()
    grant, action = _signed_chain(root, device)
    roots = {root.did: root.public_key_jwk}

    registry = DeviceRegistry()
    registry.enroll(device.did, grant)
    assert registry.active_devices() == [device.did]
    assert verify_delegated_chain(
        [grant, action], trusted_roots=roots, revoked=registry.is_revoked
    ).ok

    registry.revoke(device.did)
    assert registry.active_devices() == []
    assert not verify_delegated_chain(
        [grant, action], trusted_roots=roots, revoked=registry.is_revoked
    ).ok
