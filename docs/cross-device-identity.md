# Cross-device identity

One identity across all your devices, without ever copying your private key.

Each device makes its own key and keeps it local. Your root identity signs a
scoped permission slip (a delegation grant) for each device. Anyone verifying an
action can trace it back to your trusted root. Lose a device and you revoke it;
lose all of them and you rebuild the root from recovery shares.

The full runnable version is `examples/cross_device_identity.py`.

## 1. A root identity

The root is your durable anchor. Keep it off day-to-day devices.

```python
from vouch import Agent

root = Agent("alice.example")
trusted_roots = {root.did: root.public_key_jwk}
```

## 2. Enroll a device

Each device mints its own key. The root delegates a scope to that device's DID.
The root never sees the device's private key.

```python
from vouch import enroll_device

phone = Agent()  # a did:key minted on the phone
grant = enroll_device(
    root,
    device_did=phone.did,
    action="charge",
    target="api.bank",
    resource="https://api.bank/invoices",
)
```

## 3. Sign and verify

The device signs actions with its own key, chained under the grant. A verifier
checks the whole chain back to the trusted root.

```python
from vouch import verify_delegated_chain

action = phone.sign(
    action="charge",
    target="api.bank",
    resource="https://api.bank/invoices/42",
    parent_credential=grant,
)

result = verify_delegated_chain([grant, action], trusted_roots=trusted_roots)
assert result.ok
```

`verify_delegated_chain` confirms every signature, that each step is authorized
by the one before it, that the resource only narrows, and that the validity
windows nest.

## 4. Revoke a lost device

Track devices with a `DeviceRegistry` and revoke one when it is lost. Its actions
stop verifying; other devices are unaffected.

```python
from vouch import DeviceRegistry

registry = DeviceRegistry()
registry.enroll(phone.did, grant)

registry.revoke(phone.did)

result = verify_delegated_chain(
    [grant, action], trusted_roots=trusted_roots, revoked=registry.is_revoked
)
assert not result.ok
```

The `revoked` argument also accepts a plain set of DIDs or credential ids, or any
`is_revoked(id) -> bool` callable, so you can back it with your own store.

## 5. Recover the root

Split the root into shares so any threshold rebuild it. Hand shares to guardians
or separate locations. Fewer than the threshold reveal nothing.

```python
from vouch import split_identity, recover_identity, Signer

# Splitting needs the root's key, so create the root with allow_key_export=True.
root = Agent("alice.example", allow_key_export=True)
shares = split_identity(root, threshold=2, shares=3)

# Later, any two shares rebuild the exact same identity.
recovered = recover_identity([shares[0], shares[2]], did=root.did)
signer = Signer.from_keypair(recovered)
```

The recovered key is identical to the original, so it can enroll new devices and
carry on as the same identity.

## What travels, and what does not

- The private key of a device never leaves that device.
- The root's key is only ever assembled during a deliberate recovery; do that on
  a trusted device and re-seal afterwards.
- What moves between devices is authority (a signed grant), never key material.
