# Cross-Device Identity Reference

One identity across many devices, without ever copying the private key. Each
device holds its own key; a root identity delegates scoped authority to each
device; a verifier ties any device's action back to the trusted root. Lose a
device and you revoke it; lose all of them and you rebuild the root from recovery
shares.

This builds directly on delegation chains (see the Delegation reference). The
Python and TypeScript SDKs ship the helpers described here; the credential wire
format is unchanged.

## When to use it

- A person or organization uses several devices (phones, laptops, smart devices)
  and wants one identity across all of them.
- You never want a private key to travel between devices or sit on a server.
- You need to revoke a single lost device without rotating the whole identity.
- You need the root identity to survive the loss of every device.

## The model

- Root identity: the durable anchor, kept off day-to-day devices.
- Device identity: each device mints its OWN key locally (often a did:key). The
  key never leaves the device.
- Grant: the root signs a scoped, time-bound delegation to a device's DID.
- Action: the device signs with its own key, chained under the grant.
- Verification: a relying party checks the whole chain back to the trusted root.

What moves between devices is authority (a signed grant), never key material.

## Enroll a device

```python
from vouch import Agent, enroll_device

root = Agent("alice.example")
trusted_roots = {root.did: root.public_key_jwk}

phone = Agent()  # a did:key minted on the phone
grant = enroll_device(
    root,
    device_did=phone.did,
    action="charge",
    target="api.bank",
    resource="https://api.bank/invoices",
)
```

## Sign and verify

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
by the one before it (the child's issuer is the parent's delegatee), that the
resource only narrows, and that the validity windows nest. The credentials are
ordered root-first: `[root_grant, ...intermediate grants, leaf_action]`.

## Revoke a lost device

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

The `revoked` argument accepts a `DeviceRegistry.is_revoked` callable, a set of
revoked DIDs or credential ids, or any `is_revoked(id) -> bool` function, so you
can back it with your own store.

## Recover the root

Split the root into shares so any threshold rebuild it. Distribute the shares to
guardians or separate locations. Fewer than the threshold reveal nothing.

```python
from vouch import split_identity, recover_identity, Signer

# Splitting needs the root's key, so create the root with allow_key_export=True.
root = Agent("alice.example", allow_key_export=True)
shares = split_identity(root, threshold=2, shares=3)

# Later, any two shares rebuild the exact same identity.
recovered = recover_identity([shares[0], shares[2]], did=root.did)
signer = Signer.from_keypair(recovered)
```

This is the recovery and escrow path. The seed is reconstructed only during a
deliberate recovery, so do it on a trusted device and re-seal afterwards. It is
distinct from threshold signing, where the key is never reassembled.

## Security notes

- Trust is anchored only in `trusted_roots`. The root credential's issuer must
  appear there; other links resolve their key from that map, then did:key, then
  did:web.
- did:key resolution authenticates self-consistency, not real-world identity, so
  the root anchor is what establishes trust.
- Revocation is enforced at verify time against the oracle the verifier supplies,
  so the relying party controls the revocation source of truth.
- For recovery, shares carry no integrity tag, so a wrong or corrupted share
  yields a wrong secret rather than an error; add your own checksum if you need
  to detect a bad share.

## API summary

- `enroll_device(root, device_did=, action=, target=, resource=, valid_seconds=)`
- `verify_delegated_chain(credentials, trusted_roots=, revoked=, require_action=, ...)`
- `DeviceRegistry()` with `enroll`, `revoke`, `is_revoked`, `active_devices`
- `split_identity(keypair, threshold=, shares=)` and `recover_identity(shares, did=)`
- Byte-level primitives: `split_secret(secret, threshold=, shares=)` and
  `combine_shares(shares)`

The TypeScript SDK exposes the same surface with camelCase names
(`enrollDevice`, `verifyDelegatedChain`, `DeviceRegistry`, `splitIdentity`,
`recoverIdentity`).
