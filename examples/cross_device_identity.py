#!/usr/bin/env python3
"""
cross_device_identity.py - One identity across many devices, key never travels.

Shows the whole cross-device custody story end to end:

  1. A root identity (your durable anchor).
  2. Enroll two devices. Each device mints its OWN key locally; the root only
     signs a scoped permission slip (a delegation grant). No key is copied.
  3. A device signs an action; a verifier ties it back to the trusted root.
  4. Lose a device: revoke it. Its actions stop verifying; the other device is
     unaffected.
  5. Recovery: split the root across guardians, "lose" it, then rebuild it from
     a threshold of shares and keep operating.

Run: python cross_device_identity.py
"""

from vouch import (
    Agent,
    DeviceRegistry,
    Signer,
    enroll_device,
    recover_identity,
    split_identity,
    verify_delegated_chain,
)


def rule(title):
    print(f"\n{'=' * 64}\n{title}\n{'=' * 64}")


# ---------------------------------------------------------------------------
# 1. The root identity (kept safe, off the day-to-day devices).
# ---------------------------------------------------------------------------
rule("1. Root identity")
# allow_key_export=True lets us split the root for recovery later (step 5). By
# default an Agent keeps its private key in and signs on your behalf; exporting
# the key is an explicit, opt-in action.
root = Agent("alice.example", allow_key_export=True)
trusted_roots = {root.did: root.public_key_jwk}
print(f"   Root DID: {root.did}")

# ---------------------------------------------------------------------------
# 2. Enroll two devices. Each mints its own key; the root delegates a scope.
# ---------------------------------------------------------------------------
rule("2. Enroll a phone and a laptop (each holds its own key)")
phone = Agent()  # did:key minted on the phone
laptop = Agent()  # did:key minted on the laptop
registry = DeviceRegistry()

phone_grant = enroll_device(
    root,
    device_did=phone.did,
    action="charge",
    target="api.bank",
    resource="https://api.bank/invoices",
)
laptop_grant = enroll_device(
    root,
    device_did=laptop.did,
    action="charge",
    target="api.bank",
    resource="https://api.bank/invoices",
)
registry.enroll(phone.did, phone_grant)
registry.enroll(laptop.did, laptop_grant)
print(f"   Phone:  {phone.did[:24]}... enrolled")
print(f"   Laptop: {laptop.did[:24]}... enrolled")
print("   The root never saw either device's private key.")

# ---------------------------------------------------------------------------
# 3. A device signs an action; a verifier checks it back to the root.
# ---------------------------------------------------------------------------
rule("3. The phone signs an action, and it verifies back to the root")
phone_action = phone.sign(
    action="charge",
    target="api.bank",
    resource="https://api.bank/invoices/42",
    parent_credential=phone_grant,
)
result = verify_delegated_chain(
    [phone_grant, phone_action],
    trusted_roots=trusted_roots,
    revoked=registry.is_revoked,
)
print(f"   Verified: {result.ok}  (issued by {result.leaf.issuer[:24]}...)")

# ---------------------------------------------------------------------------
# 4. Lose the phone: revoke it. Laptop keeps working.
# ---------------------------------------------------------------------------
rule("4. The phone is lost: revoke it")
registry.revoke(phone.did)
after_revoke = verify_delegated_chain(
    [phone_grant, phone_action],
    trusted_roots=trusted_roots,
    revoked=registry.is_revoked,
)
print(f"   Phone action still valid? {after_revoke.ok}  ({after_revoke.reason})")

laptop_action = laptop.sign(
    action="charge",
    target="api.bank",
    resource="https://api.bank/invoices/99",
    parent_credential=laptop_grant,
)
laptop_ok = verify_delegated_chain(
    [laptop_grant, laptop_action],
    trusted_roots=trusted_roots,
    revoked=registry.is_revoked,
)
print(f"   Laptop still works? {laptop_ok.ok}")

# ---------------------------------------------------------------------------
# 5. Recovery: split the root, "lose" it, rebuild from a threshold of shares.
# ---------------------------------------------------------------------------
rule("5. Recover the root from guardian shares")
shares = split_identity(root, threshold=2, shares=3)
print("   Split the root into 3 shares (any 2 rebuild it).")

# Two guardians hand back their shares. Rebuild the exact same root key.
recovered = recover_identity([shares[0], shares[2]], did=root.did)
recovered_signer = Signer.from_keypair(recovered)
print(f"   Recovered root DID matches: {recovered.did == root.did}")

# The recovered root can enroll a new device, proving it is the same identity.
new_tablet = Agent()
tablet_grant = enroll_device(
    recovered_signer,
    device_did=new_tablet.did,
    action="charge",
    target="api.bank",
    resource="https://api.bank/invoices",
)
tablet_action = new_tablet.sign(
    action="charge",
    target="api.bank",
    resource="https://api.bank/invoices/7",
    parent_credential=tablet_grant,
)
tablet_ok = verify_delegated_chain(
    [tablet_grant, tablet_action],
    trusted_roots={recovered.did: recovered.public_key_jwk},
)
print(f"   Recovered root enrolled a new tablet, verified? {tablet_ok.ok}")

print("""
Takeaway: one identity, many devices, and the private key never travels.
Each device holds its own key; the root delegates; losing a device is a revoke;
and the root itself survives via threshold recovery shares.
""")
