#!/usr/bin/env python3
"""
ephemeral_demo.py - Ephemeral sub-agent identities

A parent agent spawns a short-lived sub-agent (the kind Claude Code spins up per
task) and mints it a self-cleaning identity: a fresh did:key plus a time-bound
delegated credential scoped to one intent. The credential's validUntil enforces
auto-expiry, so there is nothing to clean up when the sub-agent finishes.

This demo:
  1. Spawns an ephemeral identity with a 1-second TTL.
  2. Verifies the delegation credential is valid right now.
  3. Waits past the TTL and shows the same credential is then rejected.

Run:
  source ~/venvvouch/bin/activate
  cd ~/vouch-protocol && python3 examples/ephemeral_demo.py
"""

import time

from vouch import Signer, Verifier, generate_identity
from vouch.ephemeral import spawn_ephemeral_identity

print("Ephemeral sub-agent identities")
print("=" * 50)

# The parent agent has a normal, hosted identity (did:web here).
parent_id = generate_identity(domain="orchestrator.example.com")
parent = Signer(private_key=parent_id.private_key_jwk, did=parent_id.did)
print(f"Parent agent: {parent.get_did()}")

# The parent spawns a sub-agent for one scoped task, valid for 1 second.
intent = {
    "action": "read",
    "target": "repo:vouch-protocol",
    "resource": "https://api.example.com/repos/vouch-protocol/contents",
}
TTL_SECONDS = 1
child = spawn_ephemeral_identity(parent, intent, ttl_seconds=TTL_SECONDS)

print("\nSpawned ephemeral sub-agent:")
print(f"  Child DID:    {child.did}")
print(f"  Scope:        {intent['action']} {intent['target']}")
print(f"  Valid until:  {child.valid_until}")
print(f"  TTL:          {TTL_SECONDS}s")

# The credential carries a delegation link from the parent to the child.
chain = child.credential["credentialSubject"].get("delegationChain", [])
print(f"  Delegation:   {len(chain)} link(s)")
for link in chain:
    print(f"    {link['issuer']} -> {link['subject']}")

# 1. Verify the credential is valid right now. We use the child's Multikey as the
#    verification key and clock_skew_seconds=0 so the short TTL is honored
#    exactly (the default 30s skew would otherwise mask a 1s expiry).
is_valid_now, passport = Verifier.verify_credential(
    child.credential,
    public_key=child.public_key_multikey,
    clock_skew_seconds=0,
)
print(f"\n[now]            credential valid: {is_valid_now}")
assert is_valid_now, "credential should be valid immediately after minting"
assert passport is not None
print(f"                 issuer:  {passport.iss}")
print(f"                 action:  {passport.intent.get('action')}")

# 2. Wait past the TTL and verify the same credential is now rejected. No
#    cleanup happened; the validUntil deadline did the work.
wait_for = TTL_SECONDS + 1
print(f"\nwaiting {wait_for}s for the credential to expire...")
time.sleep(wait_for)

is_valid_after, _ = Verifier.verify_credential(
    child.credential,
    public_key=child.public_key_multikey,
    clock_skew_seconds=0,
)
print(f"[after expiry]   credential valid: {is_valid_after}")
assert not is_valid_after, "credential should be rejected after its TTL elapses"

print("\nResult: the ephemeral identity verified while live and was rejected")
print("after expiry, with nothing to revoke or delete. Self-cleaning by design.")
