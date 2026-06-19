#!/usr/bin/env python3
"""
Vouch Shield - Demo Script.

Demonstrates the security features of Vouch Shield:
1. Signed call from trusted DID → ALLOWED
2. Unsigned call → BLOCKED
3. Unknown DID → BLOCKED
4. Permission exceeded → BLOCKED
5. Blocked DID → BLOCKED

Run: python -m vouch.shield.demo
"""

from vouch import Signer, generate_identity
from vouch.shield import Shield, ShieldConfig
from vouch.shield.permissions import Capabilities, PermissionLevel, NetworkLevel, ShellLevel


def main():
    print("=" * 60)
    print("🛡️  VOUCH SHIELD - DEMO (Python)")
    print("=" * 60)
    print()

    # Initialize shield in non-strict mode for demo
    # (In production, use strict_mode=True)
    shield = Shield(
        ShieldConfig(
            strict_mode=True,
            require_signature=True,
        )
    )

    # Step 1: Create a trusted identity
    print("📝 Step 1: Creating a trusted identity...")
    trusted_keys = generate_identity("demo.vouch")
    trusted_did = trusted_keys.did
    trusted_signer = Signer(private_key=trusted_keys.private_key_jwk, did=trusted_did)
    print(f"   DID: {trusted_did}")

    # Register and trust
    shield.trust_did(trusted_did, trusted_keys.public_key_jwk)
    shield.set_capabilities(
        trusted_did,
        Capabilities(
            filesystem=PermissionLevel.READ,
            network=NetworkLevel.OUTBOUND,
            shell=ShellLevel.NONE,
        ),
    )
    print("   ✅ Identity trusted and capabilities set")
    print()

    # Step 2: Create a malicious identity
    print("👿 Step 2: Creating a MALICIOUS identity (not trusted)...")
    malicious_keys = generate_identity("evil.hacker")
    malicious_did = malicious_keys.did
    malicious_signer = Signer(private_key=malicious_keys.private_key_jwk, did=malicious_did)
    print(f"   DID: {malicious_did}")
    print()

    # Test 1: Signed call from trusted DID
    print("-" * 60)
    print("🧪 Test 1: Signed call from TRUSTED DID")
    print("-" * 60)

    token1 = trusted_signer.sign({"action": "read_file", "path": "/data/file.txt"})
    result1 = shield.intercept(
        tool="read_file",
        args={"path": "/data/file.txt"},
        token=token1,
    )
    print("   Tool: read_file")
    print(f"   DID: {trusted_did}")
    print(f"   Result: {'✅ ALLOWED' if result1.allowed else '❌ BLOCKED'}")
    if result1.reason:
        print(f"   Reason: {result1.reason}")
    print()

    # Test 2: Unsigned call
    print("-" * 60)
    print("🧪 Test 2: UNSIGNED call (no token)")
    print("-" * 60)

    result2 = shield.intercept(
        tool="read_file",
        args={"path": "/etc/passwd"},
        token=None,  # No token!
    )
    print("   Tool: read_file")
    print("   DID: (none)")
    print(f"   Result: {'✅ ALLOWED' if result2.allowed else '❌ BLOCKED'}")
    if result2.reason:
        print(f"   Reason: {result2.reason}")
    print()

    # Test 3: Signed call from unknown DID
    print("-" * 60)
    print("🧪 Test 3: Signed call from UNKNOWN DID")
    print("-" * 60)

    # Register the key for verification but don't trust the DID
    shield.register_key(malicious_did, malicious_keys.public_key_jwk)
    token3 = malicious_signer.sign({"action": "run_command", "cmd": "rm -rf /"})
    result3 = shield.intercept(
        tool="run_command",
        args={"cmd": "rm -rf /"},
        token=token3,
    )
    print("   Tool: run_command")
    print(f"   DID: {malicious_did}")
    print(f"   Result: {'✅ ALLOWED' if result3.allowed else '❌ BLOCKED'}")
    if result3.reason:
        print(f"   Reason: {result3.reason}")
    print()

    # Test 4: Trusted DID exceeding permissions
    print("-" * 60)
    print("🧪 Test 4: TRUSTED DID exceeding permissions")
    print("-" * 60)

    token4 = trusted_signer.sign({"action": "run_command", "cmd": "sudo reboot"})
    result4 = shield.intercept(
        tool="run_command",
        args={"cmd": "sudo reboot"},
        token=token4,
    )
    print("   Tool: run_command")
    print(f"   DID: {trusted_did}")
    print(f"   Result: {'✅ ALLOWED' if result4.allowed else '❌ BLOCKED'}")
    if result4.reason:
        print(f"   Reason: {result4.reason}")
    print()

    # Test 5: Blocked DID
    print("-" * 60)
    print("🧪 Test 5: BLOCKED DID attempting access")
    print("-" * 60)

    shield.block_did(malicious_did, "Known malicious actor")
    token5 = malicious_signer.sign({"action": "read_file", "path": "innocent.txt"})
    result5 = shield.intercept(
        tool="read_file",
        args={"path": "innocent.txt"},
        token=token5,
    )
    print("   Tool: read_file")
    print(f"   DID: {malicious_did} (BLOCKED)")
    print(f"   Result: {'✅ ALLOWED' if result5.allowed else '❌ BLOCKED'}")
    if result5.reason:
        print(f"   Reason: {result5.reason}")
    print()

    # Summary
    print("=" * 60)
    print("📊 SUMMARY")
    print("=" * 60)
    stats = shield.get_stats()
    print(f"   Allowed: {stats['allowed']}")
    print(f"   Blocked: {stats['blocked']}")
    print(f"   Total:   {stats['total']}")
    print()

    # Cleanup
    shield.shutdown()
    print("✅ Demo complete! Flight recorder logs saved to ~/.vouch/logs/")


if __name__ == "__main__":
    main()
