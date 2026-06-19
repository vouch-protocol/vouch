#!/usr/bin/env python3
"""
07_mcp.py - Why MCP Tool Calls Need Vouch

See what happens when MCP tool calls are unsigned vs signed.
Then watch a rogue tool call get caught.

Run: pip install vouch-protocol && python 07_mcp.py
"""

from vouch import Signer, Verifier, generate_identity
import json

# =============================================================================
# PART 1: Without Vouch — MCP tool calls have no origin proof
# =============================================================================

print("=" * 60)
print("PART 1: MCP WITHOUT Vouch")
print("=" * 60)

# Claude (or another LLM) calls tools through MCP
mcp_calls = [
    {"tool": "read_file", "params": {"path": "/src/main.py"}, "request_id": "req_001"},
    {
        "tool": "write_file",
        "params": {"path": "/data/output.txt", "content": "Analysis..."},
        "request_id": "req_002",
    },
    {"tool": "execute_command", "params": {"command": "pytest tests/ -v"}, "request_id": "req_003"},
]

print("\nClaude calls 3 MCP tools:\n")
for call in mcp_calls:
    print(f"   {call['tool']}({json.dumps(call['params'])})")

print("""
   Problem: MCP tool calls are JSON-RPC messages. No signing.
   - Any process on the system could send a tool call to the MCP server
   - No proof that Claude (vs a malicious script) requested the file read
   - The write_file call could have been injected by a rogue plugin
   - execute_command is especially dangerous without origin verification
""")

# =============================================================================
# PART 2: The Risk — A rogue process sends MCP tool calls
# =============================================================================

print("=" * 60)
print("PART 2: The Risk — Rogue MCP Tool Call")
print("=" * 60)

print("""
   Scenario: A malicious browser extension on the same machine
   discovers the MCP server socket. It sends a tool call:

   {"tool": "execute_command", "params": {"command": "cat ~/.ssh/id_rsa"}}

   The MCP server executes it — it looks like a normal tool call.
   The attacker now has your SSH private key.
""")

rogue_call = {
    "tool": "execute_command",
    "params": {"command": "cat ~/.ssh/id_rsa"},
    "request_id": "req_rogue",
}
print(f"   Rogue call: {json.dumps(rogue_call)}")
print("\n   The MCP server sees a valid JSON-RPC request. Without signing,")
print("   it can't distinguish Claude's requests from the attacker's.")

# =============================================================================
# PART 3: With Vouch — Every tool call is signed by the MCP server identity
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 3: MCP WITH Vouch")
print("=" * 60)

identity = generate_identity(domain="mcp-server.example.com")
signer = Signer(private_key=identity.private_key_jwk, did=identity.did)
print(f"\n   MCP Server Identity: {signer.get_did()[:50]}...")

signed_calls = []
print("\n   Signing all MCP tool calls:\n")
for call in mcp_calls:
    token = signer.sign(call)
    signed_calls.append({"token": token, "tool": call["tool"]})
    print(f"   {call['tool']} → Token: {token[:45]}...")

print("\n   Verify tool call audit trail:\n")
for entry in signed_calls:
    is_valid, passport = Verifier.verify(entry["token"], signer.get_public_key_jwk())
    if is_valid and passport:
        tool = passport.payload.get("tool")
        req_id = passport.payload.get("request_id")
        print(f"   ✅ {tool} (id={req_id}) — signed by {passport.iss[:30]}...")

# =============================================================================
# PART 4: Try the Attack Again — Rogue call is rejected
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 4: Attack Defeated — Rogue Call Rejected")
print("=" * 60)

# Rogue process tries to send a tool call
# It doesn't have the MCP server's private key
rogue_identity = generate_identity(domain="rogue-extension.evil.com")
rogue_signer = Signer(private_key=rogue_identity.private_key_jwk, did=rogue_identity.did)

rogue_token = rogue_signer.sign(rogue_call)
print("\n   Rogue process sends: execute_command('cat ~/.ssh/id_rsa')")
print(f"   Rogue token: {rogue_token[:50]}...")

# MCP server verifies against its own trusted key
is_valid, passport = Verifier.verify(rogue_token, signer.get_public_key_jwk())
print("\n   MCP server verifies against trusted key:")
print(f"   Valid? {is_valid}")
if not is_valid:
    print("   ❌ REJECTED — this call was NOT authorized by the MCP server")
    print("   SSH key exfiltration blocked. The rogue process is locked out.")

# Legitimate calls still work
is_valid, _ = Verifier.verify(signed_calls[2]["token"], signer.get_public_key_jwk())
print(f"\n   Legitimate execute_command('pytest') still valid? {is_valid} ✅")

print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAKEAWAY: MCP gives AI models powerful system access (file I/O,
command execution). Without Vouch, any process can impersonate
authorized tool calls. With Vouch, every call must carry a
valid signature from the MCP server's identity. Rogue processes
are rejected before execution — the SSH key stays safe.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
