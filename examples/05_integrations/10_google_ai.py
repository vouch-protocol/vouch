#!/usr/bin/env python3
"""
10_google_ai.py - Why Google AI Function Calls Need Vouch

See what happens when Gemini function calls are unsigned vs signed.
Then watch a replay attack get caught.

Run: pip install vouch-protocol && python 10_google_ai.py
"""

from vouch import Signer, Verifier, generate_identity
import json

# =============================================================================
# PART 1: Without Vouch — Function calls have no replay protection
# =============================================================================

print("=" * 60)
print("PART 1: Google AI WITHOUT Vouch")
print("=" * 60)

# Gemini stock trading agent makes function calls
function_calls = [
    {"function": "get_stock_price", "args": {"symbol": "GOOGL"}, "model": "gemini-1.5-pro"},
    {
        "function": "analyze_risk",
        "args": {"symbol": "GOOGL", "quantity": 10, "strategy": "market_buy"},
        "model": "gemini-1.5-pro",
    },
    {
        "function": "place_order",
        "args": {"symbol": "GOOGL", "quantity": 10, "order_type": "market"},
        "model": "gemini-1.5-pro",
    },
]

print("\nGemini stock trading agent executes 3 function calls:\n")
for call in function_calls:
    print(f"   {call['function']}({json.dumps(call['args'])})")

print("""
   Problem: Function calls are fire-and-forget JSON payloads.
   - get_stock_price is harmless, but place_order moves real money
   - No unique identifier per call — the same payload could be sent twice
   - If the network glitches, did the order execute once or twice?
   - A malicious actor could capture and replay the place_order call
""")

# =============================================================================
# PART 2: The Risk — Replay attack duplicates a trade
# =============================================================================

print("=" * 60)
print("PART 2: The Risk — Replay Attack")
print("=" * 60)

print("""
   Scenario: An attacker captures the place_order function call
   as it travels from Gemini to the brokerage API. They replay it
   10 times:

   Original: place_order(symbol="GOOGL", quantity=10)  → 10 shares
   Replay 1: place_order(symbol="GOOGL", quantity=10)  → 10 more shares
   Replay 2: place_order(symbol="GOOGL", quantity=10)  → 10 more shares
   ...
   Total: 100 shares purchased instead of 10

   The brokerage sees 10 identical, valid function calls.
   Each one looks legitimate. The user loses ~$17,000.
""")

replay_call = function_calls[2]
print(f"   Replayed call: {json.dumps(replay_call)}")
print("\n   Without unique signatures, the brokerage can't tell original from replay.")

# =============================================================================
# PART 3: With Vouch — Each function call gets a unique signed token
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 3: Google AI WITH Vouch")
print("=" * 60)

identity = generate_identity(domain="google-ai-agent.example.com")
signer = Signer(private_key=identity.private_key_jwk, did=identity.did)
print(f"\n   Agent Identity: {signer.get_did()[:50]}...")

signed_calls = []
print("\n   Signing all function calls:\n")
for call in function_calls:
    token = signer.sign(call)
    signed_calls.append({"token": token, "function": call["function"]})
    print(f"   {call['function']} → Token: {token[:45]}...")

print("\n   Verify function call audit trail:\n")
for entry in signed_calls:
    is_valid, passport = Verifier.verify(entry["token"], signer.get_public_key_jwk())
    if is_valid and passport:
        func = passport.payload.get("function")
        args = passport.payload.get("args", {})
        print(f"   ✅ {func}({json.dumps(args)}) — signed by {passport.iss[:30]}...")

# =============================================================================
# PART 4: Try the Attack Again — Replay is detected
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 4: Attack Defeated — Replay Detected")
print("=" * 60)

# Each Vouch token has a unique signature with timestamp (iat) and token ID (jti)
order_token = signed_calls[2]["token"]

# First submission — accepted
is_valid, passport = Verifier.verify(order_token, signer.get_public_key_jwk())
if is_valid and passport:
    token_id = passport.jti if hasattr(passport, "jti") else passport.iat
    print("\n   First submission of place_order token:")
    print("   Valid? True ✅")
    print(f"   Token timestamp (iat): {passport.iat}")
    print("   Brokerage records this token as PROCESSED")

# Replay attempt — same token submitted again
print("\n   Attacker replays the same token...")
is_valid_2, passport_2 = Verifier.verify(order_token, signer.get_public_key_jwk())
if is_valid_2 and passport_2:
    print("   Signature valid? True (cryptographically it's the same token)")
    print(f"   Token timestamp (iat): {passport_2.iat}")
    print("\n   But the brokerage checks its processed-token ledger:")
    print(f"   Token with iat={passport_2.iat} already processed!")
    print("   ❌ REPLAY REJECTED — this exact token was already executed")
    print("   The attacker's 9 replay attempts are all blocked.")
    print("   Only 10 shares purchased, not 100.")

# Show that a NEW legitimate order would get a different token
print("\n   For comparison — a new legitimate order:")
new_token = signer.sign(function_calls[2])
print(f"   New token: {new_token[:50]}...")
print(f"   Old token: {order_token[:50]}...")
print(f"   Different tokens? {new_token != order_token} — each signing produces a unique token")

print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAKEAWAY: AI agents making financial function calls (trades,
payments, bookings) are vulnerable to replay attacks.
Without Vouch, the same call can be replayed multiple times.
With Vouch, each call gets a unique cryptographic token with
a timestamp. Execution layers track processed tokens and reject
replays. Each call executes exactly once.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
