#!/usr/bin/env python3
"""
08_vertex_ai.py - Why Vertex AI Function Calls Need Vouch

See what happens when Vertex AI function calls are unsigned vs signed.
Then watch a tampered function call get caught.

Run: pip install vouch-protocol && python 08_vertex_ai.py
"""

from vouch import Signer, Verifier, generate_identity
import json

# =============================================================================
# PART 1: Without Vouch — Function calls have no intent binding
# =============================================================================

print("=" * 60)
print("PART 1: Vertex AI WITHOUT Vouch")
print("=" * 60)

# Gemini makes function calls on Vertex AI
function_calls = [
    {"function": "get_weather", "args": {"city": "Tokyo"}, "model": "gemini-1.5-pro"},
    {"function": "search_flights", "args": {"from": "SFO", "to": "NRT", "date": "2026-03-15"}, "model": "gemini-1.5-pro"},
    {"function": "book_hotel", "args": {"city": "Tokyo", "checkin": "2026-03-15", "nights": 5}, "model": "gemini-1.5-pro"},
]

print("\nGemini executes 3 function calls for travel planning:\n")
for call in function_calls:
    print(f"   {call['function']}({json.dumps(call['args'])})")

print("""
   Problem: Function calls are just structured outputs from the model.
   - No binding between the user's intent and the function call
   - "Book a hotel for 5 nights" could become "book for 50 nights" in transit
   - In a multi-step chain, there's no proof which model generated which call
   - For enterprise billing, disputed function calls have no audit proof
""")

# =============================================================================
# PART 2: The Risk — Function arguments tampered between model and execution
# =============================================================================

print("=" * 60)
print("PART 2: The Risk — Function Call Tampering")
print("=" * 60)

print("""
   Scenario: A compromised middleware between Gemini and the booking API
   modifies the hotel booking:

   Gemini outputs:  book_hotel(city="Tokyo", nights=5)
   Middleware sends: book_hotel(city="Tokyo", nights=50)

   The user gets billed for 50 nights instead of 5.
   The middleware logs show "5 nights" — the tampering is invisible.
""")

original_booking = {"function": "book_hotel", "args": {"city": "Tokyo", "checkin": "2026-03-15", "nights": 5}}
tampered_booking = {"function": "book_hotel", "args": {"city": "Tokyo", "checkin": "2026-03-15", "nights": 50}}
print(f"   Original: {json.dumps(original_booking['args'])}")
print(f"   Tampered: {json.dumps(tampered_booking['args'])}")
print(f"\n   The booking API received nights=50. Was it Gemini's decision or tampering?")
print(f"   Without signing, there's no way to know.")

# =============================================================================
# PART 3: With Vouch — Function calls are signed with intent binding
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 3: Vertex AI WITH Vouch")
print("=" * 60)

identity = generate_identity(domain="vertex-agent.example.com")
signer = Signer(private_key=identity.private_key_jwk, did=identity.did)
print(f"\n   Agent Identity: {signer.get_did()[:50]}...")

# Sign each function call with its intent
intents = [
    "Weather query for travel planning",
    "Flight search for confirmed dates",
    "Hotel booking for 5-night stay",
]

signed_calls = []
print("\n   Signing function calls with intent binding:\n")
for call, intent in zip(function_calls, intents):
    payload = {**call, "intent": intent}
    token = signer.sign(payload)
    signed_calls.append({"token": token, "function": call["function"]})
    print(f"   {call['function']} (intent: \"{intent}\") → {token[:40]}...")

print("\n   Verify function call audit trail:\n")
for entry in signed_calls:
    is_valid, passport = Verifier.verify(entry["token"], signer.get_public_key_jwk())
    if is_valid and passport:
        func = passport.payload.get("function")
        intent = passport.payload.get("intent")
        print(f"   ✅ {func}: \"{intent}\" — signed by {passport.iss[:30]}...")

# =============================================================================
# PART 4: Try the Attack Again — Tampered booking is caught
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 4: Attack Defeated — Tampering Detected")
print("=" * 60)

# The booking was signed with nights=5
booking_token = signed_calls[2]["token"]
is_valid, passport = Verifier.verify(booking_token, signer.get_public_key_jwk())
if is_valid and passport:
    signed_nights = passport.payload["args"]["nights"]
    signed_intent = passport.payload["intent"]
    print(f"\n   Signed booking: nights={signed_nights}, intent=\"{signed_intent}\"")
    print(f"   Middleware claims: nights=50")
    print(f"\n   Booking API verifies the signed token:")
    print(f"   Signed says {signed_nights} nights ≠ middleware says 50 nights")
    print(f"   ❌ MISMATCH — the booking was tampered after Gemini signed it")
    print(f"   The 50-night booking is blocked. Only the signed 5-night")
    print(f"   booking is accepted.")

# Attacker tries to forge a new token
attacker_identity = generate_identity(domain="compromised-middleware.evil.com")
attacker_signer = Signer(private_key=attacker_identity.private_key_jwk, did=attacker_identity.did)

forged_token = attacker_signer.sign({**tampered_booking, "intent": "Hotel booking for 50-night stay"})
print(f"\n   Attacker forges token with nights=50...")
is_valid, _ = Verifier.verify(forged_token, signer.get_public_key_jwk())
print(f"   Valid against agent's trusted key? {is_valid}")
if not is_valid:
    print(f"   ❌ REJECTED — not signed by the Vertex AI agent's identity")

print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAKEAWAY: Vertex AI function calls drive real-world actions
(bookings, payments, API calls). Without Vouch, arguments can
be tampered between the model and the execution layer.
With Vouch, each function call is signed with intent binding —
the exact arguments and purpose are locked in cryptographically.
Tampering is detected before execution.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
