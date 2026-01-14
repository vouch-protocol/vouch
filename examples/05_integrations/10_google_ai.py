#!/usr/bin/env python3
"""
10_google_ai.py - Vouch with Google AI (Generative AI SDK)

Sign function calls in Google's Generative AI SDK.

Run: pip install google-generativeai && python 10_google_ai.py
"""

from vouch import Signer

print("🔮 Google AI (Generative AI) + Vouch")
print("=" * 50)

# =============================================================================
# Google AI Integration
# =============================================================================

print("""
import google.generativeai as genai
from vouch import Signer
from vouch.integrations.google import VouchGoogleAI

# Configure
genai.configure(api_key="YOUR_API_KEY")

# Create signed wrapper
google_ai = VouchGoogleAI(
    signer=Signer(name="Google AI Agent"),
)

# Define tools
def get_stock_price(symbol: str) -> float:
    '''Get current stock price.'''
    return 150.00  # Mock

def place_order(symbol: str, quantity: int) -> str:
    '''Place a stock order.'''
    return f"Order placed: {quantity} shares of {symbol}"

# Create model with signed function calling  
model = google_ai.wrap_model(
    genai.GenerativeModel(
        model_name="gemini-1.5-pro",
        tools=[get_stock_price, place_order]
    )
)

# All function calls are signed
response = model.generate_content("Buy 10 shares of GOOGL")
""")

# =============================================================================
# Demo
# =============================================================================

signer = Signer(name="Google AI Agent")

# Simulate function call
function_call = {
    "function": "place_order",
    "args": {"symbol": "GOOGL", "quantity": 10},
    "model": "gemini-1.5-pro"
}

import json
token = signer.sign(json.dumps(function_call))

print("\n📋 Signed Function Call:")
print(f"   Function: {function_call['function']}")
print(f"   Args: {function_call['args']}")
print(f"   Token: {token[:50]}...")

print("""
✅ Google AI SDK Benefits:
   • Works with Gemini 1.5 and 2.0
   • Function calls signed automatically
   • Compatible with all genai features
   • Lightweight wrapper
""")
