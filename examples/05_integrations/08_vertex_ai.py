#!/usr/bin/env python3
"""
08_vertex_ai.py - Vouch with Google Vertex AI

Sign Vertex AI agent actions and function calls.

Run: python 08_vertex_ai.py
"""

from vouch import Signer

print("☁️ Vertex AI + Vouch")
print("=" * 50)

# =============================================================================
# Vertex AI Integration
# =============================================================================

print("""
from vertexai.generative_models import GenerativeModel, FunctionDeclaration
from vouch.integrations.vertex_ai import VouchVertexAI

# Create signed Vertex AI wrapper
vertex = VouchVertexAI(
    signer=Signer(name="Vertex AI Agent"),
    project="your-gcp-project",
    location="us-central1"
)

# Define tools
get_weather_func = FunctionDeclaration(
    name="get_weather",
    description="Get weather for a city",
    parameters={
        "type": "object",
        "properties": {
            "city": {"type": "string"}
        }
    }
)

# Create model with signed function calling
model = vertex.create_model(
    "gemini-1.5-pro",
    tools=[get_weather_func]
)

# Function calls are signed before execution
response = model.generate_content(
    "What's the weather in Tokyo?",
    vouch_intent="Weather query for user request"
)
""")

# =============================================================================
# Demo
# =============================================================================

signer = Signer(name="Vertex AI Agent")

# Simulate Vertex AI function call
function_call = {
    "function": "get_weather",
    "args": {"city": "Tokyo"},
    "model": "gemini-1.5-pro",
    "intent": "Weather query"
}

import json
token = signer.sign(json.dumps(function_call))

print("\n📋 Signed Vertex AI Call:")
print(f"   Function: {function_call['function']}")
print(f"   Args: {function_call['args']}")
print(f"   Token: {token[:50]}...")

print("""
✅ Vertex AI Benefits:
   • Gemini function calls signed
   • Enterprise-grade audit trail
   • GCP IAM + Vouch = defense in depth
   • Works with all Vertex AI models
""")
