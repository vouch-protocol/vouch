#!/usr/bin/env python3
"""
04_autogen.py - Vouch with Microsoft AutoGen

Sign multi-agent conversations in AutoGen.

Run: pip install pyautogen && python 04_autogen.py
"""

from vouch import Signer

print("🔄 AutoGen + Vouch")
print("=" * 50)

# =============================================================================
# AutoGen Multi-Agent Setup
# =============================================================================

print("""
from autogen import AssistantAgent, UserProxyAgent
from vouch.integrations.autogen import VouchAutoGen

# Create agents with Vouch signing
assistant = VouchAutoGen.wrap_agent(
    AssistantAgent(
        name="assistant",
        llm_config=llm_config,
    ),
    signer=Signer(name="Assistant Agent"),
)

user_proxy = VouchAutoGen.wrap_agent(
    UserProxyAgent(
        name="user_proxy",
        human_input_mode="NEVER",
    ),
    signer=Signer(name="User Proxy"),
)

# Start conversation - all messages are signed!
user_proxy.initiate_chat(
    assistant,
    message="Write a Python function to calculate fibonacci",
)
""")

# =============================================================================
# What Gets Signed
# =============================================================================

print("\n📝 AutoGen Signing Points:")
print("  ✅ Agent-to-agent messages")
print("  ✅ Code generation outputs")
print("  ✅ Function call requests")
print("  ✅ Tool execution results")

# Demo
assistant = Signer(name="AutoGen Assistant")
user_proxy = Signer(name="AutoGen UserProxy")

msg1 = assistant.sign('{"role": "assistant", "content": "Here is the code..."}')
msg2 = user_proxy.sign('{"role": "user", "content": "Execute this code"}')

print("\n📨 Signed Message Flow:")
print(f"   Assistant → UserProxy: {msg1[:50]}...")
print(f"   UserProxy → Assistant: {msg2[:50]}...")

print("""
✅ Complete conversation audit trail!
""")
