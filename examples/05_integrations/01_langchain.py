#!/usr/bin/env python3
"""
01_langchain.py - Vouch with LangChain

Sign all LangChain tool calls with Vouch Protocol.

Run: pip install langchain-core && python 01_langchain.py
"""

from vouch import Signer
from vouch.integrations.langchain import VouchSignerTool

# =============================================================================
# Option 1: Wrap Your Tools
# =============================================================================

print("🔗 LangChain + Vouch")
print("=" * 50)

# Create a signer
signer = Signer(name="LangChain Agent", email="agent@example.com")

# Wrap any tool to sign its calls
from langchain_core.tools import tool


@tool
def transfer_funds(from_account: str, to_account: str, amount: float) -> str:
    """Transfer funds between accounts."""
    return f"Transferred ${amount} from {from_account} to {to_account}"


# Make it sign all calls
signed_tool = VouchSignerTool(tool=transfer_funds, signer=signer)

# When invoked, the call is signed
result = signed_tool.invoke({"from_account": "12345", "to_account": "67890", "amount": 100.00})

print(f"✅ Tool result: {result}")
print("📝 (Call was cryptographically signed)")

# =============================================================================
# Option 2: With LangChain Agents
# =============================================================================

print("\n🤖 With LangChain Agent")
print("=" * 50)

# In a real agent setup:
# tools = [VouchSignerTool(tool=t, signer=signer) for t in your_tools]
# agent = create_react_agent(llm, tools, prompt)

print("""
from langchain.agents import create_react_agent
from vouch.integrations.langchain import VouchSignerTool

# Wrap all tools
signed_tools = [VouchSignerTool(tool=t, signer=signer) for t in tools]

# Create agent with signed tools
agent = create_react_agent(llm, signed_tools, prompt)

# Every tool call is now signed!
""")

print("✅ All LangChain tool calls are now auditable!")
