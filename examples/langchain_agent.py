"""
LangChain Agent Example - Using Vouch for authenticated API calls.

This example demonstrates how to integrate Vouch signing into a LangChain agent.
"""

import os

# Check for required environment variables
if not os.getenv("VOUCH_PRIVATE_KEY") or not os.getenv("VOUCH_DID"):
    print("⚠️  Please set VOUCH_PRIVATE_KEY and VOUCH_DID environment variables")
    print("   Run: vouch init --domain your-domain.com")
    print("   Then export the generated keys")

try:
    from langchain.agents import initialize_agent, AgentType
    from langchain_openai import ChatOpenAI
except ImportError:
    print("Please install langchain: pip install langchain langchain-openai")
    exit(1)

from vouch.integrations.langchain.tool import VouchSignerTool
from vouch import generate_identity


def main():
    """Run the LangChain agent with Vouch signing capability."""
    
    # Option 1: Use environment variables (recommended)
    vouch_tool = VouchSignerTool()
    
    # Option 2: Use explicit keys (for testing)
    # keys = generate_identity(domain='my-agent.com')
    # vouch_tool = VouchSignerTool(
    #     private_key_json=keys.private_key_jwk,
    #     agent_did=keys.did
    # )
    
    # Initialize LLM (requires OPENAI_API_KEY)
    try:
        llm = ChatOpenAI(temperature=0, model="gpt-4")
    except Exception as e:
        print(f"Error initializing LLM: {e}")
        print("Make sure OPENAI_API_KEY is set")
        return
    
    # Create agent with Vouch tool
    tools = [vouch_tool]
    
    agent = initialize_agent(
        tools,
        llm,
        agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True
    )
    
    # Run the agent
    print("\n🤖 Agent Starting...")
    print("=" * 50)
    
    try:
        response = agent.run(
            "I need to access a protected API. "
            "Please generate a Vouch Token to prove my identity "
            "for the action 'read_customer_data'."
        )
        print(f"\n✅ Agent Response:\n{response}")
        
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
