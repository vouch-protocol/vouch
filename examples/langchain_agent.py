import os

# 1. Setup (Mocking the environment)
# pip install langchain langchain-openai
from langchain.agents import initialize_agent, AgentType
from langchain.chat_models import ChatOpenAI
from vouch.integrations.langchain.tools import VouchSignerTool
from vouch.keys import generate_identity_keys # Hypothetical helper

# Generate a temporary identity for this demo
print("🔑 Setting up Vouch Identity...")
# (In real life, load these from env vars)
# For demo, we just generate raw keys here manually or use your keys.py logic
# Assume 'my_private_key' and 'did:web:finance-bot' exist.

MY_PRIVATE_KEY = '{"kty":"OKP","crv":"Ed25519" ... }' # Paste a real key here for testing
MY_DID = "did:web:finance-bot"

# 2. Initialize the Tool
vouch_tool = VouchSignerTool(
    private_key_json=MY_PRIVATE_KEY,
    agent_did=MY_DID
)

# 3. Give the Tool to the Agent
llm = ChatOpenAI(temperature=0)
tools = [vouch_tool]

agent = initialize_agent(
    tools, 
    llm, 
    agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION, 
    verbose=True
)

# 4. Run the Agent
print("\n🤖 Agent Requesting Action...")
response = agent.run("I need to book a flight to London. Please generate a Vouch Token to authorize this request.")

print(f"\n✅ Agent Response: {response}")
