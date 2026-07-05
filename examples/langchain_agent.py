"""
LangChain Agent Example - deterministic Vouch signing.

Instead of giving the agent a "sign a token" tool and hoping the LLM calls it,
we wrap the agent's real tools with ``protect([...])``. Every tool call is then
signed in Python before it runs - no prompt, no reliance on the model.
"""

import os

# Check for required environment variables
if not os.getenv("VOUCH_PRIVATE_KEY") or not os.getenv("VOUCH_DID"):
    print("⚠️  Please set VOUCH_PRIVATE_KEY and VOUCH_DID environment variables")
    print("   Run: vouch init --domain your-domain.com")
    print("   Then export the generated keys")

try:
    from langchain.agents import AgentType, initialize_agent
    from langchain.tools import tool
    from langchain_openai import ChatOpenAI
except ImportError:
    print("Please install langchain: pip install langchain langchain-openai")
    exit(1)

from vouch import Verifier
from vouch.integrations.langchain import current_credential, protect


@tool
def read_customer_data(customer_id: str) -> str:
    """Read a customer's record from the protected customer API."""
    # In real code this would call the API, attaching the signed credential.
    return f"<record for {customer_id}>"


def main():
    """Run a LangChain agent whose tools are signed automatically."""
    # The one line that adds Vouch: wrap the real tools. The agent never has to
    # think about signing; identity is resolved from VOUCH_PRIVATE_KEY/VOUCH_DID.
    tools = protect([read_customer_data])

    try:
        llm = ChatOpenAI(temperature=0, model="gpt-4")
    except Exception as e:
        print(f"Error initializing LLM: {e}")
        print("Make sure OPENAI_API_KEY is set")
        return

    agent = initialize_agent(
        tools, llm, agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION, verbose=True
    )

    print("\n🤖 Agent Starting...")
    print("=" * 50)
    try:
        response = agent.run("Read the customer record for customer_id 'C-42'.")
        print(f"\n✅ Agent Response:\n{response}")

        # The call the agent made was signed; verify it server-side.
        cred = current_credential()
        if cred is not None:
            ok, passport = Verifier.verify(cred)
            print(f"\n🔏 Last tool call signed & verifiable: {ok}")
            if ok:
                print(f"   intent: {passport.intent}")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
