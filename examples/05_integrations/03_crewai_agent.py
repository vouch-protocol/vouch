#!/usr/bin/env python3
"""
03_crewai_agent.py - Deterministic Vouch signing for a real CrewAI agent.

02_crewai.py *simulates* a crew with plain Signer/Verifier calls. This file
shows the real, recommended integration: a genuine crewai Agent/Task/Crew where
**every tool call is signed automatically, in Python, before it runs** - with no
prompt telling the model to sign, and no dependence on the model remembering to.

The old way (fragile): give the agent a `sign_request` tool and write a
paragraph begging the LLM to call it and thread the token onward. If the model
forgets, nothing is signed and nothing fails loudly.

The new way (this file): wrap the real tool once. Signing is not the model's job.

    pip install vouch-protocol crewai
    export OPENAI_API_KEY=sk-...
    python 03_crewai_agent.py
"""

import os

from vouch import Verifier, generate_identity

# `protect` wraps real tools so each call is signed deterministically;
# `current_credential` exposes the credential that was signed for the last call.
from vouch.integrations.crewai import current_credential, protect

# -----------------------------------------------------------------------------
# 1. Identity. In production this comes from `vouch init` (env vars or the
#    on-disk keystore) and the signer is resolved automatically. We set it
#    inline here so the example is self-contained.
# -----------------------------------------------------------------------------
identity = generate_identity(domain="billing-agent.example.com")
os.environ["VOUCH_PRIVATE_KEY"] = identity.private_key_jwk
os.environ["VOUCH_DID"] = identity.did
print(f"Agent identity: {identity.did}")


# -----------------------------------------------------------------------------
# 2. A normal tool that does the real work. Note: it says NOTHING about Vouch.
#    The developer just writes the action.
# -----------------------------------------------------------------------------
try:
    from crewai.tools import tool
    from crewai import Agent, Crew, Task

    CREWAI = True
except ImportError:
    CREWAI = False

    def tool(name):  # minimal stand-in so the file still runs without crewai
        def deco(fn):
            fn.name = name
            return fn

        return deco


@tool("Charge Invoice")
def charge_invoice(invoice_id: str, amount: float, target: str = "api.payments.example.com") -> str:
    """Charge a customer's invoice via the billing API."""
    # In real code: requests.post(f"https://{target}/charge", json=..., headers=...)
    return f"Charged {amount} on invoice {invoice_id}"


# -----------------------------------------------------------------------------
# 3. The ONE line that adds Vouch: wrap the tools. Every call the agent makes to
#    `charge_invoice` is now signed before the body runs - deterministically, in
#    code, whether or not the LLM "knows" about signing.
# -----------------------------------------------------------------------------
signed_tools = protect([charge_invoice])


def run_with_real_crew():
    """The real path: a CrewAI agent that calls the protected tool."""
    agent = Agent(
        role="Billing Agent",
        goal="Charge invoices. You do not need to think about security.",
        backstory="An autonomous billing agent.",
        tools=signed_tools,
        verbose=True,
    )
    task = Task(
        description="Charge invoice #42 for $99.00.",
        expected_output="Confirmation that the invoice was charged.",
        agent=agent,
    )
    Crew(agents=[agent], tasks=[task]).kickoff()


def run_without_crew():
    """No LLM key? Call the protected tool directly to see signing happen."""
    print("\n(crewai/LLM not available - invoking the protected tool directly)")
    result = signed_tools[0]("42", 99.00, target="api.payments.example.com")
    print(f"Tool result: {result}")


if CREWAI and os.getenv("OPENAI_API_KEY"):
    run_with_real_crew()
else:
    run_without_crew()

# -----------------------------------------------------------------------------
# 4. Server side: the credential the agent signed is available without the tool
#    body or the prompt ever mentioning it. This is what the billing API verifies.
# -----------------------------------------------------------------------------
credential = current_credential()
print("\n--- Server-side verification ---")
if credential is None:
    print("No credential - no identity was resolved.")
else:
    ok, passport = Verifier.verify(credential, identity.public_key_jwk)
    print(f"Valid?  {ok}")
    if ok:
        print(f"Issuer: {passport.iss}")
        print(f"Intent: {passport.intent}")
        print("The billing API knows which agent acted, and what it intended -")
        print("and the agent's code never had to remember to sign.")
