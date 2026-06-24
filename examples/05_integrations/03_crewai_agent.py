#!/usr/bin/env python3
"""
03_crewai_agent.py - A REAL CrewAI agent that signs its actions with Vouch.

Unlike 02_crewai.py (which simulates a crew with plain Signer/Verifier calls and
print statements), this file uses actual CrewAI objects: a real `Agent`, a real
`Task`, and a real `Crew` that you `.kickoff()`. The agent's LLM decides, on its
own, to call the Vouch signing tool before it touches an external API.

What to look for:
  - `generate_identity(...)`         -> gives the agent a DID + Ed25519 keypair
  - `tools=[sign_request]`           -> grants the agent the Vouch signing tool
  - the agent calls that tool        -> produces a real, verifiable Vouch-Token
  - `Verifier.verify(...)`           -> proves the token came from THIS agent

Run:
    pip install vouch-protocol crewai
    export OPENAI_API_KEY=sk-...      # (or any LLM provider CrewAI supports)
    python 03_crewai_agent.py
"""

import os

from crewai import Agent, Crew, Task

from vouch import Verifier, generate_identity
from vouch.integrations.crewai import sign_request  # a ready-made CrewAI @tool

# -----------------------------------------------------------------------------
# 1. Give the agent a cryptographic identity (DID + Ed25519 keypair).
#    The Vouch tool reads the key/DID from the environment, so the private key
#    never enters the LLM's context window — a prompt injection cannot read it.
# -----------------------------------------------------------------------------
identity = generate_identity(domain="billing-agent.example.com")
os.environ["VOUCH_PRIVATE_KEY"] = identity.private_key_jwk
os.environ["VOUCH_DID"] = identity.did

print(f"Agent identity: {identity.did}")

# -----------------------------------------------------------------------------
# 2. A REAL CrewAI agent. The only Vouch-specific line is `tools=[sign_request]`.
#    `sign_request` is imported from vouch.integrations.crewai and is a CrewAI
#    @tool whose body calls vouch.Signer.sign(...) under the hood.
# -----------------------------------------------------------------------------
billing_agent = Agent(
    role="Billing Agent",
    goal="Charge a customer's invoice, but cryptographically prove who you are "
    "before making the call.",
    backstory="An autonomous agent that moves money, so every action it takes "
    "must be signed and accountable.",
    tools=[sign_request],  # <-- this is what links the agent to Vouch
    verbose=True,
)

# -----------------------------------------------------------------------------
# 3. A REAL task. The instructions tell the agent to sign its intent first.
#    When the LLM reasons through this, it will invoke the `sign_request` tool.
# -----------------------------------------------------------------------------
charge_task = Task(
    description=(
        "You need to charge invoice #42 for $99.00 via the billing API at "
        "api.payments.example.com. Before making that call, use the "
        "'Sign Request with Vouch' tool to sign your intent. Pass "
        "intent='charge_invoice' and target='api.payments.example.com'. "
        "Return the exact Vouch-Token string the tool gives you."
    ),
    expected_output="The Vouch-Token string produced by the signing tool.",
    agent=billing_agent,
)

# -----------------------------------------------------------------------------
# 4. Run the crew. The agent's LLM calls the Vouch tool on its own.
# -----------------------------------------------------------------------------
crew = Crew(agents=[billing_agent], tasks=[charge_task], verbose=True)
result = crew.kickoff()

print("\n--- Crew result ---")
print(result)

# -----------------------------------------------------------------------------
# 5. Server side: prove the token the agent produced is genuinely from THIS
#    agent's key. This is what the billing API would do on receipt.
# -----------------------------------------------------------------------------
token = str(result).replace("Vouch-Token:", "").strip()
is_valid, passport = Verifier.verify(token, identity.public_key_jwk)

print("\n--- Server-side verification ---")
print(f"Valid?  {is_valid}")
if is_valid and passport:
    print(f"Issuer: {passport.iss}")
    print(f"Intent: {passport.payload}")
    print("The billing API now KNOWS which agent asked, and what it intended.")
