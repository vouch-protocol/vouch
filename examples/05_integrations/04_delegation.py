#!/usr/bin/env python3
"""
04_delegation.py - One-line principal -> agent delegation.

A human (or a supervisor agent) grants a worker agent narrow authority, and the
worker's every signed action is automatically chained under that grant. The
protocol enforces that a worker can only *narrow* the granted authority, never
widen it (Specification §9.3).

Two calls do the whole thing:

    grant = vouch.delegate(action=..., target=..., resource=..., signer=principal)
    tools = protect([...], parent=grant)

Run:
    pip install vouch-protocol
    python 04_delegation.py
"""

import os

import vouch
from vouch import Signer, Verifier, current_credential, delegate, generate_identity, protect

# --- Principal: a human/supervisor with their own identity --------------------
principal = generate_identity(domain="alice.example.com")
principal_signer = Signer(private_key=principal.private_key_jwk, did=principal.did)

# --- Worker agent: identity resolved automatically from the environment -------
agent = generate_identity(domain="billing-agent.example.com")
os.environ["VOUCH_PRIVATE_KEY"] = agent.private_key_jwk
os.environ["VOUCH_DID"] = agent.did

# 1) The principal delegates narrow authority in ONE call.
grant = delegate(
    action="charge",
    target="api.payments.example.com",
    resource="invoices",  # the agent may act only within "invoices"
    to=agent.did,
    signer=principal_signer,
)
print(f"Grant issued by {grant['issuer']}")
print(f"  granting: {grant['credentialSubject']['intent']}")


# 2) The agent's tools are chained under the grant in ONE call.
def charge_invoice(invoice_id: str, amount: float) -> str:
    return f"charged {amount} on {invoice_id}"


tools = protect([charge_invoice], parent=grant)

# When the agent acts, the signed credential carries the full delegation chain.
tools[0]("invoices/42", 99.0)
cred = current_credential()
chain = cred["credentialSubject"]["delegationChain"]
print("\nAgent acted. Its credential carries a delegation chain:")
print(f"  {chain[0]['issuer']}  ->  {chain[0]['subject']}")

ok, passport = Verifier.verify_credential(cred, agent.public_key_jwk)
print(f"\nVerifies: {ok} | agent intent: {passport.intent['resource']}")
print("The verifier can see the action was authorized by the principal,")
print("and that the agent stayed within the 'invoices' grant.")
