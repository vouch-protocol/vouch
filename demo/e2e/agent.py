"""The AI agent part: business logic that decides what to do.

This module is deliberately framework-agnostic so the Vouch integration cost is
visible in isolation. The agent decides on an action using whatever logic you
like (an LLM, a planner, a rule). Then it asks the sidecar to sign that intent
and attaches the returned credential to its outbound request.

Count the Vouch-specific lines here: there is exactly one call, ``sidecar.sign``.
Nothing else in an agent has to change. To make this a real LangChain, CrewAI,
or Google ADK agent, wrap that one call as a tool the framework can invoke;
``examples/05_integrations/`` shows the per-framework glue.

The private key is never in this module. It cannot be: the agent only ever
holds a VouchSidecar handle.
"""

from __future__ import annotations

from typing import Any, Dict

from vouch_sidecar import VouchSidecar

# The service this agent calls. In a real deployment this is your bank, CRM,
# database gateway, or any API that wants proof of who authorized the call.
BANK_API = "api.bank.example.com"


async def make_payment(
    sidecar: VouchSidecar,
    amount: int,
    to_account: str,
    post_quantum: bool = False,
) -> Dict[str, Any]:
    """Decide to move money, then authorize it with a signed intent.

    Returns the outbound request the agent would send to the bank, with the
    Vouch Credential attached.
    """
    # ---- agent business logic (no Vouch here) --------------------------------
    resource = f"account:{to_account}"
    plan = f"transfer ${amount} to {resource}"

    # ---- the one Vouch line: sign this exact intent in the sidecar -----------
    credential = await sidecar.sign(
        action="transfer",
        target=BANK_API,
        resource=resource,
        post_quantum=post_quantum,
    )

    # ---- send the request, credential attached as a header -------------------
    return {
        "plan": plan,
        "action": "transfer",
        "amount": amount,
        "requested_resource": resource,
        "vouch_credential": credential,
    }
