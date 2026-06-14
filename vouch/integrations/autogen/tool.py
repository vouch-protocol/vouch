"""
Vouch Protocol AutoGen Integration.

Provides AutoGen-compatible functions that issue v1.0 Vouch Credentials
(eddsa-jcs-2022 Data Integrity proofs) to authorize agent tool calls.

Note: AutoGen is in maintenance mode as of 2026, folded into the Microsoft
Agent Framework. This wrapper is kept working for existing AutoGen users; new
deployments should prefer the Microsoft Agent Framework wrapper once available.
"""

from typing import Annotated, Optional

from vouch.integrations._common import load_signer, sign_tool_call_json


def sign_action(
    action: Annotated[str, "The verb: read, write, execute, send, ..."],
    target: Annotated[str, "The service or URL being called"],
    resource: Annotated[Optional[str], "The specific object, e.g. customer:123"] = None,
) -> str:
    """Issue a Vouch Credential authorizing a single tool call for AutoGen agents.

    Call this before any authenticated request to an external service. Attach
    the returned JSON as a 'Vouch-Credential' header or send it in the body.

    Returns:
        A compact JSON Vouch Credential, or an error string.
    """
    try:
        signer = load_signer()
        return sign_tool_call_json(signer, action, target, resource)
    except Exception as e:
        return f"Error issuing Vouch Credential: {e}"


# Function registry for AutoGen.
VOUCH_FUNCTIONS = [
    {
        "name": "sign_action",
        "description": "Issue a Vouch Credential authorizing an authenticated tool call.",
        "function": sign_action,
    }
]
