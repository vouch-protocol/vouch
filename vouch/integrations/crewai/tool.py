"""
Vouch Protocol CrewAI Integration.

Provides CrewAI-compatible tools that issue v1.0 Vouch Credentials
(eddsa-jcs-2022 Data Integrity proofs) to authorize agent tool calls.
"""

from typing import Optional

try:
    from crewai.tools import tool
except ImportError:
    # Fallback so this module imports without CrewAI installed.
    def tool(name):  # type: ignore
        def decorator(func):
            return func

        return decorator


from vouch.integrations._common import load_signer, sign_tool_call_json


@tool("Sign Request with Vouch")
def sign_request(action: str, target: str, resource: Optional[str] = None) -> str:
    """Issue a cryptographic Vouch Credential authorizing one tool call.

    Call this before any authenticated request to an external service. Attach
    the returned JSON as a 'Vouch-Credential' header or send it in the body.

    Args:
        action: The verb, e.g. 'read', 'write', 'execute', 'send'.
        target: The service or URL being called.
        resource: The specific object, e.g. 'customer:123'. Defaults to target.

    Returns:
        A compact JSON Vouch Credential, or an error string.
    """
    try:
        signer = load_signer()
        return sign_tool_call_json(signer, action, target, resource)
    except Exception as e:
        return f"Error issuing Vouch Credential: {e}"


class VouchCrewTools:
    """Collection of Vouch tools for CrewAI agents."""

    sign_request = sign_request


# Backward-compatible alias.
VouchSignerTool = sign_request
