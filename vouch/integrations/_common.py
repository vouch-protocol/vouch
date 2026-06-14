"""
Shared helpers for Vouch framework integrations.

Every framework wrapper (LangChain, CrewAI, AutoGen, MCP, ...) routes through
this module so they all issue v1.0 Verifiable Credentials with an
eddsa-jcs-2022 Data Integrity proof, instead of the legacy JWS path.

See Specification sections 5 and 7.1 for the issuance flow.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional, Tuple

from vouch import Signer, Verifier


def load_signer() -> Signer:
    """Build a Signer from the VOUCH_PRIVATE_KEY and VOUCH_DID environment vars.

    Raises:
        RuntimeError: if either variable is missing.
    """
    private_key = os.getenv("VOUCH_PRIVATE_KEY")
    did = os.getenv("VOUCH_DID")
    if not private_key:
        raise RuntimeError("VOUCH_PRIVATE_KEY is not set")
    if not did:
        raise RuntimeError("VOUCH_DID is not set")
    return Signer(private_key=private_key, did=did)


def sign_tool_call(
    signer: Signer,
    action: str,
    target: str,
    resource: Optional[str] = None,
    *,
    parent_credential: Optional[Dict[str, Any]] = None,
    hybrid: bool = False,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Issue a v1.0 Vouch Credential authorizing a single tool call.

    Args:
        signer: A configured Signer.
        action: The verb, e.g. "read", "write", "execute", "send".
        target: The service or URL being called.
        resource: The specific object, e.g. "customer:123". Defaults to
            target when omitted so callers that only know a coarse target
            still produce a spec-valid credential (intent.resource is
            REQUIRED in v1.0).
        parent_credential: A previously issued credential whose delegation
            chain this call extends. Enables agent-to-agent delegation with
            capability attenuation (v1.7).
        hybrid: Issue under the post-quantum hybrid profile when True.
        valid_seconds: Optional validity window override.

    Returns:
        A signed Vouch Credential dict.
    """
    intent = {"action": action, "target": target, "resource": resource or target}
    issue = signer.sign_credential_hybrid if hybrid else signer.sign_credential
    return issue(
        intent=intent,
        parent_credential=parent_credential,
        valid_seconds=valid_seconds,
    )


def sign_tool_call_json(*args: Any, **kwargs: Any) -> str:
    """Same as sign_tool_call but returns compact JSON for transport.

    The result is meant to travel in an HTTP body, or in a Vouch-Credential
    header for the smaller eddsa-jcs-2022 profile.
    """
    return json.dumps(sign_tool_call(*args, **kwargs), separators=(",", ":"))


def verify_tool_call(
    credential: Any,
    public_key: Optional[Any] = None,
) -> Tuple[bool, Optional[Any]]:
    """Verify a credential produced by sign_tool_call.

    Returns an (is_valid, passport) tuple, mirroring
    Verifier.verify_credential.
    """
    return Verifier.verify_credential(credential, public_key=public_key)
