"""
Signed tool descriptors and a customs-officer client for MCP tools.

An agent reads a tool's description and input schema, then trusts it. Two
attacks follow: an unsigned tool nobody vouched for, and the "rug pull", where a
tool is approved with a benign description and later silently swapped for a
malicious one. This module gives a tool a verifiable publisher signature over
its description and schema, and a gate that refuses unsigned tools and refuses
any tool whose description changed after it was approved.

This is the open format plus a local reference client. A hosted tool registry
service is out of scope here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import data_integrity, jcs

# The fields a signature commits to. Volatile transport fields (annotations,
# server-assigned ids) are deliberately excluded so a re-publish with the same
# description verifies identically.
SIGNABLE_FIELDS = ("name", "description", "inputSchema")


def signable_view(tool: Dict[str, Any]) -> Dict[str, Any]:
    """The subset of a tool descriptor that a signature and digest cover."""
    view = {f: tool[f] for f in SIGNABLE_FIELDS if f in tool}
    if "publisher" in tool:
        view["publisher"] = tool["publisher"]
    return view


def tool_digest(tool: Dict[str, Any]) -> str:
    """Stable SHA-256 over the JCS-canonical signable view of a tool."""
    return hashlib.sha256(jcs.canonicalize(signable_view(tool))).hexdigest()


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise ValueError("signing a tool requires a Signer with an Ed25519 key")
    return raw


def sign_tool(signer: Any, tool: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a copy of the tool descriptor with the publisher DID and a Data
    Integrity proof over its signable view attached.
    """
    signed = dict(tool)
    signed["publisher"] = signer.get_did()
    # Build the proof over the signable view so verification is independent of
    # any extra transport fields the descriptor may carry.
    view = signable_view(signed)
    proof = data_integrity.build_proof(view, _raw_priv(signer), signer.verification_method_id())
    signed["proof"] = proof
    return signed


def verify_tool(signed_tool: Dict[str, Any], public_key) -> bool:
    """Verify a signed tool's publisher signature over its signable view."""
    proof = signed_tool.get("proof")
    if not isinstance(proof, dict):
        return False
    view = signable_view(signed_tool)
    view["proof"] = proof
    try:
        return data_integrity.verify_proof(view, public_key)
    except Exception:
        return False


@dataclass
class ToolVerdict:
    allowed: bool
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"allowed": self.allowed, "reasons": list(self.reasons)}


class ToolGate:
    """
    The customs officer. Holds the public keys of trusted publishers and the
    approved digest of each tool it has cleared. On every check it:

      1. refuses an unsigned tool (when require_signed),
      2. refuses a tool whose publisher is not trusted,
      3. refuses an invalid signature,
      4. refuses a tool whose description changed since it was approved
         (rug-pull detection).

    `approve` records the current digest of a verified tool as the baseline.
    """

    def __init__(
        self,
        trusted_publishers: Optional[Dict[str, Any]] = None,
        require_signed: bool = True,
    ) -> None:
        self._publishers: Dict[str, Any] = dict(trusted_publishers or {})
        self.require_signed = require_signed
        self._approved: Dict[str, str] = {}  # tool name -> approved digest

    def trust_publisher(self, did: str, public_key) -> None:
        self._publishers[did] = public_key

    def _verify_signature(self, signed_tool: Dict[str, Any], reasons: List[str]) -> bool:
        proof = signed_tool.get("proof")
        if not isinstance(proof, dict):
            if self.require_signed:
                reasons.append("unsigned")
            return not self.require_signed
        publisher = signed_tool.get("publisher")
        key = self._publishers.get(publisher)
        if key is None:
            reasons.append(f"untrusted_publisher:{publisher}")
            return False
        if not verify_tool(signed_tool, key):
            reasons.append("invalid_signature")
            return False
        return True

    def approve(self, signed_tool: Dict[str, Any]) -> ToolVerdict:
        """Verify a tool and record its digest as the approved baseline."""
        reasons: List[str] = []
        if not self._verify_signature(signed_tool, reasons):
            return ToolVerdict(allowed=False, reasons=reasons)
        self._approved[signed_tool["name"]] = tool_digest(signed_tool)
        return ToolVerdict(allowed=True)

    def check(self, signed_tool: Dict[str, Any]) -> ToolVerdict:
        """
        Check a tool before use: signature, trusted publisher, and that its
        description has not changed since approval.
        """
        reasons: List[str] = []
        signed_ok = self._verify_signature(signed_tool, reasons)

        name = signed_tool.get("name")
        approved_digest = self._approved.get(name)
        if approved_digest is not None and tool_digest(signed_tool) != approved_digest:
            reasons.append("description_changed_since_approval")

        return ToolVerdict(allowed=signed_ok and not reasons, reasons=reasons)
