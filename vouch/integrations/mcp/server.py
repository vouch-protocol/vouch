"""
Vouch Protocol MCP Server.

A Model Context Protocol server, built on the official MCP Python SDK,
that lets MCP-compatible clients (Claude Desktop, Cursor, agent
frameworks in any language) both *issue* and *verify* Vouch Credentials.

Works with both major lines of the official SDK: mcp 1.x (protocol
revisions up to 2025-11-25, FastMCP class) and mcp 2.x (the stateless
2026-07-28 revision, MCPServer class). All tools here are stateless
request/response functions, and session vouchers are explicit signed
handles the client passes back in, which is exactly the state model the
2026-07-28 revision prescribes.

Relationship to ``vouch.autosign``:

    ``autosign`` is the in-process, Python-native path: it wraps a tool so
    every call is signed deterministically, before the tool body runs, with
    no LLM cooperation. This MCP server is the out-of-process, cross-language
    path: any MCP client calls ``sign`` / ``verify`` over
    the wire, and the private key stays in this server's process, never in
    the model's context. Both share one signing primitive: ``sign_intent``.

Tools:
    sign        Issue a credential authorizing one action (PQC optional).
    verify  Verify a credential someone else presented.
    create_session     Issue a trust-decaying session voucher (Heartbeat).
    check_revocation   Check a credential's BitstringStatusList entry.
    get_identity       Return this agent's DID.
    evaluate_freshness Bounded-staleness revocation gate for offline/DTN use.
    verify_disconnected_edge  Authenticate a disconnected-edge (DTN) credential.

Run (stdio, for Claude Desktop / Cursor):
    VOUCH_PRIVATE_KEY=... VOUCH_DID=... vouch-mcp

Run (Streamable HTTP, for remote / hosted use):
    VOUCH_MCP_TRANSPORT=http VOUCH_MCP_HOST=0.0.0.0 VOUCH_MCP_PORT=8080 \
        VOUCH_PRIVATE_KEY=... VOUCH_DID=... vouch-mcp
"""

from __future__ import annotations

import json
import os
from typing import Optional

# The official MCP Python SDK renamed its high-level server class for the
# 2026-07-28 protocol revision: mcp>=2.0 ships ``mcp.server.MCPServer``
# (stateless core, no initialize handshake, server/discover), while mcp 1.x
# ships ``mcp.server.fastmcp.FastMCP``. The tool decorator API is identical,
# so we support both and let the installed SDK determine the protocol
# revisions spoken on the wire.
try:
    from mcp.server import MCPServer as _ServerClass  # mcp >= 2.0

    _MCP_SDK_V2 = True
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as _ServerClass  # mcp 1.x

        _MCP_SDK_V2 = False
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "The Vouch MCP server requires the MCP SDK. Install it with:\n"
            "    pip install 'vouch-protocol[mcp]'\n"
            "or\n"
            "    pip install mcp\n"
            f"(import error: {exc})"
        )

from vouch.autosign import resolve_signer, sign_intent


_HOST = os.getenv("VOUCH_MCP_HOST", "127.0.0.1")
_PORT = int(os.getenv("VOUCH_MCP_PORT", "8080"))

if _MCP_SDK_V2:
    # mcp>=2.0 takes host/port per transport at run() time, not here.
    mcp = _ServerClass("vouch")
else:
    mcp = _ServerClass("vouch", host=_HOST, port=_PORT)


@mcp.tool()
def sign(
    action: str,
    target: str,
    resource: Optional[str] = None,
    post_quantum: bool = False,
) -> str:
    """Issue a Vouch Credential authorizing a single sensitive action.

    Call this before any authenticated request to an external service. The
    returned credential binds this agent's identity to this exact action and
    resource, so a downstream service can confirm the call was authorized.

    Args:
        action: The verb, e.g. 'read', 'write', 'execute', 'send'.
        target: The service or URL being called.
        resource: The specific object, e.g. 'customer:123'. Defaults to target.
        post_quantum: If true, sign under the hybrid post-quantum profile
            (hybrid-eddsa-mldsa44-jcs-2026) for regulated deployments.
            Requires the server to have 'vouch-protocol[pq]' installed.

    Returns:
        A compact JSON Vouch Credential to attach as a 'Vouch-Credential' header.
    """
    signer = resolve_signer()
    if signer is None:
        return (
            "Error: no Vouch identity configured. Set VOUCH_PRIVATE_KEY and "
            "VOUCH_DID, or run 'vouch init'."
        )
    resolved_resource = resource or target
    try:
        if post_quantum:
            credential = signer.sign_hybrid(
                {"action": action, "target": target, "resource": resolved_resource}
            )
        else:
            credential = sign_intent(
                action,
                target=target,
                resource=resolved_resource,
                signer=signer,
                publish=False,
            )
        return json.dumps(credential, separators=(",", ":"))
    except Exception as e:
        return f"Error issuing Vouch Credential: {e}"


@mcp.tool()
def verify(credential_json: str, public_key: Optional[str] = None) -> str:
    """Verify a Vouch Credential that another agent or service presented.

    This is the receiving side: given a credential (the JSON another party's
    sign produced), confirm the signature, validity window, and intent
    binding. Any MCP client can call this without installing an SDK.

    Args:
        credential_json: The credential as a JSON string.
        public_key: Optional Multikey public key of the issuer. If omitted,
            the issuer's DID is resolved to fetch its key.

    Returns:
        A human-readable verdict: the issuer DID and authorized intent when
        valid, or a rejection reason.
    """
    from vouch import Verifier

    try:
        credential = json.loads(credential_json)
    except json.JSONDecodeError as e:
        return f"REJECTED: not valid JSON ({e})"

    try:
        is_valid, passport = Verifier.verify(credential, public_key=public_key)
    except Exception as e:
        return f"REJECTED: verification error ({e})"

    if not is_valid or passport is None:
        return "REJECTED: signature, validity window, or schema check failed."

    intent = getattr(passport, "intent", {}) or {}
    issuer = getattr(passport, "iss", None) or getattr(passport, "sub", "(unknown)")
    return (
        "VERIFIED\n"
        f"  issuer:   {issuer}\n"
        f"  action:   {intent.get('action')}\n"
        f"  target:   {intent.get('target')}\n"
        f"  resource: {intent.get('resource')}"
    )


@mcp.tool()
def create_session(
    purpose: str,
    valid_seconds: int = 3600,
    decay_lambda: float = 0.0005,
    initial_trust: float = 1.0,
) -> str:
    """Issue a trust-decaying session voucher (Heartbeat Protocol).

    Unlike a plain long-lived credential, a session voucher carries a trust
    value that decays over time (Trust Entropy). A verifier recomputes the
    current trust with compute_trust_at and can refuse a high-stakes action
    once trust falls below a threshold, unless the session is refreshed.

    Args:
        purpose: What the session is for, e.g. 'calendar_access'.
        valid_seconds: Voucher lifetime in seconds (default 3600).
        decay_lambda: Trust decay rate per second (default 0.0005).
        initial_trust: Starting trust in [0, 1] (default 1.0).

    Returns:
        A compact JSON session voucher with an eddsa-jcs-2022 proof.
    """
    signer = resolve_signer()
    if signer is None:
        return (
            "Error: no Vouch identity configured. Set VOUCH_PRIVATE_KEY and "
            "VOUCH_DID, or run 'vouch init'."
        )
    try:
        from vouch import data_integrity
        from vouch.vc import build_session_voucher

        voucher = build_session_voucher(
            subject_did=signer.did,
            validator_dids=[signer.did],
            decay_lambda=decay_lambda,
            initial_trust=initial_trust,
            max_ttl_seconds=valid_seconds,
            scope=[purpose],
            valid_seconds=valid_seconds,
        )
        proof = data_integrity.build_proof(
            voucher,
            private_key=signer._raw_priv,
            verification_method=signer.verification_method_id(),
        )
        voucher["proof"] = proof
        return json.dumps(voucher, separators=(",", ":"))
    except Exception as e:
        return f"Error creating session: {e}"


@mcp.tool()
def check_revocation(credential_json: str) -> str:
    """Check whether a credential has been revoked via its status list.

    Reads the credential's BitstringStatusList entry (credentialStatus),
    fetches the referenced status list, and reports whether the bit is set.

    Args:
        credential_json: The credential as a JSON string.

    Returns:
        'ACTIVE', 'REVOKED', or a note that the credential is not individually
        revocable (no credentialStatus attached).
    """
    try:
        credential = json.loads(credential_json)
    except json.JSONDecodeError as e:
        return f"Error: not valid JSON ({e})"

    status = credential.get("credentialStatus")
    if not status:
        return "NOT REVOCABLE: credential has no credentialStatus entry."

    try:
        from vouch import StatusListFetcher, verify_status

        fetcher = StatusListFetcher(cache_ttl_seconds=300)
        status_credential = fetcher.get(status["statusListCredential"])
        revoked = verify_status(
            credential_status=status,
            status_list_credential=status_credential,
        )
        return "REVOKED" if revoked else "ACTIVE"
    except Exception as e:
        return f"Error checking revocation: {e}"


@mcp.tool()
def get_identity() -> str:
    """Return this agent's DID (Decentralized Identifier)."""
    signer = resolve_signer()
    if signer is None:
        return "No Vouch identity configured. Set VOUCH_DID or run 'vouch init'."
    return f"Agent DID: {signer.did}"


# Disconnected-edge / DTN trust surface (PAD-106 to PAD-124). These let an MCP
# client make offline-first trust decisions: the bounded-staleness revocation gate,
# and authenticity checks for the disconnected-edge credential types.

_DISCONNECTED_EDGE_TYPES = {
    "FreshnessToken",
    "ChannelGeometryPresenceAttestation",
    "EphemerisScopedGrantCredential",
    "RangeObservationCredential",
    "ProofOfLocationCredential",
    "BeamPresenceAttestation",
    "ConditionalRevocationCredential",
    "RevocationAccumulatorRoot",
    "ValiditySetRootCredential",
    "DistressAttestation",
    "TrustStateUpdate",
    "KeyContinuityPredelegation",
    "ContinuityApproval",
    "TimeQualityAttestation",
    "AutonomyDecaySchedule",
    "IntegrityRiskAttestation",
    "SharedPerceptionClaim",
    "InteractionAttestation",
    "BundleTrustCredential",
    "BundleCustodyTransfer",
}


@mcp.tool()
def evaluate_freshness(
    tier: str = "critical",
    snapshot_json: Optional[str] = None,
    now_iso: Optional[str] = None,
) -> str:
    """Decide if a revocation snapshot is fresh enough for a disconnected action.

    Bounded-staleness revocation gate (PAD-106) for delay-tolerant / offline use:
    a verifier that cannot fetch a live status list weighs the age of the snapshot
    it holds against the consequence of the action, and fails closed when the view
    is too old. A routine beacon tolerates a 30-day-old snapshot; a critical
    maneuver does not (1-hour default budget).

    Args:
        tier: Consequence tier: 'routine', 'sensitive', or 'critical' (default).
            An unknown tier is treated as 'critical' (fail-closed).
        snapshot_json: The last-synced BitstringStatusListCredential as a JSON
            string, or omitted if no snapshot is held (allows only 'routine').
        now_iso: The verifier's clock as 'YYYY-MM-DDTHH:MM:SSZ'. Defaults to now.

    Returns:
        'ALLOW' or 'DENY' with the reason (snapshot age vs. the tier budget).
    """
    from datetime import datetime, timezone

    from vouch.status_list import evaluate_freshness as _eval

    snapshot = None
    if snapshot_json:
        try:
            snapshot = json.loads(snapshot_json)
        except json.JSONDecodeError as e:
            return f"Error: snapshot_json is not valid JSON ({e})"

    now = None
    if now_iso:
        try:
            now = datetime.strptime(now_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError as e:
            return f"Error: now_iso must be 'YYYY-MM-DDTHH:MM:SSZ' ({e})"

    verdict = _eval(tier=tier, snapshot=snapshot, now=now)
    mark = "ALLOW" if verdict.allow else "DENY"
    return f"{mark} (tier={verdict.tier}): {verdict.reason}"


@mcp.tool()
def verify_disconnected_edge(credential_json: str, public_key: str) -> str:
    """Authenticate a disconnected-edge (DTN) credential's signature.

    Verifies the eddsa-jcs-2022 proof of any disconnected-edge credential type
    (PAD-106 to PAD-124): freshness tokens, channel-geometry presence,
    ephemeris-scoped grants, dead-man and accumulator revocation, distress and
    trust-state updates, time-quality, autonomy schedules, integrity risk,
    perception claims, DTN bundle custody, and more. This confirms authenticity
    and returns the credential's type and subject; the geometry, epoch-gap, region,
    and staleness *predicates* are applied by the holder with its own local state
    (position, epoch, clock), so they are not evaluated here.

    Args:
        credential_json: The disconnected-edge credential as a JSON string.
        public_key: The issuer's Ed25519 public key (Multikey or JWK).

    Returns:
        'VERIFIED' with the credential type and subject, or a rejection reason.
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    try:
        credential = json.loads(credential_json)
    except json.JSONDecodeError as e:
        return f"REJECTED: not valid JSON ({e})"

    type_field = credential.get("type") or []
    types = [type_field] if isinstance(type_field, str) else list(type_field)
    edge_type = next((t for t in types if t in _DISCONNECTED_EDGE_TYPES), None)
    if edge_type is None:
        return (
            "REJECTED: not a disconnected-edge credential type. Use 'verify' for "
            "general Vouch credentials."
        )

    try:
        key = _coerce_ed25519_public_key(public_key)
        if key is None or not data_integrity.verify_proof(credential, key):
            return "REJECTED: signature or proof check failed."
    except Exception as e:
        return f"REJECTED: verification error ({e})"

    subject = credential.get("credentialSubject", {})
    return (
        "VERIFIED\n"
        f"  type:    {edge_type}\n"
        f"  issuer:  {credential.get('issuer', '(unknown)')}\n"
        f"  subject: {json.dumps(subject, separators=(',', ':'))}\n"
        "  note:    authenticity only; apply freshness/geometry/region predicates "
        "with your local state."
    )


def main() -> None:
    """Entry point. Transport is selected by VOUCH_MCP_TRANSPORT.

    - 'stdio' (default): for local clients like Claude Desktop and Cursor.
    - 'http' / 'streamable-http': for remote / hosted deployments.
    - 'sse': the HTTP+SSE transport, deprecated by the MCP specification;
      kept for existing clients during the deprecation window. Use
      Streamable HTTP for anything new.
    """
    transport = os.getenv("VOUCH_MCP_TRANSPORT", "stdio").lower().replace("_", "-")
    if transport in ("http", "streamable-http"):
        if _MCP_SDK_V2:
            mcp.run(transport="streamable-http", host=_HOST, port=_PORT)
        else:
            mcp.run(transport="streamable-http")
    elif transport == "sse":
        if _MCP_SDK_V2:
            mcp.run(transport="sse", host=_HOST, port=_PORT)
        else:
            mcp.run(transport="sse")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
