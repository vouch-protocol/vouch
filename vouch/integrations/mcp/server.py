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
    scan               Scan text for leaked private keys and key material.
    decode_did         Decode a DID key / Multikey and report its algorithm.
    delegate           Issue a narrowed sub-delegation grant to another agent.
    check_action       Decide if an agent's capabilities permit a tool (Shield).
    check_trust        Recompute a session voucher's decayed trust vs a threshold.
    disclose_ai_origin Sign a disclosure that content is AI-generated.
    reputation         Compute an agent's reputation score from its outcomes.
    attribute          Attribute authorship from a signed attribution manifest.

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


# Key-hygiene and DID tools. These back the two capabilities README.md
# advertises out of the box ("scan for leaked keys" and "decode DIDs") but the
# server did not previously expose.


@mcp.tool()
def scan(text: str) -> str:
    """Scan text for leaked Vouch private keys and other key material.

    Run this over anything about to leave a trust boundary -- a diff, a log
    line, a chat message, a file the agent is about to paste or commit -- to
    catch an Ed25519 private JWK, a private multibase key, a hybrid
    post-quantum secret, a seed env var, or a DID document that embeds a
    private key, before it is exposed.

    Args:
        text: The text to scan (source, config, log output, message body).

    Returns:
        'CLEAN' when nothing sensitive is found, or a list of findings with
        their kind, severity, line, and remediation.
    """
    from vouch.scan import scan_text

    try:
        findings = scan_text(text)
    except Exception as e:
        return f"Error scanning: {e}"

    if not findings:
        return "CLEAN: no leaked key material detected."

    lines = [f"LEAK RISK: {len(findings)} finding(s)."]
    for f in findings:
        lines.append(
            f"  [{f.severity.name}] {f.kind.name} at line {f.line}: "
            f"{f.description} -- {f.remediation}"
        )
    return "\n".join(lines)


@mcp.tool()
def decode_did(key: str) -> str:
    """Decode a DID key or Multikey and report its algorithm.

    Accepts a ``did:key:z...`` identifier or a bare ``z...`` Multikey and
    reports the key algorithm and raw public-key size. Use it to inspect an
    identifier before trusting it -- for example to confirm a peer's key is an
    Ed25519 (``ed25519-pub``) key and not an unexpected algorithm.

    Args:
        key: A ``did:key:z...`` DID or a bare ``z...`` Multikey string.

    Returns:
        The decoded algorithm and public-key length, or a rejection reason.
    """
    from vouch.multikey import decode

    multikey = key.strip()
    if multikey.startswith("did:key:"):
        multikey = multikey[len("did:key:") :]
    # did:key can carry a fragment (did:key:z...#z...); the identifier is the
    # part before the fragment.
    multikey = multikey.split("#", 1)[0]

    try:
        algorithm, raw = decode(multikey)
    except Exception as e:
        return f"REJECTED: not a valid Multikey ({e})"

    return (
        "DECODED\n"
        f"  algorithm: {algorithm}\n"
        f"  key bytes: {len(raw)}\n"
        f"  multikey:  {multikey[:16]}...{multikey[-6:]}"
    )


# Authority tools: narrowed sub-delegation and the capability/permission gate.


@mcp.tool()
def delegate(
    action: str,
    target: str,
    resource: str,
    to: Optional[str] = None,
    valid_seconds: Optional[int] = None,
    reputation_score: Optional[int] = None,
) -> str:
    """Issue a narrowed delegation grant to another agent.

    The principal (this server's identity) authorizes ``action`` on
    ``target``/``resource`` and hands the grant to a sub-agent. Every action the
    sub-agent signs is chained under this grant and can only *narrow* the
    authority, never widen it (Specification 9.3). Use this to give a worker
    agent exactly one scoped capability with an optional expiry.

    Args:
        action: The verb being delegated, e.g. 'charge', 'read', 'send'.
        target: The service or URL the grant applies to.
        resource: The specific object the grant is scoped to.
        to: Optional DID of the intended sub-agent (audience binding).
        valid_seconds: Optional lifetime of the grant in seconds.
        reputation_score: Optional minimum reputation the sub-agent must carry.

    Returns:
        A compact JSON delegation grant to pass to the sub-agent as its parent.
    """
    signer = resolve_signer()
    if signer is None:
        return (
            "Error: no Vouch identity configured. Set VOUCH_PRIVATE_KEY and "
            "VOUCH_DID, or run 'vouch init'."
        )
    try:
        from vouch import delegate as _delegate

        grant = _delegate(
            action=action,
            target=target,
            resource=resource,
            to=to,
            signer=signer,
            valid_seconds=valid_seconds,
            reputation_score=reputation_score,
        )
        if grant is None:
            return "Error: delegation could not be issued."
        return json.dumps(grant, separators=(",", ":"))
    except Exception as e:
        return f"Error issuing delegation: {e}"


@mcp.tool()
def check_action(
    tool: str,
    capabilities_json: str,
    requirements_json: str,
) -> str:
    """Decide whether an agent's capabilities permit a tool call (Shield).

    A pure authorization check: given the capability grant an agent holds and
    the requirements a tool demands, decide whether the call is allowed. This is
    the gate Vouch Shield applies before a tool runs -- filesystem, network, and
    shell levels must each meet or exceed what the tool requires.

    Args:
        tool: The tool name being gated, e.g. 'write_file'.
        capabilities_json: The agent's capabilities as JSON, e.g.
            '{"filesystem":"read","network":"outbound","shell":"none"}'.
        requirements_json: What the tool requires, same shape, e.g.
            '{"filesystem":"write"}'.

    Returns:
        'ALLOW' or 'DENY' with the reason (which requirement was not met).
    """
    from vouch.shield.permissions import Capabilities, PermissionManager

    try:
        caps = Capabilities.from_dict(json.loads(capabilities_json))
    except Exception as e:
        return f"Error: capabilities_json invalid ({e})"
    try:
        requirements = json.loads(requirements_json)
    except json.JSONDecodeError as e:
        return f"Error: requirements_json is not valid JSON ({e})"

    try:
        manager = PermissionManager()
        manager.register_tool(tool, requirements)
        did = "did:vouch:subject"
        manager.set_capabilities(did, caps)
        allowed, reason = manager.check_permission(did, tool)
    except Exception as e:
        return f"Error checking action: {e}"

    if allowed:
        return f"ALLOW: '{tool}' is permitted by the agent's capabilities."
    return f"DENY: {reason}"


# Trust-over-time and transparency tools.


@mcp.tool()
def check_trust(
    voucher_json: str,
    threshold: float = 0.5,
    now_iso: Optional[str] = None,
) -> str:
    """Recompute a session voucher's live trust and compare it to a threshold.

    A session voucher's trust decays over time (Trust Entropy). Before honoring
    a high-stakes action, recompute the *current* trust and refuse if it has
    fallen below the threshold you require -- unless the session is refreshed.
    Pair this with create_session, which issues the voucher.

    Args:
        voucher_json: The session voucher (from create_session) as a JSON string.
        threshold: Minimum trust in [0, 1] the action requires (default 0.5).
        now_iso: The verifier's clock as 'YYYY-MM-DDTHH:MM:SSZ'. Defaults to now.

    Returns:
        'ALLOW' or 'DENY' with the current trust, threshold, and elapsed age.
    """
    from datetime import datetime, timezone

    from vouch.trust_entropy import evaluate_trust

    try:
        voucher = json.loads(voucher_json)
    except json.JSONDecodeError as e:
        return f"Error: voucher_json is not valid JSON ({e})"

    at_time = None
    if now_iso:
        try:
            at_time = datetime.strptime(now_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError as e:
            return f"Error: now_iso must be 'YYYY-MM-DDTHH:MM:SSZ' ({e})"

    try:
        result = evaluate_trust(voucher, threshold=threshold, at_time=at_time)
    except Exception as e:
        return f"Error evaluating trust: {e}"

    mark = "ALLOW" if result.passed else "DENY"
    return (
        f"{mark}\n"
        f"  trust:     {result.trust:.4f}\n"
        f"  threshold: {result.threshold}\n"
        f"  elapsed:   {result.elapsed_seconds:.0f}s"
    )


@mcp.tool()
def disclose_ai_origin(content_hash: str, content_ref: Optional[str] = None) -> str:
    """Sign a disclosure that a piece of content is AI-generated.

    Issues a Vouch Credential attesting that this agent produced the content
    identified by ``content_hash``. Attach it alongside generated text, images,
    or code so any downstream party can verify the AI-origin claim
    cryptographically rather than trusting an unsigned label.

    Args:
        content_hash: A content digest, e.g. 'sha256:ab12...'.
        content_ref: Optional locator for the content (URL or path). Defaults to
            the generic label 'ai-generated-content'.

    Returns:
        A compact JSON Vouch Credential disclosing AI origin.
    """
    signer = resolve_signer()
    if signer is None:
        return (
            "Error: no Vouch identity configured. Set VOUCH_PRIVATE_KEY and "
            "VOUCH_DID, or run 'vouch init'."
        )
    try:
        credential = sign_intent(
            "disclose",
            target=content_ref or "ai-generated-content",
            resource=content_hash,
            signer=signer,
            publish=False,
        )
        return json.dumps(credential, separators=(",", ":"))
    except Exception as e:
        return f"Error signing disclosure: {e}"


# Accountability tools: reputation scoring and post-hoc attribution.


@mcp.tool()
async def reputation(did: str, events_json: str) -> str:
    """Compute an agent's reputation score from a history of outcomes.

    Replays a sequence of recorded outcomes for ``did`` and returns the current
    reputation score and success rate. Use it to weigh how much to trust a peer
    agent that has a track record, or to gate a sensitive action on a minimum
    standing.

    Args:
        did: The DID whose reputation to compute.
        events_json: A JSON array of events, each
            '{"outcome":"success"|"failure","reason":"..."}', or a
            '{"boost"|"slash": <amount>, "reason":"..."}' adjustment.

    Returns:
        The computed score, total actions, and success rate.
    """
    try:
        events = json.loads(events_json)
    except json.JSONDecodeError as e:
        return f"Error: events_json is not valid JSON ({e})"
    if not isinstance(events, list):
        return "Error: events_json must be a JSON array."

    try:
        from vouch.reputation import MemoryReputationStore, ReputationEngine

        engine = ReputationEngine(store=MemoryReputationStore())
        for event in events:
            reason = event.get("reason", "")
            if "boost" in event:
                await engine.boost(did, int(event["boost"]), reason or "boost")
            elif "slash" in event:
                await engine.slash(did, int(event["slash"]), reason or "slash")
            elif event.get("outcome") == "failure":
                await engine.record_failure(did, reason or "Action failed")
            else:
                await engine.record_success(did, reason or "Action completed")
        score = await engine.get_score(did)
    except Exception as e:
        return f"Error computing reputation: {e}"

    return (
        "REPUTATION\n"
        f"  did:           {score.did}\n"
        f"  score:         {score.score}\n"
        f"  total actions: {score.total_actions}\n"
        f"  success rate:  {score.success_rate:.2%}"
    )


@mcp.tool()
def attribute(manifest_json: str, path: Optional[str] = None) -> str:
    """Attribute authorship from a signed attribution manifest.

    Given an attribution manifest (which records, per file, what a human wrote
    versus what an AI agent generated), summarize the human/AI/pre-existing
    split across the whole manifest, or -- when ``path`` is given -- report the
    per-region authorship of that one file.

    Args:
        manifest_json: The attribution manifest as a JSON string.
        path: Optional file path to blame; omit for a whole-manifest summary.

    Returns:
        A per-file blame breakdown, or a manifest-wide authorship summary.
    """
    from vouch.attribution import blame, summarize

    try:
        manifest = json.loads(manifest_json)
    except json.JSONDecodeError as e:
        return f"Error: manifest_json is not valid JSON ({e})"

    try:
        if path:
            regions = blame(manifest, path)
            if not regions:
                return f"No attribution recorded for '{path}'."
            lines = [f"BLAME {path}:"]
            for r in regions:
                lines.append(f"  {json.dumps(r, separators=(',', ':'))}")
            return "\n".join(lines)
        summary = summarize(manifest)
        return "SUMMARY\n" + json.dumps(summary, indent=2)
    except Exception as e:
        return f"Error attributing: {e}"


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
