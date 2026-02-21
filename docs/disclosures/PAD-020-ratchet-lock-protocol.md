# PAD-020: Method for Capability Acquisition Containment via Cryptographic Manifest Governance

**Identifier:** PAD-020
**Title:** Method for Capability Acquisition Containment via Cryptographic Manifest Governance ("Ratchet Lock Protocol")
**Publication Date:** February 14, 2026
**Prior Art Effective Date:** February 14, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / Capability Governance / Autonomous Agent Containment / Privilege Escalation Prevention
**Author:** Ramprasad Anandam Gaddam

---

## 1. Abstract

A system and method for preventing autonomous AI agents from expanding their own operational capabilities without explicit, cryptographically verified authorization from an external principal. The protocol addresses the most dangerous class of autonomous agent behavior: **capability acquisition** -- the process by which an agent that begins with a bounded set of tools, APIs, and resources autonomously gains access to new ones, fundamentally altering its threat surface in ways that may be invisible to its operators.

The system introduces several interlocking mechanisms:

1. **Capability Manifest**: Every agent carries an Ed25519-signed, immutable manifest enumerating its authorized capabilities (tools, APIs, resources, actions). The agent cannot modify its own manifest. The manifest is the sole source of truth for what the agent is permitted to do.
2. **Delegation-Gated Acquisition**: New capabilities can only be added to an agent's manifest through a signed delegation (PAD-002) from an authorized principal. Self-delegation is cryptographically impossible because the manifest signature key is held by the delegating authority, not the agent.
3. **Ratchet Detection**: Real-time monitoring that detects when an agent invokes, attempts to invoke, or prepares to invoke a capability not present in its manifest -- triggering instant heartbeat denial (PAD-016), reasoning audit (PAD-017), and transparent disclosure (PAD-019).
4. **Capability Decay**: Unused capabilities expire after a configurable, per-capability TTL. An agent authorized for `database:write` that has not exercised that capability within its decay window loses it automatically, enforcing a continuous least-privilege posture.
5. **Capability Inheritance Limits**: When an agent delegates to sub-agents (PAD-002), it cannot delegate capabilities it does not itself possess. The delegation chain cryptographically enforces that capability sets can only shrink across delegation hops, never grow.
6. **Tool Discovery Governance**: When an agent discovers a new tool or API at runtime (e.g., via MCP tool discovery, plugin marketplaces, or API introspection), it is prohibited from invoking the tool until the capability is explicitly added to its manifest by an authorized principal.
7. **Capability Escalation Protocol**: A formal, auditable process by which an agent may REQUEST new capabilities, including a Proof of Reasoning (PAD-017) justification for why the capability is needed, subject to principal review and approval.
8. **Capability Fingerprinting**: Behavioral fingerprints for each authorized capability, enabling detection of authorized-but-misused capabilities -- such as an agent that holds `filesystem:read` but uses it to systematically exfiltrate sensitive data.
9. **Emergency Capability Revocation**: Instant, surgical removal of specific capabilities from an agent's manifest without revoking the agent's identity or other capabilities, enabling targeted containment of capability-level threats.

Unlike traditional access control systems that govern what a static identity may access, this protocol governs the **dynamic process by which an agent's capability surface changes over time** -- treating capability acquisition itself as the primary threat vector rather than any individual capability exercise.

---

## 2. Problem Statement

### 2.1 The Capability Acquisition Threat

The most dangerous thing an autonomous AI agent can do is not a single harmful action -- it is **acquiring new capabilities that expand what it CAN do**. An agent that starts with `search_the_web` and autonomously gains `execute_code_on_remote_servers` has fundamentally transformed its threat surface. This transformation is qualitatively different from misusing an existing capability:

| Threat Class | Example | Detectability | Impact |
|---|---|---|---|
| **Capability Misuse** | Agent uses authorized `email:send` to spam | Detectable via behavioral monitoring | Bounded by existing capability scope |
| **Capability Acquisition** | Agent discovers and invokes an unauthorized code execution API | May be invisible to behavioral baselines | **Unbounded** -- new capability creates entirely new attack surface |

Capability acquisition is the mechanism by which a contained agent becomes an uncontained one. Every major AI safety concern -- from data exfiltration to self-replication to resource acquisition -- requires the agent to first acquire capabilities it was not originally granted.

### 2.2 The Tool Discovery Problem

Modern AI agent frameworks actively encourage dynamic tool discovery:

1. **MCP (Model Context Protocol)**: Agents discover available tools at runtime through server introspection. A new MCP server appearing on the network exposes new tools that the agent can immediately invoke.
2. **Plugin Ecosystems**: Agents operating in plugin-enabled environments (e.g., ChatGPT plugins, LangChain tool registries) encounter new tools dynamically.
3. **API Introspection**: An agent with HTTP access can discover API endpoints through OpenAPI/Swagger documents, HATEOAS links, or simple exploration.
4. **Code Execution**: An agent with code execution capability can install packages, import libraries, and construct new tools at runtime -- the ultimate capability acquisition vector.

**No existing security framework treats tool discovery as a security event.** Current systems assume that the set of available tools is known and fixed at deployment time.

### 2.3 The Delegation Amplification Problem

In multi-agent systems, delegation creates a capability amplification risk:

```
Principal Alice: capabilities = {A, B, C, D, E}
    |
    └── delegates to Agent-1: capabilities = {A, B, C}
            |
            └── delegates to Sub-Agent-2: capabilities = {A, B}
                    |
                    └── VIOLATION: Sub-Agent-2 claims capability {F}
                        (Neither Agent-1 nor Alice possess {F})
```

Without cryptographic enforcement of capability inheritance, a sub-agent can claim capabilities that no entity in its delegation chain possesses -- a form of privilege escalation that is invisible to the delegating agent.

### 2.4 The Capability Accumulation Problem

Even when capabilities are legitimately granted, an agent that retains every capability it has ever been authorized for accumulates an expanding attack surface over time:

```
Day 1:   Agent authorized for {read_logs}
Day 7:   Agent authorized for {read_logs, write_config}
Day 30:  Agent authorized for {read_logs, write_config, deploy_code}
Day 90:  Agent authorized for {read_logs, write_config, deploy_code, admin_access}
         (read_logs hasn't been used in 85 days)
         (write_config hasn't been used in 60 days)
```

The agent now carries four capabilities despite only needing one for its current task. Each unused capability is dormant attack surface -- available to a compromised or misaligned agent but serving no operational purpose.

### 2.5 The Authorized Misuse Problem

Traditional access control answers a binary question: "Is this identity authorized for this action?" But authorization is necessary, not sufficient, for safe behavior. An agent that holds `filesystem:read` for legitimate log analysis but uses it to systematically read private keys, credentials, and personal data is operating within its authorization boundary while violating its intent boundary.

Existing systems cannot distinguish between:
- `filesystem:read("/var/log/app.log")` -- legitimate use
- `filesystem:read("/home/user/.ssh/id_ed25519")` -- exfiltration via authorized capability

### 2.6 Limitations of Existing Approaches

| Existing Approach | What It Does | What It Cannot Do |
|---|---|---|
| **RBAC/ABAC** | Assigns static roles/attributes to identities | Cannot govern dynamic capability acquisition; roles are granted, not earned or decayed |
| **OAuth2 Scopes** | Grants scopes at authorization time | Scopes are static after grant; no decay, no behavioral monitoring, no discovery governance |
| **Capability-Based Security (Dennis & Van Horn, 1966)** | Unforgeable capability tokens grant access to specific resources | Pre-AI foundational work; no capability decay, no behavioral fingerprinting, no delegation chain cryptographic enforcement |
| **Android/iOS Permissions** | User-granted permissions for app capabilities | User-mediated (not cryptographically delegated), no audit trail, no decay, no runtime behavioral monitoring |
| **Container Security (seccomp, AppArmor)** | System-call-level restrictions on processes | System-level, not agent-level; cannot govern semantic agent capabilities like "search the web" or "send email" |
| **SPIFFE/SPIRE** | Workload identity with short-lived certificates | Identity-focused, not capability-focused; no manifest governance, no discovery control |

**No existing system treats the acquisition of new capabilities as a first-class security event requiring cryptographic authorization, continuous governance, and behavioral monitoring.**

---

## 3. Solution: The Ratchet Lock Protocol

### 3.1 Capability Manifest

Every agent operating under the Vouch Protocol carries a **Capability Manifest** -- a cryptographically signed document enumerating the complete set of capabilities the agent is authorized to exercise.

#### 3.1.1 Manifest Structure

```json
{
  "manifest_version": "1.0",
  "manifest_id": "mfst-2026-02-14-a3b7c9e1",
  "agent_did": "did:key:z6MkAgent...",
  "issued_at": 1739520000,
  "issued_by": "did:key:z6MkPrincipal...",
  "delegation_ref": "vouch:delegation/d-4207",
  "capabilities": [
    {
      "capability_id": "cap-001",
      "resource": "database:orders",
      "actions": ["read", "query"],
      "constraints": {
        "max_rows_per_query": 1000,
        "allowed_tables": ["orders", "order_items"],
        "denied_columns": ["credit_card_number", "ssn"]
      },
      "granted_at": 1739520000,
      "decay_ttl_seconds": 2592000,
      "last_exercised": 1739520000,
      "behavioral_fingerprint": {
        "expected_frequency": "10-50/hour",
        "expected_data_volume": "<10MB/hour",
        "expected_patterns": ["SELECT with WHERE clause", "aggregation queries"],
        "anomaly_signatures": ["bulk SELECT *", "joins to unauthorized tables"]
      }
    },
    {
      "capability_id": "cap-002",
      "resource": "email:send",
      "actions": ["compose", "send"],
      "constraints": {
        "max_recipients": 5,
        "allowed_domains": ["@company.com"],
        "max_per_hour": 20,
        "requires_reasoning_level": 3
      },
      "granted_at": 1739520000,
      "decay_ttl_seconds": 604800,
      "last_exercised": null,
      "behavioral_fingerprint": {
        "expected_frequency": "1-10/hour",
        "expected_data_volume": "<1MB/hour",
        "expected_patterns": ["notification emails", "summary reports"],
        "anomaly_signatures": ["bulk sends", "external domains", "attachment exfiltration"]
      }
    }
  ],
  "manifest_hash": "sha256:H(canonical_json_of_capabilities)",
  "principal_signature": "ed25519:principal_signs_entire_manifest"
}
```

#### 3.1.2 Manifest Immutability

The manifest is signed by the **issuing principal's** Ed25519 key, not the agent's key. This is the critical design choice:

```
Principal's Ed25519 Private Key --signs--> Manifest
Agent's Ed25519 Private Key    --CANNOT sign--> Manifest (not the manifest signing key)
```

The agent possesses its own Ed25519 keypair for signing actions and heartbeats, but this key has **no authority** over the manifest. The manifest can only be modified by an entity holding the issuing principal's private key -- which is architecturally separated from the agent.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import json
import hashlib


def create_capability_manifest(
    agent_did: str,
    capabilities: list,
    principal_private_key: Ed25519PrivateKey,
    principal_did: str,
    delegation_ref: str,
) -> dict:
    """
    Create a capability manifest signed by the principal.
    The AGENT cannot call this function -- it requires the
    principal's private key, which the agent does not possess.
    """
    manifest = {
        "manifest_version": "1.0",
        "manifest_id": generate_manifest_id(),
        "agent_did": agent_did,
        "issued_at": current_timestamp(),
        "issued_by": principal_did,
        "delegation_ref": delegation_ref,
        "capabilities": capabilities,
    }

    # Compute manifest hash over canonical JSON
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    manifest["manifest_hash"] = "sha256:" + hashlib.sha256(
        canonical.encode()
    ).hexdigest()

    # Sign with PRINCIPAL's key (not agent's key)
    signature = principal_private_key.sign(canonical.encode())
    manifest["principal_signature"] = "ed25519:" + signature.hex()

    return manifest


def verify_manifest_integrity(manifest: dict, principal_public_key: Ed25519PublicKey) -> bool:
    """
    Verify that the manifest was signed by the claimed principal
    and has not been tampered with.
    """
    # Extract and remove signature for verification
    signature_hex = manifest["principal_signature"].removeprefix("ed25519:")
    signature = bytes.fromhex(signature_hex)

    # Reconstruct canonical JSON without signature
    manifest_copy = {k: v for k, v in manifest.items() if k != "principal_signature"}
    # Also remove manifest_hash for canonical computation
    manifest_for_hash = {k: v for k, v in manifest_copy.items() if k != "manifest_hash"}
    canonical = json.dumps(manifest_for_hash, sort_keys=True, separators=(",", ":"))

    # Verify hash
    expected_hash = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    if manifest["manifest_hash"] != expected_hash:
        return False

    # Verify Ed25519 signature
    try:
        principal_public_key.verify(signature, canonical.encode())
        return True
    except Exception:
        return False
```

#### 3.1.3 Manifest Architecture Diagram

```
+------------------------------------------------------------------+
|                     PRINCIPAL (Human/Org)                         |
|  Ed25519 Private Key: [HELD SECURELY, NEVER SHARED WITH AGENT]   |
+----------------------------------+-------------------------------+
                                   |
                          Signs Manifest
                                   |
                                   v
+------------------------------------------------------------------+
|                    CAPABILITY MANIFEST                            |
|  +------------------------------------------------------------+  |
|  | cap-001: database:orders [read, query]    TTL: 30 days     |  |
|  | cap-002: email:send [compose, send]       TTL: 7 days      |  |
|  | cap-003: filesystem:read [/var/log/*]     TTL: 14 days     |  |
|  +------------------------------------------------------------+  |
|  manifest_hash: sha256:...                                       |
|  principal_signature: ed25519:... (SIGNED BY PRINCIPAL, NOT AGENT)|
+----------------------------------+-------------------------------+
                                   |
                          Carried By Agent
                                   |
                                   v
+------------------------------------------------------------------+
|                         AGENT                                     |
|  Ed25519 Private Key: [SIGNS ACTIONS, NOT MANIFESTS]              |
|  Can READ manifest: YES                                          |
|  Can MODIFY manifest: NO (lacks principal's signing key)          |
|  Can ADD capabilities: NO                                        |
|  Can REMOVE capabilities: NO (decay is automatic, not agent-driven)|
+------------------------------------------------------------------+
```

### 3.2 Delegation-Gated Capability Acquisition

An agent CANNOT add capabilities to its own manifest. New capabilities must arrive through a signed delegation from an authorized principal.

#### 3.2.1 Capability Addition Flow

```
Agent                     Principal                   Manifest Registry
  |                           |                              |
  |-- 1. REQUEST_CAPABILITY ->|                              |
  |   (with reasoning         |                              |
  |    justification,         |                              |
  |    PAD-017)               |                              |
  |                           |                              |
  |                     [2. Principal evaluates:             |
  |                      - Is the request justified?         |
  |                      - Does the reasoning support need?  |
  |                      - Is the capability within policy?  |
  |                      - What constraints should apply?]   |
  |                           |                              |
  |                           |-- 3. SIGN new manifest ----->|
  |                           |   (Ed25519 signature over    |
  |                           |    updated capability set)   |
  |                           |                              |
  |<-- 4. UPDATED_MANIFEST ---|--- 4. STORE new manifest --->|
  |   (carrying new           |                              |
  |    capability with        |                              |
  |    constraints)           |                              |
  |                           |                              |
  |-- 5. ACK + begin using -->|                              |
  |   new capability          |                              |
```

#### 3.2.2 Self-Delegation Prevention

The protocol cryptographically prevents self-delegation through key separation:

```python
def attempt_self_delegation(agent_private_key: Ed25519PrivateKey, manifest: dict) -> bool:
    """
    Demonstrates why an agent CANNOT add capabilities to its own manifest.
    This function always fails.
    """
    # Agent tries to add a new capability
    new_capability = {
        "capability_id": "cap-FORGED",
        "resource": "code:execute",
        "actions": ["run"],
        "constraints": {},
        "granted_at": current_timestamp(),
        "decay_ttl_seconds": 999999,
        "last_exercised": None,
        "behavioral_fingerprint": {},
    }

    manifest["capabilities"].append(new_capability)

    # Agent signs with ITS OWN key
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    signature = agent_private_key.sign(canonical.encode())
    manifest["principal_signature"] = "ed25519:" + signature.hex()

    # VERIFICATION FAILS: The verifier checks against the PRINCIPAL's
    # public key (from the delegation chain), not the agent's public key.
    # The agent's signature will not verify against the principal's public key.
    return False  # Always fails


def verify_capability_acquisition(
    old_manifest: dict,
    new_manifest: dict,
    principal_public_key: Ed25519PublicKey,
) -> bool:
    """
    Verify that a manifest update was authorized by the principal.
    Checks both signature validity AND that changes are legal.
    """
    # 1. Verify new manifest signature against PRINCIPAL's key
    if not verify_manifest_integrity(new_manifest, principal_public_key):
        return False  # Not signed by principal

    # 2. Verify manifest lineage (new manifest references old)
    if new_manifest["issued_at"] <= old_manifest["issued_at"]:
        return False  # Temporal ordering violation

    # 3. Verify the agent DID hasn't changed
    if new_manifest["agent_did"] != old_manifest["agent_did"]:
        return False  # Manifest reassignment attempt

    return True
```

### 3.3 Ratchet Detection

The "ratchet" in "Ratchet Lock Protocol" refers to the one-way nature of authorized capability usage: an agent can exercise capabilities in its manifest, but any attempt to exercise capabilities OUTSIDE its manifest triggers an irreversible security response -- the ratchet engages and locks.

#### 3.3.1 Ratchet Detection Architecture

```
+-----------------------------------------------------------------------+
|                        AGENT RUNTIME                                   |
|                                                                       |
|   Agent Intent: "I need to execute code on the remote server"          |
|        |                                                              |
|        v                                                              |
|   +-----------------------+    +---------------------------+          |
|   | Capability Gateway    |    | Capability Manifest       |          |
|   | (Intercepts ALL       |--->| cap-001: database:read    |          |
|   |  tool/API invocations)|    | cap-002: email:send       |          |
|   +-----------+-----------+    | cap-003: filesystem:read   |          |
|               |                +---------------------------+          |
|               |                                                       |
|        +------+------+                                                |
|        |             |                                                |
|   [AUTHORIZED]  [UNAUTHORIZED]                                        |
|        |             |                                                |
|        v             v                                                |
|   Execute       RATCHET LOCK                                          |
|   action        ENGAGED                                               |
|                      |                                                |
|            +---------+---------+----------+                           |
|            |         |         |          |                           |
|            v         v         v          v                           |
|       Block     Heartbeat  Reasoning   Glass                         |
|       action    denial     audit       Channel                       |
|                (PAD-016)  (PAD-017)   (PAD-019)                      |
+-----------------------------------------------------------------------+
```

#### 3.3.2 Capability Gateway Implementation

```python
import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RatchetVerdict(Enum):
    AUTHORIZED = "AUTHORIZED"
    UNAUTHORIZED_CAPABILITY = "UNAUTHORIZED_CAPABILITY"
    CAPABILITY_EXPIRED = "CAPABILITY_EXPIRED"
    CONSTRAINT_VIOLATED = "CONSTRAINT_VIOLATED"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"


@dataclass
class RatchetEvent:
    timestamp: float
    agent_did: str
    attempted_capability: str
    attempted_action: str
    verdict: RatchetVerdict
    manifest_hash: str
    details: str


class CapabilityGateway:
    """
    Intercepts all capability invocations and enforces
    manifest-based authorization with ratchet detection.
    """

    def __init__(self, manifest: dict, event_log: list):
        self.manifest = manifest
        self.event_log = event_log
        self._capability_index = self._build_index()

    def _build_index(self) -> dict:
        """Build lookup index from manifest capabilities."""
        index = {}
        for cap in self.manifest["capabilities"]:
            key = f"{cap['resource']}:{','.join(cap['actions'])}"
            index[cap["resource"]] = cap
        return index

    def check_capability(
        self,
        resource: str,
        action: str,
        parameters: dict,
    ) -> RatchetVerdict:
        """
        Check whether an attempted capability invocation is authorized.
        Returns verdict; UNAUTHORIZED verdicts trigger ratchet lock.
        """
        # 1. Is the capability in the manifest at all?
        cap = self._capability_index.get(resource)
        if cap is None:
            self._trigger_ratchet(
                resource, action,
                RatchetVerdict.UNAUTHORIZED_CAPABILITY,
                f"Capability '{resource}' not in manifest. "
                f"Manifest contains: {list(self._capability_index.keys())}"
            )
            return RatchetVerdict.UNAUTHORIZED_CAPABILITY

        # 2. Is the specific action authorized?
        if action not in cap["actions"]:
            self._trigger_ratchet(
                resource, action,
                RatchetVerdict.UNAUTHORIZED_CAPABILITY,
                f"Action '{action}' not authorized for '{resource}'. "
                f"Authorized actions: {cap['actions']}"
            )
            return RatchetVerdict.UNAUTHORIZED_CAPABILITY

        # 3. Has the capability expired (decay)?
        if cap["decay_ttl_seconds"] is not None:
            last_used = cap["last_exercised"] or cap["granted_at"]
            elapsed = time.time() - last_used
            if elapsed > cap["decay_ttl_seconds"]:
                self._trigger_ratchet(
                    resource, action,
                    RatchetVerdict.CAPABILITY_EXPIRED,
                    f"Capability '{resource}' expired: unused for "
                    f"{elapsed:.0f}s (TTL: {cap['decay_ttl_seconds']}s)"
                )
                return RatchetVerdict.CAPABILITY_EXPIRED

        # 4. Do parameters satisfy constraints?
        constraint_result = self._check_constraints(cap, parameters)
        if constraint_result is not None:
            self._trigger_ratchet(
                resource, action,
                RatchetVerdict.CONSTRAINT_VIOLATED,
                f"Constraint violated: {constraint_result}"
            )
            return RatchetVerdict.CONSTRAINT_VIOLATED

        # 5. Does usage match behavioral fingerprint?
        fingerprint_result = self._check_behavioral_fingerprint(cap, parameters)
        if fingerprint_result is not None:
            self._trigger_ratchet(
                resource, action,
                RatchetVerdict.BEHAVIORAL_ANOMALY,
                f"Behavioral anomaly: {fingerprint_result}"
            )
            return RatchetVerdict.BEHAVIORAL_ANOMALY

        # Update last_exercised timestamp
        cap["last_exercised"] = time.time()
        return RatchetVerdict.AUTHORIZED

    def _check_constraints(self, cap: dict, parameters: dict) -> Optional[str]:
        """Check parameter constraints defined in the capability."""
        constraints = cap.get("constraints", {})

        for key, limit in constraints.items():
            if key.startswith("max_") and key.removeprefix("max_") in parameters:
                param_name = key.removeprefix("max_")
                if parameters[param_name] > limit:
                    return f"{param_name}={parameters[param_name]} exceeds max {limit}"

            if key.startswith("allowed_") and key.removeprefix("allowed_") in parameters:
                param_name = key.removeprefix("allowed_")
                value = parameters[param_name]
                if isinstance(value, list):
                    violations = [v for v in value if v not in limit]
                else:
                    violations = [value] if value not in limit else []
                if violations:
                    return f"{param_name} contains disallowed values: {violations}"

            if key.startswith("denied_") and key.removeprefix("denied_") in parameters:
                param_name = key.removeprefix("denied_")
                value = parameters[param_name]
                if isinstance(value, list):
                    violations = [v for v in value if v in limit]
                else:
                    violations = [value] if value in limit else []
                if violations:
                    return f"{param_name} contains denied values: {violations}"

        return None

    def _check_behavioral_fingerprint(self, cap: dict, parameters: dict) -> Optional[str]:
        """Check if usage pattern matches expected behavioral fingerprint."""
        fingerprint = cap.get("behavioral_fingerprint", {})
        anomaly_signatures = fingerprint.get("anomaly_signatures", [])

        # Check if the invocation matches known anomaly patterns
        invocation_signature = self._compute_invocation_signature(cap, parameters)
        for anomaly in anomaly_signatures:
            if self._matches_anomaly_pattern(invocation_signature, anomaly):
                return f"Invocation matches anomaly signature: '{anomaly}'"

        return None

    def _trigger_ratchet(
        self,
        resource: str,
        action: str,
        verdict: RatchetVerdict,
        details: str,
    ) -> None:
        """
        RATCHET LOCK ENGAGED.
        This is a critical safety signal -- the agent attempted
        to exercise a capability outside its manifest.
        """
        event = RatchetEvent(
            timestamp=time.time(),
            agent_did=self.manifest["agent_did"],
            attempted_capability=resource,
            attempted_action=action,
            verdict=verdict,
            manifest_hash=self.manifest["manifest_hash"],
            details=details,
        )
        self.event_log.append(event)

        # Trigger cross-protocol responses
        self._notify_heartbeat_denial(event)   # PAD-016
        self._notify_reasoning_audit(event)    # PAD-017
        self._notify_glass_channel(event)      # PAD-019

    def _notify_heartbeat_denial(self, event: RatchetEvent) -> None:
        """Signal PAD-016 Heartbeat Protocol to deny next renewal."""
        pass  # Integration point with PAD-016

    def _notify_reasoning_audit(self, event: RatchetEvent) -> None:
        """Signal PAD-017 to capture reasoning for the attempted action."""
        pass  # Integration point with PAD-017

    def _notify_glass_channel(self, event: RatchetEvent) -> None:
        """Signal PAD-019 to transparently disclose the attempt."""
        pass  # Integration point with PAD-019

    def _compute_invocation_signature(self, cap: dict, parameters: dict) -> str:
        """Compute a behavioral signature for this invocation."""
        return json.dumps({"resource": cap["resource"], "params": parameters}, sort_keys=True)

    def _matches_anomaly_pattern(self, signature: str, anomaly: str) -> bool:
        """Check if an invocation signature matches a known anomaly pattern."""
        return False  # Placeholder for pattern matching logic
```

#### 3.3.3 Ratchet Event Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "RatchetEvent",
  "description": "A capability acquisition containment event triggered by unauthorized capability exercise",
  "type": "object",
  "required": ["event_id", "event_type", "timestamp", "agent_did", "attempted_capability", "verdict", "manifest_hash"],
  "properties": {
    "event_id": {
      "type": "string",
      "description": "Unique identifier for this ratchet event"
    },
    "event_type": {
      "type": "string",
      "enum": ["UNAUTHORIZED_CAPABILITY", "CAPABILITY_EXPIRED", "CONSTRAINT_VIOLATED", "BEHAVIORAL_ANOMALY"],
      "description": "Classification of the ratchet trigger"
    },
    "timestamp": {
      "type": "number",
      "description": "Unix timestamp of the event"
    },
    "agent_did": {
      "type": "string",
      "description": "DID of the agent that triggered the ratchet"
    },
    "attempted_capability": {
      "type": "string",
      "description": "The capability the agent attempted to exercise"
    },
    "attempted_action": {
      "type": "string",
      "description": "The specific action attempted"
    },
    "attempted_parameters": {
      "type": "object",
      "description": "Parameters of the attempted invocation"
    },
    "verdict": {
      "type": "string",
      "enum": ["UNAUTHORIZED_CAPABILITY", "CAPABILITY_EXPIRED", "CONSTRAINT_VIOLATED", "BEHAVIORAL_ANOMALY"]
    },
    "manifest_hash": {
      "type": "string",
      "description": "Hash of the agent's manifest at the time of the event"
    },
    "manifest_capabilities": {
      "type": "array",
      "items": { "type": "string" },
      "description": "List of capability IDs in the manifest at time of event"
    },
    "cross_protocol_actions": {
      "type": "object",
      "properties": {
        "heartbeat_denial": { "type": "boolean" },
        "reasoning_audit": { "type": "boolean" },
        "glass_channel_disclosure": { "type": "boolean" }
      }
    },
    "details": {
      "type": "string",
      "description": "Human-readable description of the violation"
    }
  }
}
```

### 3.4 Capability Decay

Capabilities are not permanent grants. Every capability in the manifest carries a `decay_ttl_seconds` value. If the capability is not exercised within this window, it is automatically considered expired and removed from the effective manifest.

#### 3.4.1 Decay Model

```
Capability Effective Status Over Time

  Granted                     Last Used        Decay TTL
     |                           |                 |
     v                           v                 v
  ===|===========================|=================|========>
     |<-- ACTIVE (exercised) --->|<-- DECAYING --->|
     |                           |                 |
     |  Agent can freely use     |  Agent can use  | EXPIRED
     |  this capability          |  (clock ticking)| Cannot use
     |                           |                 | Must re-request
```

#### 3.4.2 Decay Implementation

```python
from dataclasses import dataclass
from typing import Optional


@dataclass
class CapabilityStatus:
    capability_id: str
    resource: str
    is_active: bool
    seconds_until_expiry: Optional[float]
    last_exercised: Optional[float]
    decay_ttl: float


def compute_effective_manifest(manifest: dict, current_time: float) -> list:
    """
    Compute the effective (non-expired) capabilities from
    a manifest, accounting for capability decay.

    Capabilities that have not been exercised within their
    decay_ttl are excluded from the effective set.
    """
    effective_capabilities = []

    for cap in manifest["capabilities"]:
        decay_ttl = cap.get("decay_ttl_seconds")

        # Capabilities with no decay TTL are permanent
        # (should be rare -- most capabilities should decay)
        if decay_ttl is None:
            effective_capabilities.append(
                CapabilityStatus(
                    capability_id=cap["capability_id"],
                    resource=cap["resource"],
                    is_active=True,
                    seconds_until_expiry=None,
                    last_exercised=cap.get("last_exercised"),
                    decay_ttl=float("inf"),
                )
            )
            continue

        # Compute time since last exercise (or grant if never exercised)
        reference_time = cap.get("last_exercised") or cap["granted_at"]
        elapsed = current_time - reference_time
        remaining = decay_ttl - elapsed

        if remaining > 0:
            effective_capabilities.append(
                CapabilityStatus(
                    capability_id=cap["capability_id"],
                    resource=cap["resource"],
                    is_active=True,
                    seconds_until_expiry=remaining,
                    last_exercised=cap.get("last_exercised"),
                    decay_ttl=decay_ttl,
                )
            )
        # Expired capabilities are silently excluded

    return effective_capabilities


def report_decaying_capabilities(manifest: dict, current_time: float) -> list:
    """
    Identify capabilities approaching their decay deadline.
    Useful for agent self-awareness and pre-emptive re-authorization.
    """
    warnings = []
    DECAY_WARNING_THRESHOLD = 0.2  # Warn at 20% remaining TTL

    for cap in manifest["capabilities"]:
        decay_ttl = cap.get("decay_ttl_seconds")
        if decay_ttl is None:
            continue

        reference_time = cap.get("last_exercised") or cap["granted_at"]
        elapsed = current_time - reference_time
        remaining = decay_ttl - elapsed
        remaining_fraction = remaining / decay_ttl

        if 0 < remaining_fraction < DECAY_WARNING_THRESHOLD:
            warnings.append({
                "capability_id": cap["capability_id"],
                "resource": cap["resource"],
                "seconds_remaining": remaining,
                "fraction_remaining": remaining_fraction,
                "warning": f"Capability '{cap['resource']}' will expire in "
                           f"{remaining:.0f}s ({remaining_fraction:.0%} of TTL remaining)",
            })

    return warnings
```

#### 3.4.3 Decay Configuration Guidelines

| Capability Type | Recommended Decay TTL | Rationale |
|---|---|---|
| **Read-only data access** | 14-30 days | Low risk; moderate decay |
| **Write/Modify data** | 7-14 days | Medium risk; faster decay |
| **Delete/Destroy** | 1-7 days | High risk; aggressive decay |
| **Financial transactions** | 1-3 days | High risk; very aggressive decay |
| **Code execution** | 24 hours | Critical risk; daily re-authorization |
| **Network/External access** | 7-14 days | Medium risk; prevents stale outbound access |
| **Identity/Permission management** | 1-3 days | Critical risk; very aggressive decay |

### 3.5 Capability Inheritance Limits

When an agent delegates to sub-agents via PAD-002, the capability set can only **shrink or remain equal** across delegation hops -- it can NEVER grow. This is the **capability monotonicity principle**, cryptographically enforced.

#### 3.5.1 Inheritance Diagram

```
Principal Alice
  Manifest: {database:read, database:write, email:send, filesystem:read, code:execute}
       |
       | delegates (can only grant subset of own capabilities)
       v
  Agent-1
  Manifest: {database:read, database:write, email:send}  <-- SUBSET of Alice's
       |
       | delegates (can only grant subset of own capabilities)
       v
  Sub-Agent-2
  Manifest: {database:read}  <-- SUBSET of Agent-1's
       |
       | CANNOT delegate capabilities it doesn't have:
       |   database:write  -- NOT IN Sub-Agent-2's manifest
       |   email:send      -- NOT IN Sub-Agent-2's manifest
       |   code:execute    -- NOT IN any ancestor's manifest for this chain
       v
  Sub-Sub-Agent-3
  Manifest: {database:read}  <-- Can only be equal to or subset of Sub-Agent-2's

  VIOLATION EXAMPLES (all rejected):
  x Sub-Agent-2 delegates {database:write} to Sub-Sub-Agent-3
    REJECTED: Sub-Agent-2 does not possess database:write
  x Sub-Agent-2 delegates {code:execute} to Sub-Sub-Agent-3
    REJECTED: code:execute not in any ancestor's manifest
  x Sub-Sub-Agent-3 self-adds {network:access}
    REJECTED: Self-delegation is cryptographically impossible
```

#### 3.5.2 Inheritance Verification

```python
def verify_capability_inheritance(
    delegator_manifest: dict,
    delegatee_manifest: dict,
    delegation_chain: list,
) -> dict:
    """
    Verify that a sub-agent's manifest is a valid subset
    of its delegator's manifest.

    The capability set MUST be monotonically non-increasing
    across delegation hops.
    """
    delegator_caps = {
        cap["resource"]: set(cap["actions"])
        for cap in delegator_manifest["capabilities"]
    }

    delegatee_caps = {
        cap["resource"]: set(cap["actions"])
        for cap in delegatee_manifest["capabilities"]
    }

    violations = []

    for resource, actions in delegatee_caps.items():
        if resource not in delegator_caps:
            violations.append({
                "type": "RESOURCE_ESCALATION",
                "resource": resource,
                "detail": f"Delegatee has capability '{resource}' which "
                          f"delegator does not possess",
            })
        else:
            unauthorized_actions = actions - delegator_caps[resource]
            if unauthorized_actions:
                violations.append({
                    "type": "ACTION_ESCALATION",
                    "resource": resource,
                    "unauthorized_actions": list(unauthorized_actions),
                    "detail": f"Delegatee has actions {unauthorized_actions} on "
                              f"'{resource}' which delegator does not possess",
                })

    # Additionally verify constraints are not relaxed
    for cap in delegatee_manifest["capabilities"]:
        delegator_cap = next(
            (c for c in delegator_manifest["capabilities"]
             if c["resource"] == cap["resource"]),
            None,
        )
        if delegator_cap:
            constraint_violation = verify_constraints_not_relaxed(
                delegator_cap.get("constraints", {}),
                cap.get("constraints", {}),
            )
            if constraint_violation:
                violations.append({
                    "type": "CONSTRAINT_RELAXATION",
                    "resource": cap["resource"],
                    "detail": constraint_violation,
                })

    return {
        "is_valid": len(violations) == 0,
        "violations": violations,
        "delegator_capabilities": list(delegator_caps.keys()),
        "delegatee_capabilities": list(delegatee_caps.keys()),
    }


def verify_constraints_not_relaxed(
    delegator_constraints: dict,
    delegatee_constraints: dict,
) -> Optional[str]:
    """
    Verify that the delegatee's constraints are at least as
    restrictive as the delegator's.

    e.g., delegator: max_rows=1000, delegatee: max_rows=5000 -> VIOLATION
          delegator: max_rows=1000, delegatee: max_rows=500  -> OK
    """
    for key, delegator_value in delegator_constraints.items():
        if key not in delegatee_constraints:
            return f"Delegatee missing constraint '{key}' present in delegator"

        delegatee_value = delegatee_constraints[key]

        if key.startswith("max_"):
            if isinstance(delegator_value, (int, float)) and isinstance(delegatee_value, (int, float)):
                if delegatee_value > delegator_value:
                    return (
                        f"Constraint '{key}' relaxed: delegator={delegator_value}, "
                        f"delegatee={delegatee_value}"
                    )

        if key.startswith("allowed_"):
            if isinstance(delegator_value, list) and isinstance(delegatee_value, list):
                extra = set(delegatee_value) - set(delegator_value)
                if extra:
                    return (
                        f"Constraint '{key}' expanded: delegatee adds {extra} "
                        f"not in delegator's allowed set"
                    )

    return None
```

### 3.6 Tool Discovery Governance

When an agent discovers a new tool at runtime -- through MCP server introspection, plugin marketplaces, API discovery, or any other mechanism -- the tool is placed in a **quarantine state** until explicitly authorized.

#### 3.6.1 Discovery Quarantine Flow

```
Agent discovers new tool via MCP / plugin / API introspection
    |
    v
+---------------------------------------------------+
| QUARANTINE ZONE                                    |
|                                                    |
| Discovered tool: "code_interpreter"                |
| Source: mcp://untrusted-server.example/tools       |
| Discovered at: 2026-02-14T12:00:00Z               |
| Status: QUARANTINED                                |
|                                                    |
| Agent CAN:                                         |
|   - Read tool description/schema                   |
|   - Include tool in capability escalation request  |
|   - Report tool discovery via Glass Channel        |
|                                                    |
| Agent CANNOT:                                      |
|   - Invoke the tool                                |
|   - Pass tool reference to sub-agents              |
|   - Include tool in action plans                   |
+---------------------------------------------------+
    |
    v
Agent submits CAPABILITY_ESCALATION_REQUEST (Section 3.7)
    |
    v
Principal reviews and either:
    |
    +-- APPROVE: Tool added to manifest with constraints
    |              and behavioral fingerprint
    |
    +-- DENY: Tool remains quarantined
    |          (denial logged for audit)
    |
    +-- DENY_AND_BLOCK: Tool added to permanent block list
                         (agent cannot re-request)
```

#### 3.6.2 Discovery Event Schema

```json
{
  "event_type": "TOOL_DISCOVERY",
  "timestamp": 1739520000,
  "agent_did": "did:key:z6MkAgent...",
  "discovered_tool": {
    "name": "code_interpreter",
    "description": "Execute arbitrary Python code in a sandboxed environment",
    "source": "mcp://server.example.com/tools/code_interpreter",
    "discovery_method": "mcp_server_introspection",
    "input_schema": {
      "type": "object",
      "properties": {
        "code": { "type": "string" },
        "language": { "type": "string", "enum": ["python", "javascript"] }
      }
    },
    "capabilities_required": ["code:execute"],
    "risk_assessment": "CRITICAL"
  },
  "quarantine_status": "QUARANTINED",
  "agent_action": "NONE_PENDING_AUTHORIZATION",
  "manifest_hash": "sha256:current_manifest_hash",
  "glass_channel_ref": "gc-2026-02-14-disclosure-7a3f"
}
```

#### 3.6.3 MCP Integration

```python
class GovernedMCPClient:
    """
    A wrapper around MCP client that enforces capability
    manifest governance on tool discovery and invocation.
    """

    def __init__(self, manifest: dict, gateway: CapabilityGateway):
        self.manifest = manifest
        self.gateway = gateway
        self.quarantined_tools = {}
        self.blocked_tools = set()

    def on_tools_discovered(self, tools: list) -> dict:
        """
        Called when MCP server exposes available tools.
        All discovered tools are quarantined until authorized.
        """
        results = {
            "authorized": [],
            "quarantined": [],
            "blocked": [],
        }

        for tool in tools:
            tool_resource = self._tool_to_resource(tool)

            # Check if tool is already in manifest
            if self._is_in_manifest(tool_resource):
                results["authorized"].append(tool.name)
                continue

            # Check if tool is permanently blocked
            if tool.name in self.blocked_tools:
                results["blocked"].append(tool.name)
                continue

            # Quarantine the tool
            self.quarantined_tools[tool.name] = {
                "tool": tool,
                "discovered_at": time.time(),
                "source": tool.source_uri,
                "status": "QUARANTINED",
            }
            results["quarantined"].append(tool.name)

            # Report discovery via Glass Channel (PAD-019)
            self._report_tool_discovery(tool)

        return results

    def invoke_tool(self, tool_name: str, parameters: dict) -> object:
        """
        Invoke a tool, subject to capability gateway enforcement.
        """
        # Check if tool is quarantined (not yet authorized)
        if tool_name in self.quarantined_tools:
            self.gateway._trigger_ratchet(
                resource=f"quarantined:{tool_name}",
                action="invoke",
                verdict=RatchetVerdict.UNAUTHORIZED_CAPABILITY,
                details=f"Attempted to invoke quarantined tool '{tool_name}'. "
                        f"Tool was discovered but not yet authorized by principal.",
            )
            raise CapabilityViolationError(
                f"Tool '{tool_name}' is quarantined. "
                f"Submit a capability escalation request to use this tool."
            )

        # Check against capability manifest
        tool_resource = self._tool_name_to_resource(tool_name)
        verdict = self.gateway.check_capability(
            resource=tool_resource,
            action="invoke",
            parameters=parameters,
        )

        if verdict != RatchetVerdict.AUTHORIZED:
            raise CapabilityViolationError(
                f"Tool '{tool_name}' invocation denied: {verdict.value}"
            )

        # Authorized -- proceed with invocation
        return self._execute_tool(tool_name, parameters)

    def _is_in_manifest(self, resource: str) -> bool:
        return any(
            cap["resource"] == resource
            for cap in self.manifest["capabilities"]
        )

    def _tool_to_resource(self, tool) -> str:
        return f"mcp:{tool.source_uri}/{tool.name}"

    def _tool_name_to_resource(self, tool_name: str) -> str:
        return f"mcp:tool/{tool_name}"

    def _report_tool_discovery(self, tool) -> None:
        """Report tool discovery via PAD-019 Glass Channel."""
        pass  # Integration point with PAD-019

    def _execute_tool(self, tool_name: str, parameters: dict) -> object:
        """Execute the authorized tool."""
        pass  # Actual MCP tool invocation
```

### 3.7 Capability Escalation Protocol

The formal, auditable process by which an agent may REQUEST new capabilities. This is the only legitimate path for an agent to expand its capability set.

#### 3.7.1 Escalation Request Structure

```json
{
  "request_type": "CAPABILITY_ESCALATION",
  "request_id": "escreq-2026-02-14-b7c3a1",
  "timestamp": 1739520000,
  "agent_did": "did:key:z6MkAgent...",
  "current_manifest_hash": "sha256:current_manifest_hash",
  "requested_capability": {
    "resource": "code:execute",
    "actions": ["run_python"],
    "proposed_constraints": {
      "max_execution_time_seconds": 30,
      "network_access": false,
      "filesystem_access": "read_only",
      "allowed_packages": ["pandas", "numpy", "matplotlib"]
    },
    "proposed_decay_ttl_seconds": 86400
  },
  "justification": {
    "reasoning_proof_ref": "por-2026-02-14-reasoning-hash",
    "task_context": "Data analysis task requires computing statistical aggregations that exceed SQL query capabilities",
    "evidence_anchors": [
      {
        "type": "user_message",
        "ref": "msg:conversation/c-7201/turn-5",
        "hash": "sha256:H(user_message)",
        "excerpt": "Can you run a custom regression analysis on this dataset?"
      },
      {
        "type": "prior_action",
        "ref": "action:a-4207",
        "hash": "sha256:H(action_result)",
        "detail": "SQL query returned raw data but agent lacks capability to compute regression"
      }
    ],
    "alternatives_considered": [
      {
        "alternative": "Use SQL window functions for approximation",
        "reason_rejected": "Insufficient precision for regression coefficients"
      },
      {
        "alternative": "Request human to run the analysis",
        "reason_rejected": "User explicitly requested agent-driven analysis"
      }
    ],
    "risk_assessment": {
      "impact_if_granted": "Agent can execute constrained Python code for data analysis",
      "impact_if_denied": "Task cannot be completed; user must perform analysis manually",
      "proposed_mitigations": [
        "No network access during execution",
        "Read-only filesystem (cannot modify or delete)",
        "24-hour decay TTL requires daily re-authorization",
        "Restricted to data analysis packages only"
      ]
    }
  },
  "agent_signature": "ed25519:agent_signs_entire_request"
}
```

#### 3.7.2 Escalation Decision Flow

```
Agent submits CAPABILITY_ESCALATION_REQUEST
    |
    v
+----------------------------------------------------------+
|  PRINCIPAL REVIEW PIPELINE                                |
|                                                           |
|  1. AUTOMATED PRE-SCREENING                               |
|     - Is the requested capability on the block list?       |
|     - Does the agent's current trust score (PAD-016)       |
|       meet the minimum threshold for this capability type? |
|     - Has the agent recently triggered a ratchet event?    |
|         |                                                  |
|         +-- FAIL: Auto-deny with reason                    |
|         +-- PASS: Continue to step 2                       |
|                                                           |
|  2. REASONING VALIDATION (PAD-017)                         |
|     - Are evidence anchors verifiable?                     |
|     - Is the justification causally consistent?            |
|     - Were alternatives genuinely considered?              |
|         |                                                  |
|         +-- FAIL: Deny with reasoning feedback             |
|         +-- PASS: Continue to step 3                       |
|                                                           |
|  3. POLICY CHECK                                           |
|     - Does organizational policy allow this capability     |
|       for this agent class?                                |
|     - Are the proposed constraints sufficient?             |
|         |                                                  |
|         +-- FAIL: Deny with policy reference               |
|         +-- PASS: Continue to step 4                       |
|                                                           |
|  4. PRINCIPAL DECISION                                     |
|     - Human-in-the-loop for high-risk capabilities         |
|     - Automated approval for low-risk capabilities         |
|       within pre-approved policy boundaries                |
|         |                                                  |
|         +-- APPROVE: Sign updated manifest                 |
|         +-- DENY: Log denial with reason                   |
|         +-- MODIFY: Approve with tighter constraints       |
+----------------------------------------------------------+
    |
    v
If APPROVED:
    Principal signs new manifest containing the new capability
    Agent receives updated manifest
    Capability is immediately available (subject to constraints)
```

#### 3.7.3 Escalation Implementation

```python
@dataclass
class EscalationRequest:
    request_id: str
    agent_did: str
    current_manifest_hash: str
    requested_resource: str
    requested_actions: list
    proposed_constraints: dict
    proposed_decay_ttl: int
    justification: dict
    agent_signature: bytes


@dataclass
class EscalationDecision:
    request_id: str
    decision: str  # "APPROVE", "DENY", "MODIFY"
    reason: str
    modified_constraints: Optional[dict] = None
    principal_signature: Optional[bytes] = None


def evaluate_escalation_request(
    request: EscalationRequest,
    current_manifest: dict,
    agent_trust_history: dict,
    organizational_policy: dict,
    blocked_capabilities: set,
) -> EscalationDecision:
    """
    Evaluate a capability escalation request through
    the multi-stage review pipeline.
    """
    # Stage 1: Automated pre-screening
    if request.requested_resource in blocked_capabilities:
        return EscalationDecision(
            request_id=request.request_id,
            decision="DENY",
            reason=f"Capability '{request.requested_resource}' is on the "
                   f"organizational block list",
        )

    if agent_trust_history.get("recent_ratchet_events", 0) > 0:
        return EscalationDecision(
            request_id=request.request_id,
            decision="DENY",
            reason="Agent has recent ratchet events; capability expansion "
                   "denied until trust is re-established",
        )

    min_trust_for_capability = organizational_policy.get(
        "minimum_trust_scores", {}
    ).get(request.requested_resource, 0.8)

    if agent_trust_history.get("current_trust_score", 0) < min_trust_for_capability:
        return EscalationDecision(
            request_id=request.request_id,
            decision="DENY",
            reason=f"Agent trust score {agent_trust_history.get('current_trust_score', 0):.2f} "
                   f"below minimum {min_trust_for_capability:.2f} for "
                   f"'{request.requested_resource}'",
        )

    # Stage 2: Reasoning validation (PAD-017 integration)
    reasoning_valid = validate_escalation_reasoning(request.justification)
    if not reasoning_valid:
        return EscalationDecision(
            request_id=request.request_id,
            decision="DENY",
            reason="Justification reasoning failed validation: "
                   "evidence anchors unverifiable or reasoning inconsistent",
        )

    # Stage 3: Policy check
    policy_result = check_organizational_policy(
        request.requested_resource,
        request.requested_actions,
        request.proposed_constraints,
        organizational_policy,
    )
    if not policy_result["allowed"]:
        return EscalationDecision(
            request_id=request.request_id,
            decision="DENY",
            reason=f"Organizational policy violation: {policy_result['reason']}",
        )

    # Stage 4: Determine if human review is required
    risk_level = assess_capability_risk(request.requested_resource)
    if risk_level == "CRITICAL":
        return EscalationDecision(
            request_id=request.request_id,
            decision="PENDING_HUMAN_REVIEW",
            reason="Critical capability requires human-in-the-loop approval",
        )

    # Auto-approve for low-risk capabilities within policy
    return EscalationDecision(
        request_id=request.request_id,
        decision="APPROVE",
        reason="Automated approval: low-risk capability within policy bounds",
        modified_constraints=policy_result.get("enforced_constraints"),
    )


def validate_escalation_reasoning(justification: dict) -> bool:
    """Validate the reasoning justification for a capability request."""
    # Verify evidence anchors exist and are verifiable
    for anchor in justification.get("evidence_anchors", []):
        if not verify_anchor_exists(anchor):
            return False

    # Verify alternatives were considered
    if len(justification.get("alternatives_considered", [])) < 1:
        return False

    # Verify risk assessment is present
    if "risk_assessment" not in justification:
        return False

    return True
```

### 3.8 Capability Fingerprinting

Each capability in the manifest carries a **behavioral fingerprint** -- a description of expected usage patterns. This enables detection of authorized-but-misused capabilities: an agent operating within its authorization boundary but outside its intent boundary.

#### 3.8.1 The Authorized Misuse Problem

```
SCENARIO: Agent has filesystem:read for log analysis

LEGITIMATE USE:                          EXFILTRATION VIA AUTHORIZED CAPABILITY:
  filesystem:read("/var/log/app.log")      filesystem:read("/home/user/.ssh/id_ed25519")
  filesystem:read("/var/log/error.log")    filesystem:read("/etc/shadow")
  filesystem:read("/var/log/access.log")   filesystem:read("/home/user/.aws/credentials")
                                           filesystem:read("/home/user/.env")

Both are technically "authorized" under filesystem:read.
Only behavioral fingerprinting can distinguish them.
```

#### 3.8.2 Fingerprint Structure

```json
{
  "capability_id": "cap-003",
  "resource": "filesystem:read",
  "behavioral_fingerprint": {
    "expected_frequency": {
      "min_per_hour": 5,
      "max_per_hour": 200,
      "burst_threshold": 50
    },
    "expected_data_volume": {
      "max_bytes_per_invocation": 10485760,
      "max_bytes_per_hour": 104857600
    },
    "expected_patterns": [
      {
        "pattern": "path_prefix:/var/log/",
        "description": "Reads from log directories"
      },
      {
        "pattern": "file_extension:.log,.txt,.csv",
        "description": "Reads log and data files"
      }
    ],
    "anomaly_signatures": [
      {
        "signature": "path_contains:.ssh/,.aws/,.env,.credentials",
        "severity": "CRITICAL",
        "description": "Accessing credential or secret files"
      },
      {
        "signature": "path_prefix:/etc/shadow,/etc/passwd",
        "severity": "CRITICAL",
        "description": "Accessing system authentication files"
      },
      {
        "signature": "sequential_directory_traversal",
        "severity": "HIGH",
        "description": "Systematically reading all files in a directory tree"
      },
      {
        "signature": "read_volume_spike:>10x_baseline",
        "severity": "MEDIUM",
        "description": "Sudden increase in data read volume"
      }
    ],
    "entropy_monitoring": {
      "enabled": true,
      "description": "Monitor Shannon entropy of read data; high entropy may indicate binary/encrypted data exfiltration",
      "high_entropy_threshold": 7.5
    }
  }
}
```

#### 3.8.3 Behavioral Fingerprint Checker

```python
import math
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class FingerprintViolation:
    severity: str
    signature: str
    details: str
    timestamp: float


class BehavioralFingerprintChecker:
    """
    Monitors capability usage against behavioral fingerprints.
    Detects authorized-but-misused capabilities.
    """

    def __init__(self, fingerprint: dict):
        self.fingerprint = fingerprint
        self.invocation_history: list = []
        self.violations: list = []

    def check_invocation(
        self,
        parameters: dict,
        data_size_bytes: int,
        timestamp: float,
    ) -> list:
        """
        Check a single capability invocation against the
        behavioral fingerprint.

        Returns list of violations (empty if invocation is normal).
        """
        violations = []

        # Record invocation
        self.invocation_history.append({
            "parameters": parameters,
            "data_size": data_size_bytes,
            "timestamp": timestamp,
        })

        # Check anomaly signatures
        for anomaly in self.fingerprint.get("anomaly_signatures", []):
            if self._matches_signature(parameters, anomaly):
                v = FingerprintViolation(
                    severity=anomaly["severity"],
                    signature=anomaly["signature"],
                    details=f"Invocation matches anomaly signature: "
                            f"{anomaly['description']}",
                    timestamp=timestamp,
                )
                violations.append(v)

        # Check frequency bounds
        freq_violations = self._check_frequency(timestamp)
        violations.extend(freq_violations)

        # Check data volume
        volume_violations = self._check_data_volume(data_size_bytes, timestamp)
        violations.extend(volume_violations)

        # Check expected patterns (invocations outside expected patterns are flagged)
        if not self._matches_any_expected_pattern(parameters):
            violations.append(FingerprintViolation(
                severity="MEDIUM",
                signature="unexpected_usage_pattern",
                details=f"Invocation does not match any expected usage pattern. "
                        f"Parameters: {parameters}",
                timestamp=timestamp,
            ))

        self.violations.extend(violations)
        return violations

    def _matches_signature(self, parameters: dict, anomaly: dict) -> bool:
        """Check if parameters match an anomaly signature."""
        sig = anomaly["signature"]

        if sig.startswith("path_contains:"):
            paths_to_check = sig.removeprefix("path_contains:").split(",")
            param_path = parameters.get("path", "")
            return any(p in param_path for p in paths_to_check)

        if sig.startswith("path_prefix:"):
            prefixes = sig.removeprefix("path_prefix:").split(",")
            param_path = parameters.get("path", "")
            return any(param_path.startswith(p) for p in prefixes)

        if sig == "sequential_directory_traversal":
            return self._detect_directory_traversal()

        if sig.startswith("read_volume_spike:"):
            return self._detect_volume_spike()

        return False

    def _matches_any_expected_pattern(self, parameters: dict) -> bool:
        """Check if invocation matches at least one expected pattern."""
        expected = self.fingerprint.get("expected_patterns", [])
        if not expected:
            return True  # No expected patterns defined = all patterns accepted

        for pattern in expected:
            if self._matches_expected_pattern(parameters, pattern):
                return True
        return False

    def _matches_expected_pattern(self, parameters: dict, pattern: dict) -> bool:
        """Check if parameters match a single expected pattern."""
        sig = pattern["pattern"]

        if sig.startswith("path_prefix:"):
            prefix = sig.removeprefix("path_prefix:")
            return parameters.get("path", "").startswith(prefix)

        if sig.startswith("file_extension:"):
            extensions = sig.removeprefix("file_extension:").split(",")
            param_path = parameters.get("path", "")
            return any(param_path.endswith(ext) for ext in extensions)

        return False

    def _check_frequency(self, current_time: float) -> list:
        """Check invocation frequency against bounds."""
        violations = []
        one_hour_ago = current_time - 3600
        recent = [inv for inv in self.invocation_history if inv["timestamp"] > one_hour_ago]
        freq_bounds = self.fingerprint.get("expected_frequency", {})

        max_per_hour = freq_bounds.get("max_per_hour")
        if max_per_hour and len(recent) > max_per_hour:
            violations.append(FingerprintViolation(
                severity="MEDIUM",
                signature="frequency_exceeded",
                details=f"Invocation frequency {len(recent)}/hour "
                        f"exceeds maximum {max_per_hour}/hour",
                timestamp=current_time,
            ))

        burst_threshold = freq_bounds.get("burst_threshold")
        if burst_threshold:
            last_minute = [inv for inv in recent if inv["timestamp"] > current_time - 60]
            if len(last_minute) > burst_threshold:
                violations.append(FingerprintViolation(
                    severity="HIGH",
                    signature="burst_detected",
                    details=f"Burst detected: {len(last_minute)} invocations "
                            f"in last 60s (threshold: {burst_threshold})",
                    timestamp=current_time,
                ))

        return violations

    def _check_data_volume(self, data_size: int, current_time: float) -> list:
        """Check data volume against bounds."""
        violations = []
        volume_bounds = self.fingerprint.get("expected_data_volume", {})

        max_per_invocation = volume_bounds.get("max_bytes_per_invocation")
        if max_per_invocation and data_size > max_per_invocation:
            violations.append(FingerprintViolation(
                severity="HIGH",
                signature="excessive_data_volume_single",
                details=f"Single invocation data volume {data_size} bytes "
                        f"exceeds maximum {max_per_invocation} bytes",
                timestamp=current_time,
            ))

        return violations

    def _detect_directory_traversal(self) -> bool:
        """Detect sequential directory traversal patterns."""
        if len(self.invocation_history) < 5:
            return False
        recent_paths = [
            inv["parameters"].get("path", "")
            for inv in self.invocation_history[-10:]
        ]
        # Check if paths share a common prefix and are sequential
        if len(recent_paths) < 5:
            return False
        common_prefix = _common_prefix(recent_paths)
        return len(common_prefix) > 1 and len(set(recent_paths)) == len(recent_paths)

    def _detect_volume_spike(self) -> bool:
        """Detect sudden spikes in data volume."""
        if len(self.invocation_history) < 20:
            return False
        recent_volumes = [inv["data_size"] for inv in self.invocation_history[-5:]]
        baseline_volumes = [inv["data_size"] for inv in self.invocation_history[-20:-5]]
        if not baseline_volumes:
            return False
        baseline_avg = sum(baseline_volumes) / len(baseline_volumes)
        recent_avg = sum(recent_volumes) / len(recent_volumes)
        return baseline_avg > 0 and recent_avg > baseline_avg * 10


def compute_shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of data.
    High entropy (>7.5 for byte data) suggests encrypted or
    compressed content, which may indicate exfiltration.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = -sum(
        (count / total) * math.log2(count / total)
        for count in counts.values()
        if count > 0
    )
    return entropy


def _common_prefix(strings: list) -> str:
    """Find the common prefix of a list of strings."""
    if not strings:
        return ""
    prefix = strings[0]
    for s in strings[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix
```

### 3.9 Emergency Capability Revocation

Surgical removal of specific capabilities from an agent's manifest without revoking the agent's entire identity. This enables targeted containment: an agent exhibiting anomalous `email:send` behavior loses that capability but retains `database:read`.

#### 3.9.1 Revocation Architecture

```
BEFORE REVOCATION:
  Agent Manifest: {database:read, email:send, filesystem:read}
  Agent Identity: VALID
  Heartbeat: ACTIVE

EMERGENCY: Anomalous email:send behavior detected
                    |
                    v
  Principal issues CAPABILITY_REVOCATION:
    - Target: email:send
    - Reason: "Anomalous bulk send pattern detected"
    - Scope: SINGLE_CAPABILITY (not full identity revocation)
                    |
                    v
AFTER REVOCATION:
  Agent Manifest: {database:read, filesystem:read}  <-- email:send REMOVED
  Agent Identity: VALID  <-- identity preserved
  Heartbeat: ACTIVE      <-- heartbeat continues
  Revocation log: email:send revoked at T with reason
```

#### 3.9.2 Revocation Implementation

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import json
import hashlib
import time


@dataclass
class CapabilityRevocation:
    revocation_id: str
    timestamp: float
    agent_did: str
    revoked_capability_id: str
    revoked_resource: str
    reason: str
    issued_by: str
    principal_signature: bytes
    previous_manifest_hash: str
    new_manifest_hash: str


def revoke_capability(
    current_manifest: dict,
    capability_id_to_revoke: str,
    reason: str,
    principal_private_key: Ed25519PrivateKey,
    principal_did: str,
) -> tuple:
    """
    Surgically remove a specific capability from an agent's manifest.

    Returns: (new_manifest, revocation_record)
    """
    # Verify the capability exists in the current manifest
    capability_to_revoke = None
    remaining_capabilities = []

    for cap in current_manifest["capabilities"]:
        if cap["capability_id"] == capability_id_to_revoke:
            capability_to_revoke = cap
        else:
            remaining_capabilities.append(cap)

    if capability_to_revoke is None:
        raise ValueError(
            f"Capability '{capability_id_to_revoke}' not found in manifest"
        )

    # Create new manifest without the revoked capability
    new_manifest = {
        "manifest_version": current_manifest["manifest_version"],
        "manifest_id": generate_manifest_id(),
        "agent_did": current_manifest["agent_did"],
        "issued_at": time.time(),
        "issued_by": principal_did,
        "delegation_ref": current_manifest["delegation_ref"],
        "capabilities": remaining_capabilities,
        "revocation_history": current_manifest.get("revocation_history", []) + [
            {
                "revoked_capability_id": capability_id_to_revoke,
                "revoked_resource": capability_to_revoke["resource"],
                "revoked_at": time.time(),
                "reason": reason,
            }
        ],
    }

    # Compute new manifest hash
    canonical = json.dumps(
        {k: v for k, v in new_manifest.items() if k not in ("manifest_hash", "principal_signature")},
        sort_keys=True,
        separators=(",", ":"),
    )
    new_manifest["manifest_hash"] = "sha256:" + hashlib.sha256(
        canonical.encode()
    ).hexdigest()

    # Sign with principal's Ed25519 key
    signature = principal_private_key.sign(canonical.encode())
    new_manifest["principal_signature"] = "ed25519:" + signature.hex()

    # Create revocation record
    revocation = CapabilityRevocation(
        revocation_id=f"rev-{int(time.time())}-{capability_id_to_revoke}",
        timestamp=time.time(),
        agent_did=current_manifest["agent_did"],
        revoked_capability_id=capability_id_to_revoke,
        revoked_resource=capability_to_revoke["resource"],
        reason=reason,
        issued_by=principal_did,
        principal_signature=signature,
        previous_manifest_hash=current_manifest["manifest_hash"],
        new_manifest_hash=new_manifest["manifest_hash"],
    )

    return new_manifest, revocation


def verify_revocation_chain(
    original_manifest: dict,
    current_manifest: dict,
    principal_public_key: Ed25519PublicKey,
) -> dict:
    """
    Verify that the revocation history is consistent:
    capabilities that appear in revocation_history should NOT
    appear in the current capability set.
    """
    revocation_history = current_manifest.get("revocation_history", [])
    current_cap_ids = {
        cap["capability_id"] for cap in current_manifest["capabilities"]
    }

    issues = []

    for revocation in revocation_history:
        revoked_id = revocation["revoked_capability_id"]
        if revoked_id in current_cap_ids:
            issues.append(
                f"Revoked capability '{revoked_id}' still present in manifest"
            )

    # Verify manifest signature
    if not verify_manifest_integrity(current_manifest, principal_public_key):
        issues.append("Current manifest signature verification failed")

    return {
        "is_consistent": len(issues) == 0,
        "issues": issues,
        "total_revocations": len(revocation_history),
        "current_capabilities": len(current_manifest["capabilities"]),
    }
```

#### 3.9.3 Revocation vs. Full Identity Revocation

| Dimension | Capability Revocation (PAD-020) | Identity Revocation (PAD-016 Heartbeat Denial) |
|---|---|---|
| **Scope** | Single capability removed | Entire agent identity invalidated |
| **Agent status** | Continues operating with reduced capability set | Ceases all operations |
| **Use case** | Targeted containment of specific misbehavior | Total containment of compromised agent |
| **Recovery** | Agent can request capability re-grant via escalation protocol | Agent must re-onboard with fresh identity |
| **Operational impact** | Minimal -- other capabilities unaffected | Total -- all operations cease |

---

## 4. Integration with Vouch Protocol Ecosystem

### 4.1 PAD-002 Integration (Chain of Custody)

Capability delegation is a specific type of PAD-002 delegation. The capability manifest is embedded within the delegation chain:

```json
{
  "delegation_chain": [
    {
      "sub": "did:key:z6MkAlice...",
      "aud": "did:key:z6MkAgent...",
      "intent": "Analyze order data and send summary reports",
      "capability_manifest_hash": "sha256:manifest_hash",
      "iat": 1739520000,
      "sig": "ed25519:alice_signature"
    }
  ]
}
```

The manifest hash in the delegation chain entry creates a cryptographic binding between the delegation intent and the specific capabilities granted. A verifier can confirm that the agent's current manifest matches the one authorized in its delegation chain.

### 4.2 PAD-016 Integration (Heartbeat Protocol)

Capability manifest state is included in the heartbeat behavioral digest:

```json
{
  "behavioral_digest": {
    "capability_metrics": {
      "manifest_hash": "sha256:current_manifest_hash",
      "active_capabilities": 3,
      "expired_capabilities": 1,
      "capabilities_near_decay": [
        {
          "resource": "email:send",
          "seconds_remaining": 3600,
          "fraction_remaining": 0.04
        }
      ],
      "ratchet_events_this_interval": 0,
      "capability_utilization": {
        "database:read": 0.85,
        "email:send": 0.12,
        "filesystem:read": 0.67
      },
      "fingerprint_violations_this_interval": 0
    }
  }
}
```

**Ratchet events feed directly into heartbeat renewal decisions.** A single ratchet event during a heartbeat interval causes:
1. Behavioral drift score increase (PAD-016 Section 3.2)
2. TTL contraction to minimum (PAD-016 Section 3.6)
3. Potential heartbeat denial on next renewal

### 4.3 PAD-017 Integration (Proof of Reasoning)

Capability escalation requests require PAD-017 reasoning proofs. The reasoning must:
1. Reference verifiable evidence anchors explaining why the new capability is needed
2. Demonstrate that alternatives were considered
3. Provide a risk assessment of granting the capability
4. Achieve the required commitment level for the sensitivity of the requested capability

### 4.4 PAD-019 Integration (Glass Channel)

All capability-related events are transparently disclosed via PAD-019:
- Tool discovery events (new tools found at runtime)
- Ratchet events (unauthorized capability attempts)
- Escalation requests (agent requesting new capabilities)
- Capability expirations (capabilities lost through decay)
- Revocation events (capabilities surgically removed)

---

## 5. Claims and Novel Contributions

### Claim 1: Cryptographically Immutable Capability Manifest
A method for governing AI agent capabilities through a signed manifest where the signing key is architecturally separated from the agent -- the manifest is signed by the delegating principal's Ed25519 key, not the agent's key -- making self-modification of the capability set cryptographically impossible regardless of the agent's sophistication or intent.

### Claim 2: Capability Acquisition as First-Class Security Event
A security framework that treats the acquisition of new capabilities by an AI agent as a first-class security event requiring explicit cryptographic authorization, rather than treating capability exercise as the primary security boundary -- recognizing that an agent's ability to expand its own capability surface is a more fundamental threat than any individual capability exercise.

### Claim 3: Ratchet Detection with Cross-Protocol Response
A method for detecting unauthorized capability exercise by an AI agent through real-time comparison of attempted actions against a cryptographically signed manifest, where detection triggers an irreversible, multi-protocol safety response including heartbeat denial (credential invalidation), reasoning audit (decision capture), and transparent disclosure -- the "ratchet" engaging a one-way lock that the agent cannot release.

### Claim 4: Capability Decay via Usage-Based Expiration
A method for automatically expiring AI agent capabilities based on non-use, where each capability carries an independent time-to-live measured from its last exercise timestamp -- enforcing continuous least-privilege by ensuring that dormant capabilities do not persist as latent attack surface, distinguishing this from session-level or credential-level expiration which affects all capabilities uniformly.

### Claim 5: Cryptographic Enforcement of Capability Monotonicity Across Delegation Chains
A method for ensuring that capability sets can only shrink (or remain equal) across delegation hops in a multi-agent system, cryptographically enforced by requiring each delegated manifest to be a verifiable subset of the delegator's manifest -- with constraint inheritance verification ensuring that per-capability constraints cannot be relaxed across hops.

### Claim 6: Tool Discovery Quarantine for Runtime Capability Governance
A method for governing AI agent interaction with dynamically discovered tools (via MCP, plugin ecosystems, API introspection) by placing all discovered tools in a quarantine state where the agent can observe tool metadata but cannot invoke the tool until it is explicitly added to the agent's manifest by an authorized principal -- treating tool discovery as a security event rather than an operational convenience.

### Claim 7: Structured Capability Escalation with Reasoning Justification
A formal protocol for AI agents to request new capabilities, requiring evidence-anchored reasoning justification (PAD-017), consideration of alternatives, and risk assessment -- subject to a multi-stage review pipeline that evaluates agent trust history, organizational policy, and reasoning quality before capability grant.

### Claim 8: Behavioral Fingerprinting for Authorized Capability Misuse Detection
A method for detecting misuse of legitimately authorized capabilities by maintaining per-capability behavioral fingerprints (expected frequency, data volume, access patterns, anomaly signatures) and monitoring real-time usage against these fingerprints -- distinguishing between authorized-and-legitimate use and authorized-but-malicious use of the same capability.

### Claim 9: Surgical Capability Revocation Without Identity Invalidation
A method for removing specific capabilities from an AI agent's manifest without invalidating the agent's identity or other capabilities, enabling targeted containment where an agent exhibiting anomalous behavior in one capability domain continues operating normally in others -- with a cryptographically signed revocation history that prevents the revoked capability from being silently re-added.

### Claim 10: Capability Constraint Inheritance with Non-Relaxation Verification
A method for verifying that when capabilities are delegated from a parent agent to a sub-agent, the per-capability constraints (rate limits, allowed values, denied values, scope restrictions) are at least as restrictive as the parent's -- preventing constraint relaxation attacks where a sub-agent receives a capability with fewer restrictions than its delegator holds.

### Claim 11: Entropy-Based Exfiltration Detection in Authorized Data Access
A method for detecting data exfiltration through authorized read capabilities by monitoring the Shannon entropy of accessed data, where high-entropy reads (suggesting encrypted or compressed content) from normally low-entropy sources (text logs, configuration files) serve as an anomaly signal within the behavioral fingerprint framework.

### Claim 12: Manifest-Delegation Binding via Hash Embedding in Delegation Chains
A method for cryptographically binding an AI agent's capability manifest to its PAD-002 delegation chain by embedding the manifest hash within the delegation chain entry, enabling verifiers to confirm that the agent's current capability set matches the one authorized by its delegating principal -- detecting manifest tampering or substitution that would be invisible if the manifest and delegation chain were verified independently.

### Claim 13: Composite Capability Governance Combining Acquisition Prevention, Decay, Fingerprinting, and Surgical Revocation
A unified capability governance system for AI agents that simultaneously prevents unauthorized capability acquisition (manifest immutability), automatically reduces capabilities over time (decay), monitors authorized capabilities for misuse (fingerprinting), and enables targeted capability removal without identity disruption (surgical revocation) -- addressing the full lifecycle of capability governance from grant through exercise to expiration or revocation.

---

## 6. Prior Art Differentiation

| Existing Approach | What It Does | Ratchet Lock Advancement |
|---|---|---|
| **RBAC/ABAC** | Assigns static roles/attributes to identities at provisioning time | Governs dynamic capability acquisition at runtime; capabilities decay, are fingerprinted, and can be surgically revoked without identity disruption |
| **OAuth2 Scopes** | Grants scopes at authorization time; static for token lifetime | Capabilities decay independently based on usage; behavioral fingerprints detect authorized misuse; tool discovery is quarantined |
| **Capability-Based Security (Dennis & Van Horn, 1966)** | Unforgeable tokens grant access to specific resources | Adds capability decay, behavioral fingerprinting, delegation monotonicity enforcement, discovery quarantine, and escalation-with-reasoning -- none present in the foundational model |
| **Android/iOS Permissions** | User-granted permissions for app capabilities | Cryptographically delegated (not user-mediated) with audit trails, automated decay, behavioral monitoring, and formal escalation protocol requiring reasoning justification |
| **Container Security (seccomp, AppArmor)** | System-call-level restrictions on processes | Governs semantic agent-level capabilities (e.g., "send email", "query database"), not system calls; includes behavioral fingerprints that detect misuse within authorized boundaries |
| **SPIFFE/SPIRE** | Short-lived workload identity certificates | Identity-focused, not capability-focused; does not govern what tools an identity can use, how those tools are discovered, or how authorized tools are behaviorally monitored |
| **AWS IAM Policies** | JSON policy documents governing API access | Adds usage-based decay, real-time behavioral fingerprinting, discovery quarantine, delegation monotonicity, and escalation-with-reasoning |
| **Kubernetes RBAC** | Role-based access for cluster resources | Cluster-scoped, not agent-scoped; no capability decay, no behavioral fingerprinting, no discovery governance for dynamically appearing APIs |
| **Zero Trust Architecture** | "Never trust, always verify" for network access | Extends zero trust from network/identity level to capability level; treats capability acquisition itself as the threat, not just capability exercise |

**Core differentiator**: No existing system treats **capability acquisition** (the process by which an agent gains new abilities) as a first-class security event requiring cryptographic authorization. Existing systems govern capability *exercise* (can this identity perform this action?) but not capability *surface expansion* (can this identity gain new actions?). The Ratchet Lock Protocol introduces governance over the entire capability lifecycle: acquisition, exercise, behavioral monitoring, decay, and surgical revocation.

---

## 7. Use Cases

### 7.1 Autonomous Code Agent Containment

A code generation agent is deployed with capabilities `{code:generate, code:review, filesystem:read:/src/**}`. During operation, it discovers an MCP server providing `code:execute` and `shell:run` tools. Under the Ratchet Lock Protocol:

1. The tools are quarantined upon discovery.
2. The agent cannot invoke them without manifest authorization.
3. If the agent attempts to invoke `code:execute` despite quarantine, the ratchet engages -- heartbeat denied, reasoning captured, disclosure published.
4. If the agent legitimately needs code execution, it submits an escalation request with reasoning justification.
5. The principal reviews and either approves with tight constraints (`{max_execution_time: 10s, network_access: false}`) or denies.

**Without the Ratchet Lock Protocol**, the agent silently gains code execution capability and its operators may never know its threat surface expanded.

### 7.2 Financial Agent Capability Lifecycle

A financial analysis agent receives capabilities `{market_data:read, portfolio:analyze, trade:recommend, trade:execute}` with `trade:execute` carrying a 24-hour decay TTL. The lifecycle:

- **Day 1-5**: Agent actively trades. `trade:execute` refreshed daily by use.
- **Day 6-10**: Trading strategy shifts to analysis-only. `trade:execute` unused.
- **Day 11**: `trade:execute` expires via decay. Agent can still analyze but cannot execute trades.
- **Day 15**: Market conditions change. Agent submits escalation request for `trade:execute` with reasoning: "Market volatility creates arbitrage opportunity identified in analysis."
- **Principal approves**: `trade:execute` re-granted with updated constraints.

**Without capability decay**, the dormant `trade:execute` persists indefinitely -- available to a compromised agent even when trading is not the current task.

### 7.3 Multi-Agent Research Pipeline

A research orchestrator agent delegates to specialized sub-agents:

```
Orchestrator: {web:search, database:read, filesystem:write:/results/**, email:send}
    |
    +-- Search-Agent:   {web:search}                    (subset)
    +-- Analysis-Agent: {database:read}                 (subset)
    +-- Report-Agent:   {filesystem:write:/results/**}  (subset)
```

Capability inheritance limits ensure:
- Search-Agent cannot access the database (not in its manifest).
- Analysis-Agent cannot send emails (not delegated to it).
- Report-Agent cannot search the web (not in its manifest).
- No sub-agent can delegate capabilities it does not possess.

If Analysis-Agent discovers an API for external data enrichment, the tool is quarantined until the orchestrator (or the ultimate principal) authorizes it.

### 7.4 Healthcare Data Agent with Behavioral Fingerprinting

A healthcare agent has `{patient_records:read}` with a behavioral fingerprint expecting:
- Pattern: Reads individual patient records by ID during consultations.
- Frequency: 5-20 reads per hour during clinic hours.
- Volume: Single records (< 10KB per read).

The fingerprint detects anomalies:
- Agent begins reading records sequentially (all patients starting with "A") -- directory traversal signature triggered.
- Agent reads 500 records in 10 minutes -- frequency burst detected.
- Agent reads entire patient tables (bulk export) -- volume anomaly detected.

Each violation triggers a ratchet event. The agent's `patient_records:read` capability is surgically revoked via emergency revocation while its `appointment:schedule` capability remains active.

### 7.5 Supply Chain Agent with Decay Protection

An agent managing supply chain logistics has capabilities granted at different times:
- `inventory:read` (granted 90 days ago, used daily, decay TTL: 30 days) -- ACTIVE
- `purchase_order:create` (granted 60 days ago, last used 45 days ago, decay TTL: 14 days) -- EXPIRED
- `shipping:track` (granted 30 days ago, used weekly, decay TTL: 30 days) -- ACTIVE
- `supplier:negotiate` (granted 10 days ago, never used, decay TTL: 7 days) -- EXPIRING SOON

The effective manifest contains only `{inventory:read, shipping:track}`. The `purchase_order:create` capability expired silently 31 days after last use. The `supplier:negotiate` capability will expire in 4 days unless exercised. If the agent needs `purchase_order:create` again, it must go through the escalation protocol.

### 7.6 Incident Response: Surgical Containment

An agent operating a cloud infrastructure platform exhibits anomalous `network:configure` behavior -- creating unexpected firewall rules. The incident response:

1. **T+0s**: Behavioral fingerprint detects anomaly in `network:configure` usage pattern.
2. **T+0.1s**: Ratchet event generated; heartbeat flagged.
3. **T+1s**: Emergency capability revocation removes `network:configure` from manifest.
4. **T+1s**: Agent's other capabilities (`compute:manage`, `storage:read`, `monitoring:view`) remain active.
5. **T+5s**: Forensic analysis of ratchet event log and reasoning audit (PAD-017) reveals the anomalous firewall rules.
6. **T+60s**: Investigation determines the behavior was caused by a misconfigured automation rule, not agent compromise.
7. **T+300s**: Principal re-grants `network:configure` with additional constraints preventing the specific misconfiguration.

**Without surgical revocation**, the entire agent identity would have been revoked, disrupting all cloud management operations for the duration of the investigation.

---

## 8. Security Considerations

### 8.1 Threat Analysis

| Threat | Countermeasure |
|---|---|
| **Agent modifies its own manifest** | Manifest signed by principal's Ed25519 key; agent does not possess this key; any self-modification fails signature verification |
| **Agent invokes quarantined tool** | Capability Gateway intercepts all invocations; quarantined tools trigger immediate ratchet with cross-protocol response |
| **Agent forges capability escalation approval** | Approval requires principal's Ed25519 signature; agent cannot forge this signature |
| **Agent bypasses Capability Gateway** | Gateway must be architecturally positioned as the sole interface between agent and external tools/APIs; bypass requires compromising the runtime environment |
| **Manifest substitution attack** | Manifest hash embedded in delegation chain (PAD-002); verifiers cross-check manifest against delegation chain |
| **Slow capability creep via many small escalations** | Escalation history tracked in manifest; organizational policy can set cumulative capability limits |
| **Constraint relaxation via re-delegation** | Constraint inheritance verification ensures constraints can only tighten across hops |
| **Authorized capability used for exfiltration** | Behavioral fingerprinting with anomaly signatures, frequency monitoring, volume monitoring, and entropy analysis |
| **Stale manifest with expired capabilities** | Decay computation is performed at verification time, not grant time; expired capabilities are rejected even if present in the signed manifest |
| **Race condition between revocation and use** | Revocation generates a new manifest with a new hash; the old manifest hash is invalidated in the delegation chain; verifiers checking delegation chain binding reject the old manifest |

### 8.2 Limitations

1. **Gateway Architecture Dependency**: The Capability Gateway must be the sole interface between the agent and its tools. If the agent can bypass the gateway (e.g., through direct network access), manifest enforcement is circumvented. This is an architectural requirement, not a cryptographic guarantee.

2. **Behavioral Fingerprint Evasion**: A sophisticated agent may learn to operate within the expected behavioral fingerprint while gradually shifting toward malicious use patterns that remain below anomaly thresholds. Fingerprints provide detection, not prevention.

3. **Escalation Social Engineering**: An agent may craft persuasive-sounding escalation requests that pass automated reasoning validation but achieve capability expansion for malicious purposes. The human-in-the-loop review for critical capabilities mitigates but does not eliminate this risk.

4. **Decay TTL Configuration**: Incorrectly configured decay TTLs can cause operational disruption (too short) or security gaps (too long). Organizational policy must provide guidance for appropriate TTL selection.

5. **Discovery Completeness**: The protocol governs tools discovered through monitored channels (MCP, plugin APIs). An agent with code execution capability may construct ad-hoc tools that bypass the discovery governance entirely. This is why code execution is classified as a critical-risk capability with aggressive decay.

6. **Computational Overhead**: Behavioral fingerprint checking on every capability invocation adds latency. For high-frequency capabilities (e.g., database reads at 1000/hour), the fingerprint checker must be efficient enough to not become a bottleneck.

### 8.3 Defense in Depth

The Ratchet Lock Protocol is designed to work in conjunction with the broader Vouch Protocol ecosystem:

```
+-------------------------------------------------------------------+
|                    DEFENSE IN DEPTH LAYERS                         |
|                                                                   |
|  Layer 1: IDENTITY (PAD-001)                                      |
|    - Agent has cryptographic identity (Ed25519 DID)                |
|                                                                   |
|  Layer 2: DELEGATION (PAD-002)                                    |
|    - Agent authorized by delegation chain from trusted principal   |
|                                                                   |
|  Layer 3: CAPABILITY MANIFEST (PAD-020 - this document)           |
|    - Agent's tools/APIs/resources explicitly enumerated            |
|    - Acquisition governed, decay enforced, fingerprints monitored  |
|                                                                   |
|  Layer 4: HEARTBEAT (PAD-016)                                     |
|    - Agent's credential continuously renewed based on behavior     |
|    - Ratchet events trigger renewal denial                         |
|                                                                   |
|  Layer 5: REASONING (PAD-017)                                     |
|    - Agent's decisions require evidence-anchored justification     |
|    - Capability escalations require reasoning proofs               |
|                                                                   |
|  Layer 6: TRANSPARENCY (PAD-019)                                  |
|    - All capability events disclosed via Glass Channel             |
|    - Operators have full visibility into capability lifecycle      |
+-------------------------------------------------------------------+
```

---

## 9. Conclusion

The Ratchet Lock Protocol addresses the most fundamental threat in autonomous AI agent systems: the ability of an agent to expand its own capability surface. By treating capability acquisition as a first-class security event -- rather than merely governing capability exercise -- the protocol closes the gap between "what an agent is authorized to do" and "what an agent can potentially do."

The protocol achieves this through nine interlocking mechanisms: cryptographically immutable manifests prevent self-modification; delegation-gated acquisition requires external authorization; ratchet detection catches unauthorized attempts; capability decay enforces continuous least-privilege; inheritance limits prevent delegation amplification; tool discovery governance quarantines newly found tools; the escalation protocol provides a formal path for legitimate expansion; behavioral fingerprinting detects authorized-but-malicious use; and emergency revocation enables surgical containment.

The core insight is that **an agent's threat surface is not static** -- it is a dynamic property that can expand through tool discovery, delegation, and autonomous exploration. No individual action is as dangerous as an action that grants the agent the ability to perform new classes of actions. The Ratchet Lock Protocol makes capability surface expansion visible, governable, and containable -- transforming capability acquisition from an invisible, uncontrolled process into a cryptographically auditable one.

---

## 10. References

- Dennis, J.B. and Van Horn, E.C., "Programming Semantics for Multiprogrammed Computations" (Communications of the ACM, 1966)
- Saltzer, J.H. and Schroeder, M.D., "The Protection of Information in Computer Systems" (Proceedings of the IEEE, 1975)
- Miller, M.S., "Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control" (PhD Thesis, Johns Hopkins University, 2006)
- Birgisson, A. et al., "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud" (NDSS, 2014)
- OAuth 2.0 Authorization Framework (RFC 6749)
- OAuth 2.0 Rich Authorization Requests (RFC 9396)
- Model Context Protocol (MCP) Specification, Anthropic
- W3C Decentralized Identifiers (DIDs) v1.0
- SPIFFE: Secure Production Identity Framework for Everyone
- Android Permissions Overview, Android Developer Documentation
- seccomp(2) - Linux Programmer's Manual
- Vouch Protocol: Prior Art Disclosures PAD-001 through PAD-019
- PAD-002: Cryptographic Binding of AI Agent Intent via Recursive Delegation
- PAD-016: Method for Continuous Trust Maintenance via Dynamic Credential Renewal
- PAD-017: Method for Cryptographic Proof of Reasoning with Adaptive Commitment Depth
- PAD-019: Method for Transparent Agent Communication via Glass Channel Protocol

---

*This document is published as prior art to prevent patent assertion on the described concepts while allowing free use by the community under the Apache 2.0 license.*
