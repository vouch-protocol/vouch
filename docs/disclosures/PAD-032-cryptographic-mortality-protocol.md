# PAD-032: Cryptographic Mortality Protocol for Agent Identity Termination

**Identifier:** PAD-032  
**Title:** Method for Pre-Committed Identity Termination, Capability Inheritance, and Forensic State Sealing via Dead-Man's-Switch Liveness Proofs  
**Publication Date:** April 22, 2026  
**Prior Art Effective Date:** April 22, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Identity Lifecycle / Key Management / Forensic Preservation / Agent Continuity / Decentralized Identity  
**Author:** Ramprasad Anandam Gaddam  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-002 (Chain of Custody), PAD-016 (Dynamic Credential Renewal), PAD-020 (Ratchet Lock Protocol), PAD-027 (Shamir Split Biometric Recovery)  

---

## 1. Abstract

A system and method for governing the **permanent cessation** of an AI agent's identity  -  including cryptographic key revocation, capability transfer to designated successors, forensic preservation of operational state, and orderly unwinding of delegated authority chains. The protocol addresses a critical gap in identity lifecycle management: while existing systems handle identity creation (PAD-001), ongoing renewal (PAD-016), and recovery (PAD-027), no system governs what happens when an agent, an operator, or an entire organization permanently ceases to exist.

The system introduces several interlocking mechanisms:

1. **Mortality Escrow:** The agent (or its operator) deposits encrypted **termination instructions**  -  a pre-committed "digital will"  -  with an independent escrow service. These instructions specify key revocation procedures, capability inheritance mappings, data archival policies, and successor designations. The escrow is sealed with time-locked encryption that activates when liveness proofs stop arriving.

2. **Dead-Man's-Switch Liveness:** The agent must periodically submit cryptographic liveness proofs to the escrow service. If liveness proofs cease for a configurable duration (the "mortality horizon"), the escrow service initiates the termination sequence. Unlike PAD-016 heartbeats (which govern credential renewal during normal operation), the mortality switch governs the irreversible, permanent termination of identity.

3. **Pre-Committed Revocation Certificates:** The agent generates Ed25519-signed revocation certificates at identity creation time, deposits them in escrow, and they are published automatically upon mortality activation. Because the certificates are pre-signed by the agent's own key, they are indistinguishable from voluntary revocations  -  no third party can forge them, and no emergency access to the agent's private key is required.

4. **Capability Inheritance DAG:** A directed acyclic graph specifying which successor agents inherit which capabilities from the terminating agent's manifest (PAD-020). Inheritance is constrained: successors can only receive capabilities that the terminating agent held, and each capability can be inherited by exactly one successor (no duplication).

5. **Forensic State Sealing:** Upon mortality activation, the agent's operational state  -  action logs, reasoning traces (PAD-017), heartbeat history (PAD-016), capability exercise records (PAD-020)  -  is cryptographically sealed with a notarized timestamp, creating a tamper-evident archive for post-mortem analysis, regulatory compliance, or dispute resolution.

6. **Graceful Delegation Unwinding:** When a terminating agent has active delegation chains (PAD-002), the mortality protocol systematically revokes all delegated authorities, notifies affected sub-agents, and records the delegation dissolution in the provenance registry.

Key innovations:
- **Pre-committed termination prevents orphaned identities**  -  a dead agent's keys are revoked automatically, closing the window for credential theft from decommissioned systems.
- **Capability inheritance preserves operational continuity**  -  critical capabilities transfer to designated successors without service disruption, while the original agent's identity is permanently retired.
- **Forensic sealing creates a legal-grade record**  -  the sealed state archive satisfies regulatory requirements for audit trail preservation after entity dissolution (SOX, HIPAA, GDPR data processing records).
- **No existing system combines all six mechanisms** into a unified identity termination protocol for autonomous agents.

---

## 2. Problem Statement

### 2.1 Orphaned Identities Are Attack Surfaces

When an agent permanently stops operating  -  due to decommissioning, operator bankruptcy, key compromise, or infrastructure failure  -  its identity assets remain:

| Asset | Status After Death | Risk |
|-------|-------------------|------|
| Ed25519 private key | On disk, unrevoked | Credential theft → impersonation |
| DID document | Published, resolves normally | Verifiers accept signatures from stolen key |
| Capability manifest | Valid, capabilities not decayed | Stolen key exercises agent's full capabilities |
| Delegation authorities | Active, sub-agents still operating | Sub-agents operate under dead authority |
| `vouch.json` | Published, discoverable | Attackers discover and clone identity |

An orphaned identity is a perfect impersonation target: the original operator is not monitoring for misuse, the credentials are technically valid, and the attack may go undetected indefinitely.

### 2.2 No Protocol for Orderly Identity Death

Existing identity systems handle creation and ongoing management but not permanent termination:

| System | Identity Creation | Renewal/Rotation | Permanent Termination |
|--------|------------------|-------------------|-----------------------|
| X.509 PKI | Certificate issuance | Renewal, re-keying | CRL/OCSP (but relies on CA availability) |
| OAuth2 | Client registration | Token refresh | Client deletion (manual, no automation) |
| PAD-016 (Heartbeat) | Session voucher issuance | Periodic heartbeat renewal | Credential denial (temporary, not permanent) |
| DID Methods | DID creation | Key rotation | Deactivation (method-dependent, often manual) |
| **This disclosure** | **N/A (builds on PAD-001)** | **N/A (builds on PAD-016)** | **Automated, pre-committed, orderly termination** |

### 2.3 Operator Death Scenario

When a human operator dies, their AI agents continue operating until credentials expire (if they expire at all). In the absence of a termination protocol:
- Agents may continue executing actions without oversight.
- Agent private keys remain accessible on the operator's devices.
- No one knows which agents the operator controlled, what capabilities they held, or which sub-agents they delegated to.
- Regulatory requirements for data preservation may be violated when infrastructure is eventually decommissioned.

### 2.4 Corporate Shutdown Scenario

When a company shuts down:
- Hundreds or thousands of agent identities become orphaned simultaneously.
- Domain names expire, breaking `did:web` resolution.
- Infrastructure goes offline, but published credentials remain valid.
- Customer data processing records must be preserved for regulatory compliance, but the infrastructure to access them disappears.

### 2.5 Key Compromise Scenario

When an agent's private key is known to be compromised:
- The operator may not be available to manually revoke the key.
- If the operator is the attacker (insider threat), they will not voluntarily revoke.
- Pre-committed revocation certificates enable automated revocation without requiring the operator's cooperation.

---

## 3. Solution (The Invention)

### 3.1 Mortality Escrow

At identity creation time (or at any point during the agent's lifecycle), the operator deposits encrypted termination instructions with an independent escrow service.

**Termination Instructions Structure:**

```json
{
  "mortality_id": "mort-2026-04-22-a7f3",
  "agent_did": "did:vouch:z6MkAgent123",
  "deposited_at": "2026-04-22T10:00:00Z",
  "deposited_by": "did:vouch:z6MkOperator456",
  "mortality_horizon_seconds": 604800,
  "instructions": {
    "revocation": {
      "pre_signed_revocation_cert": "ed25519_signed_revocation_hex",
      "revocation_registries": ["https://revoke.vouch-protocol.com/v1"],
      "publish_to_did_document": true
    },
    "capability_inheritance": {
      "successors": [
        {
          "successor_did": "did:vouch:z6MkSuccessor789",
          "capabilities_to_inherit": ["cap-001", "cap-003"],
          "conditions": {
            "require_successor_acceptance": true,
            "max_inheritance_delay_seconds": 86400
          }
        }
      ],
      "unassigned_capabilities": "revoke"
    },
    "delegation_unwinding": {
      "active_delegations": ["deleg-001", "deleg-002", "deleg-003"],
      "unwinding_order": "leaves_first",
      "notification_method": "glass_channel"
    },
    "forensic_sealing": {
      "state_to_seal": [
        "action_logs",
        "reasoning_traces",
        "heartbeat_history",
        "capability_exercise_records",
        "delegation_chain_snapshots"
      ],
      "seal_encryption": "AES-256-GCM",
      "seal_recipients": [
        "did:vouch:z6MkLegalCounsel",
        "did:vouch:z6MkRegulator"
      ],
      "retention_period_days": 2555
    },
    "notifications": {
      "notify_on_mortality": [
        { "did": "did:vouch:z6MkCTO", "method": "webhook" },
        { "did": "did:vouch:z6MkLegal", "method": "email" }
      ]
    }
  },
  "escrow_encryption": {
    "method": "time_locked",
    "unlock_condition": "liveness_proof_absence",
    "unlock_after_missed_proofs": 3
  },
  "operator_signature": "ed25519:operator_signs_instructions"
}
```

### 3.2 Dead-Man's-Switch Liveness

The agent must submit periodic liveness proofs to the escrow service. These proofs are distinct from PAD-016 heartbeats (which govern credential renewal with the main Vouch service). Mortality liveness proofs govern the irrevocable termination sequence.

**Liveness Proof Protocol:**

```
Agent                        Mortality Escrow
  |                                |
  |-- Liveness proof ------------->|  (every mortality_horizon / 3)
  |   (signed timestamp +         |
  |    agent_did + nonce)          |
  |                                |
  |<-- Ack + countdown reset ------|
  |                                |
  |   ... time passes ...         |
  |                                |
  |   [Agent fails to submit       |
  |    liveness proof for          |
  |    mortality_horizon seconds]  |
  |                                |
  |                         [Escrow initiates
  |                          MORTALITY SEQUENCE]
  |                                |
  |                         [1. Decrypt instructions]
  |                         [2. Publish revocation cert]
  |                         [3. Execute capability inheritance]
  |                         [4. Unwind delegations]
  |                         [5. Seal forensic state]
  |                         [6. Send notifications]
```

**Liveness Proof Structure:**

```json
{
  "proof_type": "mortality_liveness",
  "agent_did": "did:vouch:z6MkAgent123",
  "mortality_id": "mort-2026-04-22-a7f3",
  "timestamp": "2026-04-22T16:00:00Z",
  "nonce": "random_32_byte_hex",
  "proof_signature": "ed25519:agent_signs_timestamp_and_nonce"
}
```

**Mortality Horizon Configuration:**

| Agent Type | Recommended Horizon | Rationale |
|-----------|-------------------|-----------|
| Production enterprise agent | 7 days | Allows for weekend/holiday outages |
| Personal agent | 30 days | Allows for extended travel/downtime |
| Critical infrastructure agent | 24 hours | Minimal orphan window |
| Test/development agent | 72 hours | Quick cleanup of abandoned test agents |

### 3.3 Pre-Committed Revocation Certificates

At identity creation time, the agent generates a signed revocation certificate and deposits it in escrow. This certificate declare's the agent's own key as revoked.

**Why Pre-Commitment Is Critical:**

```
Scenario: Agent key is compromised by insider threat.
  |
  +-- WITHOUT pre-committed revocation:
  |     Operator (the insider) controls the key and refuses to revoke.
  |     No one else can generate a valid revocation for this key.
  |     Agent identity remains valid indefinitely.
  |
  +-- WITH pre-committed revocation:
        Mortality escrow holds a valid revocation certificate
        signed by the agent's own key (before compromise).
        If liveness proofs stop (because the insider stops operating
        the agent through normal channels), the escrow publishes
        the pre-committed revocation automatically.
        No cooperation from the insider is required.
```

**Revocation Certificate Structure:**

```json
{
  "type": "vouch_revocation_v1",
  "subject_did": "did:vouch:z6MkAgent123",
  "revocation_reason": "mortality_protocol_activation",
  "effective_at": "TO_BE_SET_BY_ESCROW",
  "pre_signed_at": "2026-04-22T10:00:00Z",
  "revoked_key": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "base64url_public_key"
  },
  "subject_signature": "ed25519:agent_signs_own_revocation"
}
```

The `effective_at` field is set by the escrow at activation time. The certificate is signed by the agent's key at creation time, proving the agent consented to revocation under the mortality protocol.

### 3.4 Capability Inheritance DAG

When an agent terminates, its capabilities can be inherited by designated successors rather than simply revoked. This preserves operational continuity for critical workflows.

**Inheritance Rules:**

1. **No capability duplication:** Each capability can be inherited by exactly one successor. If capability `cap-001` is assigned to Successor A, it cannot also be assigned to Successor B.
2. **No capability escalation:** Successors can only inherit capabilities the terminating agent held. The inheritance DAG cannot create new capabilities.
3. **Successor acceptance required:** Inheritance is not forced. The designated successor must cryptographically accept the capability transfer by signing an acceptance message.
4. **Time-bounded acceptance:** Successors have a configurable window (default 24 hours) to accept inherited capabilities. Unaccepted capabilities are revoked.
5. **Unassigned capabilities are revoked:** Any capabilities not assigned to a successor are automatically revoked.

**Inheritance DAG Example:**

```
Terminating Agent (did:vouch:z6MkAgent123)
  |
  |-- cap-001 (database:read) ──────> Successor A (did:vouch:z6MkSuccessorA)
  |
  |-- cap-002 (email:send) ─────────> Successor B (did:vouch:z6MkSuccessorB)
  |
  |-- cap-003 (filesystem:read) ────> Successor A (did:vouch:z6MkSuccessorA)
  |
  |-- cap-004 (admin:access) ───────> [UNASSIGNED → REVOKED]
```

**Acceptance Protocol:**

```
Mortality Escrow              Successor Agent
      |                              |
      |-- Inheritance offer -------->|
      |   (capability details,       |
      |    acceptance deadline,       |
      |    mortality certificate)     |
      |                              |
      |                       [Successor evaluates:
      |                        - Do I want this capability?
      |                        - Is the source legitimate?
      |                        - Do I have compatible constraints?]
      |                              |
      |<-- Acceptance (signed) ------|
      |   OR                         |
      |<-- Rejection (signed) -------|
      |                              |
      [Update successor's capability
       manifest with inherited caps,
       new manifest signed by
       escrow's authority key]
```

### 3.5 Forensic State Sealing

Upon mortality activation, the agent's complete operational state is cryptographically sealed into a tamper-evident archive.

**Sealed State Structure:**

```json
{
  "seal_id": "seal-2026-04-22-a7f3",
  "agent_did": "did:vouch:z6MkAgent123",
  "sealed_at": "2026-04-29T10:00:00Z",
  "mortality_id": "mort-2026-04-22-a7f3",
  "contents": {
    "action_log_hash": "sha256:H(complete_action_log)",
    "action_log_entry_count": 47832,
    "reasoning_trace_hash": "sha256:H(all_reasoning_merkle_roots)",
    "heartbeat_history_hash": "sha256:H(heartbeat_log)",
    "capability_manifest_final": { "manifest_hash": "sha256:..." },
    "delegation_chain_snapshot": { "chain_hash": "sha256:..." }
  },
  "encryption": {
    "method": "AES-256-GCM",
    "key_distribution": "encrypted_to_recipient_public_keys",
    "recipients": [
      { "did": "did:vouch:z6MkLegalCounsel", "encrypted_key": "..." },
      { "did": "did:vouch:z6MkRegulator", "encrypted_key": "..." }
    ]
  },
  "notarization": {
    "timestamp_authority": "rfc3161:https://timestamp.vouch-protocol.com",
    "timestamp_token": "base64_encoded_rfc3161_token",
    "notarized_hash": "sha256:H(seal_contents)"
  },
  "retention_policy": {
    "minimum_retention_days": 2555,
    "deletion_after_retention": true,
    "retention_authority": "did:vouch:z6MkLegalCounsel"
  }
}
```

**Properties:**
- **Tamper-evident:** The RFC 3161 notarized timestamp proves the seal was created at a specific time. Any modification after sealing invalidates the timestamp token.
- **Access-controlled:** The sealed archive is encrypted to designated recipients' public keys. Only those recipients can decrypt and access the archived state.
- **Retention-compliant:** The retention period satisfies common regulatory requirements (7 years for SOX, HIPAA, many GDPR data processing contexts).

### 3.6 Graceful Delegation Unwinding

When a terminating agent has active delegation chains (PAD-002), the mortality protocol systematically dissolves them.

**Unwinding Order:**

```
Leaves-first (default):
  Revoke sub-sub-agents → revoke sub-agents → revoke agent

    Agent (TERMINATING)
      |
      +-- Sub-Agent A
      |     |
      |     +-- Sub-Sub-Agent A1  ← Revoked first
      |     +-- Sub-Sub-Agent A2  ← Revoked first
      |     |
      |     ← Sub-Agent A revoked second
      |
      +-- Sub-Agent B
            |
            +-- Sub-Sub-Agent B1  ← Revoked first
            |
            ← Sub-Agent B revoked second
```

Each revoked sub-agent receives a notification via PAD-019 Glass Channel:

```json
{
  "notification_type": "delegation_revocation",
  "reason": "delegator_mortality_protocol_activated",
  "original_delegator": "did:vouch:z6MkAgent123",
  "revocation_effective_at": "2026-04-29T10:05:00Z",
  "action_required": "cease_operations_or_obtain_new_delegation"
}
```

---

## 4. Prior Art Differentiation

| System | Key Revocation | Capability Transfer | Forensic Sealing | Dead-Man's-Switch | Delegation Unwinding |
|--------|---------------|--------------------|--------------------|-------------------|---------------------|
| X.509 CRL/OCSP | Manual CA-issued | No | No | No | No |
| PGP Key Revocation | Manual, requires key access | No | No | No | No |
| DID Deactivation | Method-dependent, manual | No | No | No | No |
| DNS Expiry | Automatic but uncontrolled | No | No | No | No |
| Ethereum Smart Contract Suicide | `selfdestruct` opcode | ETH transfer to designated address | On-chain state preserved | No (requires tx) | No |
| **This disclosure** | **Pre-committed, automatic** | **DAG-based inheritance** | **RFC 3161 notarized, encrypted** | **Yes (liveness proofs)** | **Yes (leaves-first)** |

Key differentiators:
1. **No existing system** provides pre-committed, self-signed revocation certificates that activate automatically upon liveness proof absence  -  enabling revocation without requiring the key holder's cooperation at revocation time.
2. **No existing system** implements capability inheritance with acceptance semantics, uniqueness constraints, and time-bounded acceptance windows for AI agent identity termination.
3. **No existing system** combines identity revocation, capability transfer, forensic state sealing, and delegation chain dissolution into a single, pre-committed, automatically-triggered mortality protocol.
4. **No existing system** provides RFC 3161 notarized forensic state archives that are encrypted to designated recipients and created automatically upon agent identity termination.

---

## 5. Technical Implementation

### 5.1 Escrow Data Model

```
Key: mortality:{mortality_id}  -  Hash (agent_did, deposited_at, horizon, status)
Key: mortality:{mortality_id}:instructions  -  Encrypted blob (AES-256-GCM, time-locked)
Key: mortality:{mortality_id}:liveness  -  Sorted Set (score = timestamp, value = liveness proof)
Key: mortality:{mortality_id}:revocation_cert  -  Pre-signed revocation certificate
Key: mortality:{mortality_id}:inheritance_dag  -  JSON DAG of capability assignments
Key: mortality:{mortality_id}:seal  -  Sealed forensic state archive
Key: mortality:agent_index:{agent_did}  -  Set of mortality_ids for this agent
```

### 5.2 Mortality State Machine

```
                    ACTIVE
                      |
          [Liveness proofs arriving regularly]
                      |
          [Liveness proof missed × 1]
                      |
                   WARNING
                      |
          [Liveness proof missed × 2]
                      |
                   CRITICAL
                      |
          [Liveness proof missed × 3 (mortality_horizon exceeded)]
                      |
                  ACTIVATING
                      |
          [Execute termination sequence]
          [1. Publish revocation cert]
          [2. Execute capability inheritance]
          [3. Unwind delegations]
          [4. Seal forensic state]
          [5. Send notifications]
                      |
                  TERMINATED
                   (final)
```

At any point before TERMINATED, a valid liveness proof resets the state to ACTIVE.

### 5.3 Liveness Proof Verification

```
Input: Signed liveness proof from agent
  |
  1. Verify Ed25519 signature against agent's registered public key
  2. Verify agent_did matches the mortality escrow's registered agent
  3. Verify nonce has not been seen before (replay prevention)
  4. Verify timestamp is within acceptable drift (±60 seconds)
  5. Reset mortality countdown to mortality_horizon
  6. Store proof in liveness log
```

---

## 6. Use Cases

### 6.1 Operator Death

A solo developer operates three AI agents for their SaaS product. They deposit mortality instructions designating a trusted colleague as successor. When the developer dies, liveness proofs stop within 30 days, the mortality protocol activates, capabilities transfer to the colleague's agents, keys are revoked, and audit trails are sealed for the estate.

### 6.2 Corporate Wind-Down

A company shutting down deposits mortality instructions for all 500 agent identities with a 90-day horizon. During wind-down, agents continue normal operation. When infrastructure is decommissioned, liveness proofs stop, and the mortality protocol systematically revokes all identities, seals all audit trails for regulatory retention, and notifies affected service providers.

### 6.3 Key Compromise Response

An agent's key is compromised but the operator is unavailable (traveling, incapacitated). The agent cannot submit liveness proofs because the attacker has taken control. After the mortality horizon (24 hours for critical agents), the escrow publishes the pre-committed revocation certificate, invalidating the compromised key without requiring the operator's intervention.

### 6.4 Agent Migration

An organization migrates from one AI infrastructure to another. They designate the new agents as successors in the mortality instructions, decommission the old infrastructure, and let the mortality protocol automatically transfer capabilities and revoke old identities on the configured schedule.

---

## 7. Claims Summary

The following aspects are disclosed as prior art:

1. A mortality escrow system for AI agent identities where pre-committed termination instructions (key revocation, capability inheritance, forensic sealing, delegation unwinding) are deposited in encrypted form and activate automatically when the agent fails to submit cryptographic liveness proofs within a configurable mortality horizon.

2. Pre-committed, self-signed revocation certificates generated at identity creation time and held in escrow, enabling automatic key revocation upon mortality activation without requiring the key holder's cooperation or access to the private key at revocation time.

3. A capability inheritance DAG that transfers specific capabilities from a terminating agent to designated successor agents, with acceptance semantics (successors must cryptographically accept), uniqueness constraints (each capability inherited by exactly one successor), and time-bounded acceptance windows.

4. A forensic state sealing mechanism that creates an RFC 3161 notarized, AES-256-GCM encrypted archive of the terminating agent's complete operational state (action logs, reasoning traces, heartbeat history, capability records, delegation snapshots), encrypted to designated recipients and retained for regulatory compliance.

5. A graceful delegation unwinding protocol that systematically revokes all delegated authorities in leaves-first order, notifying affected sub-agents via transparent channels and recording the dissolution in the provenance registry.

6. A dead-man's-switch liveness protocol distinct from operational heartbeats (PAD-016), governing permanent identity termination rather than temporary credential denial, with a state machine that progresses through WARNING → CRITICAL → ACTIVATING → TERMINATED, resettable at any non-terminal state by a valid liveness proof.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch

---

## Update (April 27, 2026): JCS Canonicalization Strengthens Determinism

The Cryptographic Mortality Protocol described above detects agent
death, substitution, or hijack via canary commitments and revealed-secret
continuity. The novel mortality-detection mechanism is independent of
the specific serialization format of the canary commitment messages.

This update discloses that when canary commitment messages and the
heartbeat envelope they accompany are JCS-canonicalized (RFC 8785)
prior to signing, the mortality-detection property gains a determinism
guarantee:

- A substituted agent attempting to forge a continuity-preserving
  canary chain must produce canonically-equivalent commitment messages
  whose byte representation is byte-identical to those a legitimate
  agent would produce. The byte-identical requirement is enforced
  across independent verifiers without trusting a specific serializer.
- A cross-implementation verifier set (Python, TypeScript, Go reference
  implementations) reaches unanimous agreement on whether a canary
  reveal-and-commit pair is valid, eliminating false positives arising
  from serialization differences.
- The forensic property of the protocol, that a broken canary chain is
  cryptographic evidence of substitution, is reproducible by any third
  party who can verify the JCS canonical form, expanding the protocol's
  use in regulated audit and post-incident review contexts.

The originally-claimed Cryptographic Mortality mechanism remains the
disclosed claim. JCS canonicalization is disclosed as a strengthening
implementation property that enables federated mortality detection
without a trusted central serializer.
