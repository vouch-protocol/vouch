# PAD-030: Zero-Knowledge Reputation Portability for Autonomous Agents

**Identifier:** PAD-030
**Title:** Method for Privacy-Preserving Cross-Platform Reputation Transfer Using Zero-Knowledge Proofs Bound to Decentralized Identifiers
**Publication Date:** April 22, 2026
**Prior Art Effective Date:** April 22, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Reputation Systems / Zero-Knowledge Proofs / Decentralized Identity / Agent Trust / Privacy
**Author:** Ramprasad Anandam Gaddam
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-016 (Dynamic Credential Renewal), PAD-017 (Cryptographic Proof of Reasoning), PAD-020 (Ratchet Lock Protocol)

---

## 1. Abstract

A system and method for enabling AI agents to prove quantitative reputation claims to new service providers without revealing their identity, action history, or the services they previously interacted with. The protocol addresses the **cold-start trust problem** in multi-platform agent ecosystems: when an agent with an established track record on Platform A first connects to Platform B, it currently begins with zero reputation - despite potentially thousands of verified, safe, and successful interactions elsewhere.

The system introduces several interlocking mechanisms:

1. **Reputation Accumulators:** Each service provider issues blind reputation endorsements - cryptographic attestations of agent behavior (actions completed, safety violations, uptime, reasoning quality) that the agent accumulates in a Pedersen commitment-based accumulator without revealing which service issued them.

2. **ZK Threshold Proofs:** The agent generates zero-knowledge proofs that its accumulated reputation satisfies specific thresholds (e.g., "I have completed ≥10,000 actions with zero safety violations") without revealing the exact count, the specific actions, or the issuing services.

3. **Unlinkable Presentation:** Each proof is generated with a fresh blinding factor, ensuring that two services receiving proofs from the same agent cannot correlate them to determine they are interacting with the same entity - unless the agent explicitly reveals its DID.

4. **Reputation Decay Integration:** Proofs include a freshness parameter derived from PAD-016 heartbeat timestamps, ensuring that stale reputation (from an agent that was once trustworthy but has since drifted) cannot be presented as current.

5. **Selective Disclosure of Reputation Dimensions:** Rather than a single "trust score," the system supports multi-dimensional reputation (safety, accuracy, latency, compliance) with independent ZK proofs per dimension, allowing agents to prove competence in specific areas without revealing overall profiles.

Key innovations:
- **No central reputation authority:** Reputation is accumulated from multiple independent services, no single entity controls or can revoke reputation.
- **Correlation resistance:** Services cannot determine whether two agents presenting proofs are the same entity, preventing cross-platform tracking.
- **Composable trust bootstrapping:** An agent can combine endorsements from multiple platforms into a single proof, creating compound trust that exceeds what any single platform could attest.
- **Sybil resistance:** Proofs are bound to DID-controlled accumulators that require Ed25519 signatures to update, preventing an agent from creating multiple accumulators to cherry-pick favorable reputation.

---

## 2. Problem Statement

### 2.1 The Cold-Start Trust Problem

When an AI agent first connects to a new service, the service has no information about the agent's history. Current approaches:

| Approach | Limitation |
|----------|-----------|
| Start at zero trust | Punishes well-behaved agents; no incentive for good behavior across platforms |
| Require identity disclosure | Agent reveals its DID, enabling cross-platform tracking and surveillance |
| Centralized reputation service | Single point of failure; reputation authority has surveillance power over all agents |
| Platform-specific trust scores | Non-portable; no interoperability between services |

No existing system allows an agent to bootstrap trust on a new platform using reputation earned elsewhere, without revealing which platforms it previously used or linking its identities across platforms.

### 2.2 The Cross-Platform Tracking Risk

If an agent presents the same reputation credential to multiple services, those services can collude to track the agent across platforms:

```
Service A: "Agent X has reputation score 9.5"
Service B: "Agent X has reputation score 9.5"
Collusion: "Agent X uses both Service A and Service B"
```

This tracking capability is a privacy violation that discourages agents (and their operators) from presenting reputation credentials at all. The result is a chilling effect where good reputation cannot be leveraged.

### 2.3 The Sybil Reputation Problem

Without proper binding to identity, an agent could:
- Create multiple reputation accumulators, accumulate only positive endorsements in each
- Discard accumulators that contain negative endorsements
- Present only the cherry-picked favorable accumulator to new services

Any ZK reputation system must prevent accumulator proliferation while maintaining privacy.

### 2.4 The Stale Reputation Problem

An agent that earned excellent reputation 6 months ago but has since been compromised, drifted, or degraded should not be able to present that historical reputation as current. Reputation proofs must include a freshness guarantee tied to ongoing behavioral monitoring.

### 2.5 Existing Approaches Are Insufficient

| System | Privacy | Portability | Sybil Resistance | Freshness |
|--------|---------|-------------|-------------------|-----------|
| OAuth2 scopes | No (identity revealed) | No (platform-specific) | Yes (identity-bound) | No |
| Verifiable Credentials (W3C) | Partial (selective disclosure) | Yes | Yes | Issuer-dependent |
| On-chain reputation (EigenTrust) | No (public ledger) | Yes | Partial | No decay model |
| Platform trust scores (Uber, Airbnb) | No (centralized) | No | Yes | Platform-dependent |
| **This disclosure** | **Yes (ZK proofs)** | **Yes (cross-platform)** | **Yes (DID-bound)** | **Yes (heartbeat-linked)** |

---

## 3. Solution (The Invention)

### 3.1 Reputation Accumulator

Each agent maintains a single reputation accumulator - a cryptographic data structure that aggregates endorsements from multiple services without revealing individual endorsements.

The accumulator is based on Pedersen commitments over an elliptic curve:

```
Accumulator State = Commit(r₁) · Commit(r₂) · ... · Commit(rₙ)

Where:
 rᵢ = reputation value from endorsement i
 Commit(rᵢ) = rᵢ · G + bᵢ · H (Pedersen commitment)
 G, H = generator points on Curve25519
 bᵢ = blinding factor (random, known only to agent)
```

**Properties:**
- **Homomorphic:** The product of individual commitments commits to the sum of reputation values. The agent can prove properties of the sum without revealing individual endorsements.
- **Hiding:** Given the accumulator state, no observer can determine the individual endorsement values.
- **Binding:** The agent cannot change the committed values after accumulation (computationally binding under the discrete log assumption).

**Accumulator Structure:**

```json
{
 "accumulator_id": "acc-did:vouch:agent123",
 "did": "did:vouch:agent123",
 "dimensions": {
  "safety": {
   "commitment": "curve25519_point_hex",
   "endorsement_count": 4207,
   "last_updated": "2026-04-22T10:00:00Z"
  },
  "accuracy": {
   "commitment": "curve25519_point_hex",
   "endorsement_count": 3891,
   "last_updated": "2026-04-22T09:55:00Z"
  },
  "compliance": {
   "commitment": "curve25519_point_hex",
   "endorsement_count": 2104,
   "last_updated": "2026-04-22T09:30:00Z"
  }
 },
 "freshness_proof": {
  "heartbeat_ref": "hb-2026-04-22-09:59:45",
  "heartbeat_signature": "ed25519:...",
  "max_age_seconds": 3600
 },
 "accumulator_signature": "ed25519:agent_signs_current_state"
}
```

### 3.2 Blind Reputation Endorsements

Service providers issue endorsements that the agent can incorporate into its accumulator without the service learning the accumulator's current state or total reputation.

**Endorsement Protocol:**

```
Agent            Service Provider
 |                |
 |-- 1. Request endorsement ----->|
 |  (present Vouch-Token,    |
 |  prove DID ownership)    |
 |                |
 |             [2. Service evaluates agent's
 |             behavior during session:
 |             - Actions completed: 47
 |             - Safety violations: 0
 |             - Reasoning quality: 0.92
 |             - Compliance score: 1.0]
 |                |
 |<-- 3. Blind endorsement -------|
 |  (signed reputation vector  |
 |  with service's Ed25519 key, |
 |  blinded so agent cannot   |
 |  selectively discard)    |
 |                |
 [4. Agent incorporates endorsement
  into accumulator using homomorphic
  addition of Pedersen commitments]
```

**Blind Endorsement Structure:**

```json
{
 "endorsement_id": "end-svc-a-2026-04-22-001",
 "issuer_did": "did:vouch:service-a",
 "epoch": "2026-04-22T00:00:00Z",
 "dimensions": {
  "safety": { "value_commitment": "pedersen_commit_hex", "range_proof": "bulletproof_hex" },
  "accuracy": { "value_commitment": "pedersen_commit_hex", "range_proof": "bulletproof_hex" },
  "compliance": { "value_commitment": "pedersen_commit_hex", "range_proof": "bulletproof_hex" }
 },
 "issuer_signature": "ed25519:service_signs_endorsement",
 "binding_nonce": "sha256:H(agent_did || epoch || issuer_did)"
}
```

The `binding_nonce` cryptographically binds the endorsement to the specific agent and epoch, preventing endorsement transfer between agents.

### 3.3 ZK Threshold Proofs

The agent generates zero-knowledge proofs that its accumulated reputation satisfies threshold predicates without revealing the exact values.

**Supported Predicates:**

| Predicate | Example | ZK Proof Type |
|-----------|---------|---------------|
| Greater-than-or-equal | "safety ≥ 10,000" | Bulletproof range proof |
| Inequality | "safety_violations = 0" | Equality proof on commitment |
| Ratio | "accuracy ≥ 0.95" | Division proof on commitments |
| Recency | "last endorsement ≤ 1 hour ago" | Timestamp range proof |
| Multi-dimensional | "safety ≥ 10K AND accuracy ≥ 0.9" | Composition of individual proofs |

**Proof Generation:**

```
Input:
 - Agent's accumulator state (commitments + blinding factors)
 - Threshold predicate (e.g., "safety ≥ 10,000")
 - Fresh blinding factor for unlinkability

Output:
 - ZK proof π that the committed value satisfies the predicate
 - Fresh pseudonym (unlinkable to agent's DID)
 - Freshness certificate (linked to latest heartbeat)

Verification:
 - Verifier checks π against the commitment
 - Verifier checks freshness certificate is recent
 - Verifier learns ONLY that the predicate is satisfied
 - Verifier learns NOTHING about the exact value, the agent's DID,
  or which services issued endorsements
```

**Proof Structure:**

```json
{
 "proof_type": "zk_reputation_threshold",
 "predicate": {
  "dimension": "safety",
  "operator": "gte",
  "threshold": 10000
 },
 "proof": "bulletproof_hex_encoding",
 "pseudonym": "curve25519_point_derived_from_fresh_blinding",
 "freshness": {
  "heartbeat_timestamp": "2026-04-22T09:59:45Z",
  "heartbeat_proof": "ed25519_signature_over_timestamp",
  "max_staleness_seconds": 3600
 },
 "accumulator_epoch": "2026-04-22T00:00:00Z"
}
```

### 3.4 Unlinkable Presentation

Each time the agent presents a reputation proof to a new service, it generates a **fresh pseudonym** using a new blinding factor:

```
Pseudonym_i = DID_commitment · r_i · H

Where:
 DID_commitment = fixed Pedersen commitment to agent's DID
 r_i = fresh random scalar for presentation i
 H = second generator point
```

**Properties:**
- **Unlinkability:** Two services receiving Pseudonym_1 and Pseudonym_2 cannot determine whether they originated from the same agent (decisional Diffie-Hellman assumption).
- **Self-binding:** The agent can later prove (by revealing r_i) that a pseudonym belongs to its DID, enabling voluntary de-anonymization for dispute resolution.
- **One-show per service:** Using a deterministic derivation with the service's DID as input (`r_i = PRF(agent_secret, service_did)`), the agent always presents the same pseudonym to the same service, preventing double-counting.

### 3.5 Sybil Resistance via DID Binding

The accumulator is cryptographically bound to the agent's DID, preventing accumulator proliferation:

1. **Single accumulator per DID:** The accumulator ID is derived deterministically from the DID: `accumulator_id = SHA-256(did || "reputation_accumulator_v1")`.
2. **Endorsement binding:** Each endorsement includes `binding_nonce = SHA-256(agent_did || epoch || issuer_did)`, ensuring endorsements cannot be transferred between agents.
3. **Accumulator registration:** When an agent first creates its accumulator, it registers the accumulator ID with the Vouch Protocol registry. Subsequent accumulators from the same DID are rejected.
4. **Negative endorsements are mandatory:** Services issue endorsements for every epoch of interaction, including negative outcomes. An agent cannot selectively incorporate only positive endorsements because the accumulator update requires the service's signature, and the service signs the complete behavioral assessment - not just the favorable parts.

### 3.6 Freshness via Heartbeat Integration

Reputation proofs include a freshness certificate derived from PAD-016's heartbeat protocol:

```
Freshness Certificate:
 - heartbeat_timestamp: Latest heartbeat renewal time
 - heartbeat_signature: PAD-016 heartbeat service's Ed25519 signature
 - max_staleness: Maximum age (in seconds) for the proof to be valid

Verification:
 1. Check heartbeat_signature is valid (from known heartbeat service)
 2. Check (current_time - heartbeat_timestamp) ≤ max_staleness
 3. If stale, reject the reputation proof regardless of the ZK proof's validity
```

This ensures that an agent whose credentials have been denied (PAD-016 heartbeat denial) or whose behavior has drifted cannot present historical reputation as current.

---

## 4. Prior Art Differentiation

| System | ZK Privacy | Cross-Platform | Agent-Specific | Multi-Dimensional | Freshness |
|--------|-----------|---------------|----------------|-------------------|-----------|
| Verifiable Credentials | Selective disclosure only | Yes | No | No | Issuer-dependent |
| EigenTrust (P2P) | No (public scores) | Yes | No | Single score | No |
| Semaphore (Ethereum) | Group membership proofs | No | No | No | No |
| IRMA/Yivi | Attribute-based ZK | Partial | No | Attribute-based | Issuer-dependent |
| Uber/Airbnb ratings | No | No | No | Single score | Platform-dependent |
| **This disclosure** | **Full ZK threshold proofs** | **Yes** | **Yes (DID-bound)** | **Yes (per-dimension)** | **Yes (heartbeat-linked)** |

Key differentiators:
1. **No existing system** provides zero-knowledge proofs of agent-specific reputation metrics (safety violations, reasoning quality, capability compliance) across multiple independent platforms.
2. **No existing system** combines Pedersen commitment accumulators with Bulletproof range proofs for multi-dimensional agent reputation.
3. **No existing system** links reputation proof freshness to a behavioral heartbeat protocol, ensuring stale reputation from drifted agents is automatically invalidated.
4. **No existing system** provides unlinkable reputation presentation where the same agent can prove reputation to multiple services without those services being able to correlate the presentations.

---

## 5. Technical Implementation

### 5.1 Cryptographic Primitives

| Primitive | Purpose | Specification |
|-----------|---------|---------------|
| Pedersen Commitment | Reputation value hiding + binding | Curve25519, two independent generators G, H |
| Bulletproofs | Range proofs for threshold predicates | Aggregated logarithmic-size proofs |
| Ed25519 | Endorsement and accumulator signatures | RFC 8032 |
| SHA-256 | Accumulator ID derivation, binding nonces | FIPS 180-4 |
| PRF (HMAC-SHA-256) | Deterministic pseudonym derivation per service | RFC 2104 |

### 5.2 Proof Sizes

| Proof Type | Size | Verification Time |
|-----------|------|-------------------|
| Single threshold (e.g., safety ≥ 10K) | ~700 bytes | ~3ms |
| Multi-dimensional (3 dimensions) | ~2.1KB | ~9ms |
| With freshness certificate | +256 bytes | +1ms |
| **Total (typical presentation)** | **~2.4KB** | **~10ms** |

### 5.3 Data Model

```
Key: reputation:{did}:accumulator - Hash (dimension → commitment)
Key: reputation:{did}:endorsements - Sorted Set (score = epoch, value = endorsement_id)
Key: reputation:endorsement:{id} - Hash (issuer, dimensions, signature, binding_nonce)
Key: reputation:{did}:freshness - Hash (heartbeat_ref, heartbeat_sig, timestamp)
```

### 5.4 Trust Bootstrapping Flow

When an agent first connects to a new service:

```
Agent             New Service
 |                |
 |-- 1. Present ZK reputation --->|
 |  proof with pseudonym     |
 |                |
 |             [2. Service verifies:
 |             - ZK proof is valid
 |             - Freshness is current
 |             - Threshold meets policy]
 |                |
 |<-- 3. Grant elevated trust ----|
 |  (skip probation period,   |
 |  higher rate limits,     |
 |  access to premium APIs)   |
 |                |
 [Agent operates with bootstrapped
  trust, earns new endorsements
  from this service over time]
```

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A system for AI agent reputation portability using Pedersen commitment-based accumulators that aggregate blind endorsements from multiple independent service providers, where the accumulated reputation can be proven via zero-knowledge threshold proofs without revealing the agent's identity, specific actions, or issuing services.

2. A method for unlinkable reputation presentation where each proof is generated with a fresh blinding factor, preventing cross-platform correlation of agent identity by colluding service providers.

3. A multi-dimensional reputation model where independent ZK proofs can attest to separate behavioral dimensions (safety, accuracy, compliance, reasoning quality) without revealing the agent's overall reputation profile.

4. A freshness mechanism that links reputation proof validity to PAD-016 heartbeat timestamps, ensuring that agents whose behavioral credentials have lapsed cannot present historical reputation as current.

5. A Sybil-resistant accumulator design where the accumulator ID is deterministically derived from the agent's DID, endorsements are cryptographically bound to both agent and epoch, and services issue complete behavioral assessments (including negative outcomes) rather than selective endorsements.

6. A composable trust bootstrapping protocol where an agent combines endorsements from multiple platforms into compound proofs that enable elevated trust on new platforms without a cold-start probation period.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch
