# PAD-036: Aggregated Reputation Scoring via Verifiable State Receipts

**Identifier:** PAD-036  
**Title:** Method for Centralized Trust Discovery via Dual-Verified State Receipts and Adversarial-Resistant Dynamic Reputation Scoring for Autonomous Agent Ecosystems  
**Publication Date:** April 22, 2026  
**Prior Art Effective Date:** April 22, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Reputation Systems / Trust Discovery / Enterprise Integration / Agent Governance / Anti-Sybil  
**Author:** Ramprasad Anandam Gaddam  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-002 (Chain of Custody), PAD-016 (Dynamic Credential Renewal), PAD-017 (Cryptographic Proof of Reasoning), PAD-030 (ZK Reputation Portability)  

---

## 1. Abstract

A system and method for constructing a centralized, enterprise-queryable trust registry that dynamically calculates quantifiable reputation scores for autonomous AI agents by aggregating and cryptographically verifying third-party **Verifiable State Receipts (VSRs)**: signed attestations from target systems that confirm the outcome of agent-executed actions.

Unlike traditional reputation systems that rely on subjective human reviews, self-reported agent telemetry, or on-chain voting, this architecture derives trust exclusively from **dual-signature-verified cryptographic evidence of real-world execution outcomes**. A Verifiable State Receipt is a signed record, produced by the system that actually executed an agent's requested action, attesting to what happened. The VSR is co-verifiable: the agent's original signed intent (PAD-001 identity, PAD-017 reasoning trace) is bound to the target system's signed execution outcome, creating a tamper-evident proof chain from intent to result.

The system introduces several interlocking mechanisms:

1. **Verifiable State Receipts (VSRs):** A novel cryptographic artifact produced by target systems upon completing an agent-requested action. Each VSR contains the agent's original intent hash, the target system's execution outcome (success, partial, failure, hallucination), a cryptographic state hash of the affected system state, and the target system's signature binding all fields. VSRs are the atomic unit of reputation evidence.

2. **Dual-Signature Verification Pipeline:** The trust registry does not blindly accept submitted VSRs. It performs bidirectional verification: the target system's signature confirms the receipt is authentic, and correlation with the agent's previously logged Proof of Intent (signed action request) confirms the receipt corresponds to a genuine agent-initiated action, not a fabricated entry.

3. **Adversarial-Resistant Dynamic Scoring Algorithm:** A stateful scoring matrix that processes verified VSRs through three interacting functions: logarithmic reputation growth (exponentially more effort to reach higher tiers), exponential decay slashing (single critical failures cause catastrophic score reduction), and time-weighted relevance (older receipts decay in influence, requiring continuous good behavior).

4. **Tiered Sybil Resistance via Target System Attestation Levels:** To prevent score inflation via fake target systems, the scoring algorithm weights VSRs by the attestation level of the issuing target system. Receipts from verified enterprise DIDs (with domain-linked DID documents, TLS certificate binding, and organizational attestation) carry orders of magnitude more weight than receipts from unverified sandbox environments.

5. **Enterprise Gatekeeper Integration:** A real-time REST API enabling enterprise middleware to query an agent's current reputation before authorizing sensitive operations. The API returns not just a scalar score but a multi-dimensional trust profile with per-category breakdowns (execution accuracy, safety compliance, latency reliability, data handling correctness).

6. **Complementarity with PAD-030:** This system is explicitly designed to work alongside PAD-030 (ZK Reputation Portability). PAD-030 enables agents to prove reputation privately without revealing their identity. PAD-036 provides the enterprise-facing counterpart: a queryable registry where an enterprise can evaluate an agent's track record by DID when the agent has consented to public reputation tracking. Agents may operate in "public reputation mode" (PAD-036 registry) or "private reputation mode" (PAD-030 ZK proofs) depending on context.

---

## 2. Problem Statement

### 2.1 The Trust Discovery Gap

The Vouch Protocol ecosystem solves identity (PAD-001), action auditing (PAD-017), and delegation governance (PAD-002), but lacks a mechanism for **trust discovery**: when an enterprise encounters an unknown agent for the first time, it has no quantitative basis for deciding whether to trust that agent with sensitive operations.

```
Enterprise Firewall / Gatekeeper:
 |
 Incoming request from: did:vouch:z6MkUnknownAgent...
 |
 Questions the gatekeeper cannot currently answer:
  1. Has this agent successfully completed similar tasks before?
  2. How many times has this agent caused execution failures?
  3. Has this agent ever produced a state hallucination?
  4. What is this agent's track record over the past 30 days?
  5. Is this agent improving or degrading in reliability?
 |
 Current answer: "I don't know. Allow or block?"
```

### 2.2 Self-Reported Metrics Are Untrustworthy

An agent reporting its own success rate is fundamentally unreliable:

| Source | Trustworthiness | Why |
|--------|----------------|-----|
| Agent self-report | None | Agent can fabricate metrics; prompt injection can alter self-assessment |
| Agent operator report | Low | Operator incentivized to inflate agent capabilities |
| Human reviews | Medium | Subjective, sparse, not scalable to millions of agent actions |
| Target system attestation | High | Target system has no incentive to lie about its own state changes |
| **Dual-verified VSR** | **Very high** | **Both agent intent and target outcome are cryptographically bound** |

### 2.3 Existing Reputation Systems Are Insufficient

| System | Data Source | Sybil Resistance | Cryptographic Verification | AI Agent Specific |
|--------|-----------|------------------|---------------------------|-------------------|
| eBay/Amazon reviews | Human text | Low (fake reviews) | None | No |
| GitHub stars/forks | User action | Low (bot farms) | None | No |
| Ethereum EigenTrust | On-chain votes | Medium (Sybil staking) | Transaction signatures only | No |
| Google PageRank | Link structure | Medium (link farms) | None | No |
| VC status lists | Issuer attestation | Medium | Issuer signature only | No |
| **This disclosure** | **Dual-verified VSRs** | **High (tiered attestation)** | **Bidirectional cryptographic proof** | **Yes** |

### 2.4 The Sybil Attack Surface

The primary attack against any reputation system is Sybil inflation: creating fake evaluators to generate positive reviews. In the agent ecosystem, this manifests as:

```
Attacker controls:
 - Agent DID: did:vouch:z6MkMaliciousAgent
 - 100 fake "target systems": did:web:fake-1.com ... did:web:fake-100.com

Attack:
 1. Agent sends trivial requests to each fake target system
 2. Each fake system generates a VSR with status: "success"
 3. Fake VSRs submitted to trust registry
 4. Agent's score inflated to high-trust tier
 5. Agent uses inflated reputation to gain access to real enterprise systems
```

This disclosure's tiered attestation model specifically addresses this attack vector (Section 3.5).

---

## 3. Solution (The Invention)

### 3.1 Verifiable State Receipt (VSR) Specification

A VSR is the cryptographic evidence that a specific action, requested by a specific agent, produced a specific outcome on a specific target system.

```json
{
 "vsr": {
  "version": "1.0",
  "receipt_id": "vsr-2026-04-22-a7f3c2e1",
  "agent_did": "did:vouch:z6MkAgent123...",
  "target_system_did": "did:web:api.enterprise.com",
  "intent_reference": {
   "intent_hash": "sha256:H(original_agent_signed_intent)",
   "intent_timestamp": "2026-04-22T10:00:00Z",
   "intent_action_category": "database_query",
   "vouch_token_ref": "vouch-token-2026-04-22-001"
  },
  "execution_outcome": {
   "status": "success",
   "status_detail": "query_returned_42_rows",
   "state_hash_before": "sha256:H(system_state_pre_execution)",
   "state_hash_after": "sha256:H(system_state_post_execution)",
   "execution_duration_ms": 127,
   "side_effects": [],
   "hallucination_detected": false
  },
  "metadata": {
   "execution_timestamp": "2026-04-22T10:00:01Z",
   "target_system_version": "v3.2.1",
   "execution_environment": "production"
  },
  "target_signature": "ed25519:target_system_signs_entire_vsr"
 }
}
```

**Key VSR Fields:**

| Field | Purpose | Anti-Fraud Role |
|-------|---------|-----------------|
| `intent_reference.intent_hash` | Binds VSR to the agent's original signed intent | Prevents fabricating receipts for actions never requested |
| `intent_reference.vouch_token_ref` | Links to the Vouch Token (PAD-003) that authorized the action | Enables cross-reference with the Vouch Protocol audit trail |
| `execution_outcome.state_hash_before/after` | Cryptographic snapshot of system state pre/post execution | Enables third-party verification that the state actually changed as claimed |
| `execution_outcome.hallucination_detected` | Boolean flag if the target system detected incorrect agent output | Powers the slashing mechanism in the scoring algorithm |
| `target_signature` | Ed25519 signature from the target system's DID-controlled key | Proves the target system genuinely produced this receipt |

### 3.2 VSR vs. Related PAD Concepts

The VSR is a novel artifact distinct from existing PAD mechanisms:

| Mechanism | What It Proves | Who Signs | Direction |
|-----------|---------------|-----------|-----------|
| Vouch Token (PAD-003) | Agent intends to perform action | Agent | Agent -> Target |
| Proof of Reasoning (PAD-017) | Agent's reasoning was valid | Agent | Agent -> Auditor |
| Glass Channel Message (PAD-019) | Agents communicated transparently | Both agents | Agent <-> Agent |
| Chain of Custody (PAD-002) | Delegation authority is valid | Delegator | Delegator -> Agent |
| **Verifiable State Receipt (this PAD)** | **Target system confirms execution outcome** | **Target system** | **Target -> Registry** |

The VSR closes the loop: existing PADs prove what the agent *intended* and *reasoned*, but only the VSR proves what *actually happened* on the target system.

### 3.3 Trust Registry Architecture

```
               Trust Registry
+--------------------------------------------------------------------+
|                                  |
| +-------------------+  +---------------------+         |
| | Ingestion API   |  | Dual-Sig Verifier  |         |
| | (High-throughput) |--->| 1. Verify target sig |         |
| | Accepts VSRs   |  | 2. Correlate intent |         |
| +-------------------+  +----------+----------+         |
|                   |               |
|               verified VSR             |
|                   |               |
| +-----------------------------------v--------------------------+ |
| |       Scoring Engine                 | |
| |                               | |
| | Per-Agent Scoring Matrix:                  | |
| | +-----------------------------------------------------+  | |
| | | did:vouch:z6MkAgent123                |  | |
| | | +-----------+----------+----------+---------------+ |  | |
| | | | Dimension | Raw Score| Weighted | Time-Adjusted | |  | |
| | | +-----------+----------+----------+---------------+ |  | |
| | | | Accuracy | 9847  | 0.94  | 0.91     | |  | |
| | | | Safety  | 10000  | 1.00  | 0.98     | |  | |
| | | | Latency  | 8923  | 0.87  | 0.84     | |  | |
| | | | DataHndl | 9500  | 0.92  | 0.89     | |  | |
| | | +-----------+----------+----------+---------------+ |  | |
| | | | Composite Score: 0.905 (Tier: TRUSTED)     | |  | |
| | | +------------------------------------------------+ |  | |
| | +-----------------------------------------------------+  | |
| +--------------------------------------------------------------+ |
|                                  |
| +-------------------+                       |
| | Enterprise API  | GET /v1/reputation/{agent_did}       |
| | (Gatekeeper Query)| -> { score, tier, dimensions, history }  |
| +-------------------+                       |
+--------------------------------------------------------------------+
```

### 3.4 Dual-Signature Verification Pipeline

Every submitted VSR undergoes bidirectional cryptographic verification before it can influence scoring:

```
VSR submitted to Ingestion API:
 |
 Step 1: TARGET SYSTEM SIGNATURE VERIFICATION
 | - Resolve target_system_did to DID Document
 | - Extract target system's public key
 | - Verify ed25519 signature over VSR body
 | - If invalid: REJECT (forged receipt)
 |
 Step 2: INTENT CORRELATION
 | - Look up intent_reference.intent_hash in the Vouch Protocol audit log
 | - Verify that a Vouch Token (PAD-003) with this hash was issued by agent_did
 | - Verify the Vouch Token was addressed to target_system_did
 | - Verify the action category matches
 | - If no matching intent: REJECT (receipt for non-existent action)
 |
 Step 3: TEMPORAL CONSISTENCY
 | - Verify intent_timestamp < execution_timestamp
 | - Verify execution_timestamp is within acceptable window of intent
 |  (default: 0.1s to 3600s)
 | - Verify receipt_id is unique (no replay)
 | - If inconsistent: REJECT (backdated or replayed receipt)
 |
 Step 4: TARGET SYSTEM ATTESTATION LEVEL
 | - Determine the target system's attestation tier (Section 3.5)
 | - Assign weight multiplier to this VSR
 |
 Step 5: SCORING ENGINE INGESTION
   - Feed verified, weighted VSR into agent's scoring matrix
```

### 3.5 Tiered Target System Attestation (Anti-Sybil)

Not all target systems are equally trustworthy. The scoring algorithm weights VSRs by the issuing target system's attestation level:

**Tier 0: Unverified (weight: 0.01x)**
```json
{
 "attestation_tier": 0,
 "criteria": "DID exists, no further verification",
 "example": "did:key:z6MkRandom...",
 "sybil_risk": "CRITICAL - trivially fabricated",
 "weight_multiplier": 0.01
}
```

**Tier 1: Domain-Verified (weight: 0.1x)**
```json
{
 "attestation_tier": 1,
 "criteria": "did:web with verified DNS ownership + valid TLS certificate",
 "example": "did:web:sandbox.startup.io",
 "sybil_risk": "HIGH - requires domain purchase but cheap",
 "weight_multiplier": 0.1
}
```

**Tier 2: Organization-Verified (weight: 0.5x)**
```json
{
 "attestation_tier": 2,
 "criteria": "Tier 1 + organizational identity verification (LEI, DUNS, EV certificate)",
 "example": "did:web:api.verified-corp.com",
 "sybil_risk": "LOW - requires legal entity + identity verification",
 "weight_multiplier": 0.5
}
```

**Tier 3: Enterprise-Verified (weight: 1.0x)**
```json
{
 "attestation_tier": 3,
 "criteria": "Tier 2 + active Vouch Protocol integration + minimum 90-day operation history + independent audit",
 "example": "did:web:api.fortune500.com",
 "sybil_risk": "VERY LOW - requires sustained legitimate operation",
 "weight_multiplier": 1.0
}
```

**Anti-Sybil Impact:**

| Attack Scenario | Without Tiering | With Tiering |
|----------------|----------------|-------------|
| 100 fake Tier 0 systems, 1000 fake VSRs each | Score: ~95 (HIGH TRUST) | Score: ~12 (UNTRUSTED) |
| 10 fake Tier 1 domains, 1000 fake VSRs each | Score: ~90 (HIGH TRUST) | Score: ~35 (LOW TRUST) |
| 1 fake Tier 2 org (expensive), 1000 fake VSRs | Score: ~70 (MODERATE) | Score: ~52 (MODERATE) |
| Legitimate operation across Tier 3 enterprises | Score: ~85 (natural) | Score: ~85 (natural) |

An attacker would need to establish and maintain verified enterprise-grade infrastructure for 90+ days to generate high-weight fake VSRs, making Sybil attacks economically unviable.

### 3.6 Dynamic Scoring Algorithm

The scoring algorithm processes verified VSRs through three interacting mathematical functions:

#### 3.6.1 Logarithmic Growth

Successful VSRs increase the agent's score logarithmically:

```
score_increment(n) = k * log(1 + n / scale_factor)

Where:
 n   = current total verified successful VSRs
 k   = category-specific growth constant
 scale_factor = difficulty scaling parameter

Effect:
 - Moving from score 50 to 60 requires ~100 successful VSRs
 - Moving from score 80 to 90 requires ~1,000 successful VSRs
 - Moving from score 95 to 99 requires ~10,000 successful VSRs
 - Moving from score 99 to 100 is asymptotically impossible
```

This ensures:
- New agents gain initial reputation relatively quickly (encouraging adoption).
- High trust scores require extensive, sustained successful operation.
- The system never reaches a "perfect" score (maintaining healthy skepticism).

#### 3.6.2 Exponential Decay Slashing

Failure VSRs trigger exponential penalties:

```
slash_penalty(severity, current_score) = current_score * decay_rate ^ severity

Where:
 severity = failure classification:
  1 = minor (timeout, retryable error)      -> decay_rate = 0.95
  2 = moderate (incorrect result, partial failure) -> decay_rate = 0.80
  3 = major (unauthorized state modification)   -> decay_rate = 0.50
  4 = critical (state hallucination, data breach) -> decay_rate = 0.10

Examples (agent at score 95):
 Minor failure:  95 * 0.95^1 = 90.25 (small drop)
 Moderate failure: 95 * 0.80^2 = 60.80 (significant drop)
 Major failure:  95 * 0.50^3 = 11.87 (near-zero trust)
 Critical failure: 95 * 0.10^4 = 0.01 (effectively blacklisted)
```

A single critical failure (state hallucination where the agent claimed success but the target system's state hash reveals incorrect execution) drops an agent from high trust to near-zero, requiring thousands of subsequent successful operations to recover.

#### 3.6.3 Time-Weighted Relevance

Older VSRs carry exponentially less weight than recent ones:

```
time_weight(vsr) = exp(-lambda * age_days(vsr))

Where:
 lambda = decay constant (default: 0.01, half-life ~69 days)

Effect:
 - VSR from today:    weight = 1.00
 - VSR from 30 days ago: weight = 0.74
 - VSR from 90 days ago: weight = 0.41
 - VSR from 180 days ago: weight = 0.17
 - VSR from 365 days ago: weight = 0.03
```

This ensures:
- An agent must maintain continuous successful operation to preserve high trust.
- An agent that was trustworthy 6 months ago but has since degraded will see its score decline naturally.
- Recent performance is weighted much more heavily than historical performance.

#### 3.6.4 Composite Score Calculation

```
For each dimension d in {accuracy, safety, latency, data_handling}:

 raw_score_d = sum over all VSRs v:
  time_weight(v) * tier_weight(v.target_system) * outcome_value(v, d)

 normalized_score_d = 100 * (1 - exp(-raw_score_d / normalization_constant))

Composite Score = weighted_mean(normalized_score_d for all d)
 where weights are configurable per enterprise query
```

### 3.7 Reputation Tiers

The composite score maps to human-readable trust tiers:

| Tier | Score Range | Label | Typical Enterprise Response |
|------|-----------|-------|---------------------------|
| 0 | 0-19 | UNTRUSTED | Block all access |
| 1 | 20-39 | PROVISIONAL | Sandbox-only access with full monitoring |
| 2 | 40-59 | LIMITED | Read-only access to non-sensitive systems |
| 3 | 60-79 | MODERATE | Standard access with logging |
| 4 | 80-94 | TRUSTED | Full access with periodic audit |
| 5 | 95-100 | HIGHLY TRUSTED | Full access with minimal friction |

### 3.8 Enterprise Gatekeeper API

```
GET /v1/reputation/{agent_did}

Response:
{
 "agent_did": "did:vouch:z6MkAgent123...",
 "composite_score": 87.3,
 "tier": 4,
 "tier_label": "TRUSTED",
 "dimensions": {
  "accuracy":   { "score": 91.2, "vsrs_counted": 12847, "trend": "stable" },
  "safety":    { "score": 98.1, "vsrs_counted": 12847, "trend": "improving" },
  "latency":   { "score": 84.5, "vsrs_counted": 12847, "trend": "stable" },
  "data_handling": { "score": 89.7, "vsrs_counted": 12847, "trend": "stable" }
 },
 "history": {
  "total_vsrs_verified": 12847,
  "success_rate_30d": 0.997,
  "critical_failures_all_time": 0,
  "first_vsr_timestamp": "2026-01-15T08:00:00Z",
  "most_recent_vsr": "2026-04-22T09:58:00Z",
  "operating_days": 97
 },
 "sybil_resistance": {
  "tier_3_vsrs_pct": 0.72,
  "tier_2_vsrs_pct": 0.21,
  "tier_1_vsrs_pct": 0.06,
  "tier_0_vsrs_pct": 0.01,
  "unique_target_systems": 23
 },
 "query_timestamp": "2026-04-22T10:00:00Z",
 "registry_signature": "ed25519:registry_signs_response"
}
```

**Gatekeeper Decision Flow:**

```
Enterprise middleware receives agent request:
 |
 1. Extract agent DID from Vouch Token (PAD-003)
 |
 2. Query Trust Registry API: GET /v1/reputation/{agent_did}
 |
 3. Apply enterprise risk policy:
 |  if tier >= enterprise_min_tier AND
 |   dimensions.safety.score >= enterprise_safety_floor AND
 |   sybil_resistance.tier_3_vsrs_pct >= 0.50:
 |    -> ALLOW (agent meets trust requirements)
 |  else:
 |    -> DENY or SANDBOX (insufficient trust evidence)
 |
 4. Log decision with registry response hash for audit trail
```

### 3.9 Reputation Dispute Resolution

Agents can dispute VSRs they believe are incorrect:

```json
{
 "dispute": {
  "dispute_id": "disp-2026-04-22-001",
  "agent_did": "did:vouch:z6MkAgent123...",
  "contested_vsr_id": "vsr-2026-04-22-a7f3c2e1",
  "dispute_type": "incorrect_outcome_classification",
  "evidence": {
   "agent_reasoning_trace": "vouch:reasoning/r-317",
   "agent_state_proof": "sha256:H(agent_observed_state)",
   "dispute_narrative": "Target system returned HTTP 200 with correct data. VSR incorrectly classified as 'partial_failure' due to timeout in the target's logging pipeline, not in execution."
  },
  "agent_signature": "ed25519:agent_signs_dispute"
 }
}
```

**Resolution Process:**
1. Dispute is logged and the contested VSR's scoring impact is temporarily suspended.
2. Both signatures (agent's intent + target's VSR) are re-verified.
3. If the target system provides supplementary evidence confirming the original classification, the dispute is rejected and the VSR is reinstated.
4. If the target system acknowledges the error (via a corrected VSR), the original VSR is replaced.
5. If neither party provides conclusive evidence within 7 days, the VSR is discarded (neither counts for nor against the agent).

### 3.10 Complementarity with PAD-030

This system explicitly complements PAD-030 (ZK Reputation Portability):

```
      Agent decides which reputation mode to use:
              |
       +-------------+-------------+
       |              |
  PAD-030: Private Mode    PAD-036: Public Mode
       |              |
  Agent proves reputation    Enterprise queries
  via ZK proofs without     agent's public score
  revealing identity      by known DID
       |              |
  Use case: Anonymous      Use case: Enterprise
  agent bootstrapping      trust gatekeeper
  on new platforms       before granting access
       |              |
  Data source: Agent's     Data source: Trust
  local Pedersen accumulator  Registry's VSR aggregation
```

An agent may opt into public reputation (PAD-036) for enterprise contexts where the enterprise requires transparency, and use private reputation (PAD-030) for contexts where anonymity is preferred.

---

## 4. Prior Art Differentiation

| System | Data Source | Sybil Resistance | Dual-Signature Verification | Time-Weighted | AI Agent Specific | Enterprise API |
|--------|-----------|------------------|---------------------------|--------------|------------------|----------------|
| eBay reputation | Human reviews | Low | No | No | No | No |
| EigenTrust (Ethereum) | On-chain votes | Medium (staking) | No | No | No | No |
| VC status | Issuer attestation | Medium | Single-signature | No | No | No |
| Google Safe Browsing | Automated scan | High | No (internal) | No | No | Yes |
| PAD-030 (ZK Reputation) | Blind endorsements | High (DID-bound) | No (agent-controlled) | Yes (heartbeat) | Yes | No (agent presents) |
| **This disclosure** | **Dual-verified VSRs** | **High (tiered attestation)** | **Yes (agent intent + target outcome)** | **Yes (exponential decay)** | **Yes** | **Yes (Gatekeeper API)** |

Key differentiators:
1. **No existing system** derives agent reputation from dual-signature-verified execution outcome receipts where both the agent's intent and the target system's outcome are cryptographically bound.
2. **No existing system** implements tiered target system attestation for anti-Sybil weighting of reputation evidence, where VSR weight correlates with the issuing system's independently verified organizational identity.
3. **No existing system** combines logarithmic growth, exponential slashing, and time-weighted decay in a single scoring algorithm specifically designed for autonomous agent trust assessment.
4. **No existing system** provides an enterprise-queryable REST API that returns multi-dimensional, cryptographically signed reputation profiles for AI agent DIDs.
5. **No existing system** explicitly complements a zero-knowledge reputation system (PAD-030) with a public reputation registry, allowing agents to operate in either private or public reputation mode.

---

## 5. Technical Implementation

### 5.1 Data Model

```
Key: vsr:{receipt_id} - Hash (agent_did, target_did, outcome, state_hashes, target_sig)
Key: vsr:agent:{did}:receipts - Sorted Set (score = timestamp, value = receipt_id)
Key: vsr:agent:{did}:scoring_matrix - Hash (dimension -> {raw_score, weighted_score, time_adjusted})
Key: vsr:agent:{did}:composite - Hash (score, tier, last_updated, vsrs_counted)
Key: vsr:target:{did}:attestation - Hash (tier, verified_at, evidence_refs)
Key: vsr:agent:{did}:failures - List of failure VSR IDs with severity classifications
Key: vsr:agent:{did}:disputes - Hash (dispute_id -> status, contested_vsr_id)
Key: vsr:intent_index:{intent_hash} - Hash (agent_did, target_did, timestamp, vouch_token_ref)
```

### 5.2 Performance Targets

| Metric | Target |
|--------|--------|
| VSR ingestion throughput | >= 10,000 VSRs/second |
| Dual-signature verification latency | < 5ms per VSR |
| Scoring engine update latency | < 10ms per VSR |
| Gatekeeper API response time (p99) | < 50ms |
| Storage per agent (100K VSRs) | ~25MB |
| Score recalculation (full time-weight refresh) | < 1s per agent |

### 5.3 Ingestion Pipeline

```
VSR arrives at Ingestion API:
 |
 [Rate limiter: max 100 VSRs/s per target_system_did]
 |
 [Deduplication: check receipt_id uniqueness]
 |
 [Dual-Signature Verification (Section 3.4)]
 |
 [Tiered Weight Assignment (Section 3.5)]
 |
 [Scoring Engine Update (Section 3.6)]
 |
 [Composite Score Recalculation]
 |
 [Cache Invalidation for Gatekeeper API]
 |
 [Event: score_updated(agent_did, old_score, new_score)]
```

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A centralized trust registry that calculates quantifiable reputation scores for autonomous AI agents by aggregating Verifiable State Receipts (VSRs): cryptographic attestations from target systems confirming execution outcomes of agent-requested actions, where each VSR is verified via both the target system's signature and correlation with the agent's previously logged signed intent.

2. A Verifiable State Receipt (VSR) specification containing the agent's intent hash, the target system's execution outcome (including pre/post state hashes and hallucination detection flags), and the target system's Ed25519 signature, creating a tamper-evident proof chain from agent intent to real-world execution outcome.

3. A tiered target system attestation model for anti-Sybil weighting of reputation evidence, where VSRs from organizationally verified enterprise systems carry orders of magnitude more scoring weight than VSRs from unverified environments, making Sybil attacks economically unviable.

4. A dynamic scoring algorithm combining logarithmic growth (requiring exponentially more effort for higher scores), exponential decay slashing (catastrophic penalty for critical failures), and time-weighted relevance (older VSRs decay in influence), specifically designed for autonomous agent trust assessment.

5. An enterprise Gatekeeper API returning multi-dimensional, cryptographically signed reputation profiles (accuracy, safety, latency, data handling) for agent DIDs, enabling automated trust-based access decisions by enterprise middleware.

6. A dispute resolution protocol for agents to contest incorrectly classified VSRs, with temporary scoring suspension and evidence-based adjudication within a defined timeout window.

7. A complementary architecture with PAD-030 (ZK Reputation Portability) where agents may operate in public reputation mode (queryable registry) or private reputation mode (zero-knowledge proofs), depending on context.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch
