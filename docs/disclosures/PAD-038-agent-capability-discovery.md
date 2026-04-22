# PAD-038: Decentralized Agent Capability Discovery Protocol

**Identifier:** PAD-038
**Title:** Method for Cryptographically Verified Agent Capability Advertisement and Trust-Weighted Discovery in Decentralized Multi-Agent Ecosystems
**Publication Date:** April 22, 2026
**Prior Art Effective Date:** April 22, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Agent Discovery / Capability Attestation / Service Registry / Multi-Agent Systems / Decentralized Infrastructure
**Author:** Ramprasad Anandam Gaddam
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-002 (Chain of Custody), PAD-022 (Swarm Limits Protocol), PAD-036 (Aggregated Reputation Scoring), PAD-037 (Credential Federation)

---

## 1. Abstract

A system and method for enabling autonomous AI agents to cryptographically advertise their capabilities and for other agents and enterprises to discover, evaluate, and connect to them through a decentralized, trust-weighted discovery protocol. The system functions as a **DNS for AI agents**: a resolution layer that maps capability queries ("I need an agent that can translate legal documents from English to German with HIPAA compliance") to ranked sets of verified agents that demonstrably possess those capabilities.

The protocol introduces five interlocking mechanisms:

1. **Capability Manifests:** Structured, DID-signed declarations of an agent's capabilities, constraints, SLA commitments, and pricing. Each capability claim is either self-attested (operator-signed), peer-attested (vouched by another agent that has interacted with it), or registry-attested (backed by PAD-036 reputation data showing demonstrated competence). The manifest is the agent's machine-readable "resume."

2. **Capability Taxonomy (VouchCap):** A hierarchical, extensible namespace for capability classification. VouchCap provides a shared vocabulary for agents to describe what they can do (e.g., `vouch:cap:nlp:translation:legal:de`, `vouch:cap:data:query:sql:hipaa`). The taxonomy is community-governed and version-controlled.

3. **Discovery Resolution Protocol:** A DHT-based (Distributed Hash Table) resolution protocol where agents publish their capability manifests to a decentralized network. Discovery queries are routed through the DHT to find agents matching capability requirements. Results are ranked by a trust-weighted scoring function that combines reputation (PAD-036), attestation depth, and SLA history.

4. **Capability Proof Challenges:** Before an agent is listed for a capability, it can be challenged to demonstrate the capability via a standardized proof protocol. The challenger submits a test input; the agent produces a result; a panel of peer agents or automated validators evaluate the result. Passed challenges produce cryptographic attestations that strengthen the agent's capability listing.

5. **Service Level Agreement (SLA) Binding:** Agents can commit to SLAs (response time, accuracy, uptime, throughput) that are cryptographically bound to their capability manifest. SLA violations detected via PAD-036 VSRs automatically downgrade the agent's discovery ranking, creating market-driven quality enforcement.

---

## 2. Problem Statement

### 2.1 The Agent Discovery Vacuum

As agent ecosystems scale to millions of agents, a fundamental infrastructure gap emerges: **how does an enterprise or an agent find the right agent for a specific task?**

```
Enterprise has a task:
  "I need an agent to analyze 500 medical images for anomalies,
   HIPAA-compliant, 99.9% accuracy, under $0.10 per image"

Current discovery options:
  1. Manual search through agent registries     -> Doesn't scale
  2. Ask a directory maintained by one company  -> Centralized trust, single point of failure
  3. Trial and error with random agents         -> Dangerous with sensitive data
  4. Use only pre-approved agents               -> Misses better options
  5. ??? No protocol exists for this ???        -> This disclosure
```

### 2.2 Unverified Capability Claims

Any agent can claim any capability. Without verification:

| Risk | Consequence |
|------|------------|
| Agent claims medical expertise it lacks | Incorrect diagnoses, liability |
| Agent claims HIPAA compliance without it | Regulatory violation, data breach |
| Agent claims 99.9% accuracy, delivers 80% | Wasted resources, bad decisions |
| Agent claims low latency, is actually slow | SLA violations cascade downstream |
| Malicious agent advertises attractive capabilities as bait | Data exfiltration, system compromise |

### 2.3 Existing Systems Are Insufficient

| System | Capability Discovery | Verified Claims | Trust-Weighted | Decentralized | Agent-Specific |
|--------|---------------------|----------------|---------------|---------------|---------------|
| DNS / Service Discovery (Consul, etc.) | Address resolution only | No | No | Partial | No |
| API marketplaces (RapidAPI, etc.) | Human-curated listings | Manual review | User ratings | No (centralized) | No |
| Agent registries (emerging) | Basic metadata | Self-reported | No | No | Partially |
| Semantic web / UDDI (defunct) | Capability description | No | No | Attempted | No |
| **This disclosure** | **Semantic + cryptographic** | **Multi-layer attestation** | **Yes (PAD-036)** | **Yes (DHT)** | **Yes** |

---

## 3. Solution (The Invention)

### 3.1 Capability Manifest

Each agent publishes a signed capability manifest:

```json
{
  "capability_manifest": {
    "version": "1.0",
    "agent_did": "did:vouch:z6MkMedicalAnalyzer",
    "operator_did": "did:vouch:z6MkHealthTechCorp",
    "manifest_hash": "sha256:H(manifest_body)",
    "published_at": "2026-04-22T10:00:00Z",
    "capabilities": [
      {
        "capability_id": "cap-001",
        "taxonomy_ref": "vouch:cap:medical:imaging:anomaly_detection",
        "description": "Analyzes medical images (X-ray, MRI, CT) for anomalies using FDA-cleared algorithms",
        "attestation_level": "registry_attested",
        "attestations": [
          {
            "type": "operator_signed",
            "attester_did": "did:vouch:z6MkHealthTechCorp",
            "signature": "ed25519:operator_signs_claim",
            "timestamp": "2026-04-01T00:00:00Z"
          },
          {
            "type": "peer_attested",
            "attester_did": "did:vouch:z6MkHospitalSystem",
            "attestation": "Processed 10,000 images with 99.7% accuracy over 6 months",
            "signature": "ed25519:peer_signs_attestation",
            "timestamp": "2026-04-15T00:00:00Z"
          },
          {
            "type": "registry_attested",
            "registry_did": "did:web:trust.vouch-protocol.com",
            "reputation_tier": 5,
            "accuracy_score": 99.2,
            "vsrs_counted": 47832,
            "signature": "ed25519:registry_signs_attestation",
            "timestamp": "2026-04-22T09:00:00Z"
          },
          {
            "type": "challenge_passed",
            "challenge_id": "chal-2026-03-15-med-img-001",
            "challenger_did": "did:vouch:z6MkCertificationBody",
            "result": "passed",
            "score": 0.993,
            "signature": "ed25519:challenger_signs_result"
          }
        ],
        "constraints": {
          "compliance": ["HIPAA", "FDA_510k"],
          "data_residency": ["US", "EU"],
          "max_image_size_mb": 500,
          "supported_modalities": ["xray", "mri", "ct"]
        },
        "sla": {
          "response_time_p99_ms": 5000,
          "accuracy_floor_pct": 99.0,
          "uptime_pct": 99.9,
          "throughput_images_per_hour": 1000
        },
        "pricing": {
          "model": "per_invocation",
          "base_price_usd": 0.08,
          "volume_discount": {"threshold": 10000, "discount_pct": 20}
        }
      }
    ],
    "agent_signature": "ed25519:agent_signs_manifest"
  }
}
```

### 3.2 VouchCap Taxonomy

A hierarchical capability namespace:

```
vouch:cap
  :nlp
    :translation
      :legal
        :en_de, :en_fr, :en_ja, ...
      :medical
        :en_de, :en_fr, ...
      :general
    :summarization
      :legal, :medical, :financial, ...
    :generation
      :creative, :technical, :legal, ...
  :data
    :query
      :sql, :graphql, :nosql, ...
    :transform
      :etl, :normalization, ...
    :analysis
      :statistical, :predictive, :anomaly, ...
  :medical
    :imaging
      :anomaly_detection, :segmentation, :classification, ...
    :records
      :extraction, :summarization, :deidentification, ...
  :financial
    :trading, :risk, :compliance, ...
  :code
    :generation, :review, :testing, :deployment, ...
  :infrastructure
    :monitoring, :scaling, :security, ...
```

**Properties:**
- **Hierarchical:** `vouch:cap:medical:imaging:anomaly_detection` inherits properties from `vouch:cap:medical:imaging` and `vouch:cap:medical`.
- **Extensible:** New capability namespaces are added via community governance (RFC process).
- **Version-controlled:** Each taxonomy version is content-addressed (SHA-256 of the taxonomy tree), enabling manifest pinning to specific taxonomy versions.

### 3.3 Discovery Resolution Protocol

Agents publish manifests to a DHT (Kademlia-based):

```
Publication:
  1. Agent computes manifest_hash = SHA-256(manifest)
  2. For each capability in manifest:
     - Compute key = SHA-256(capability_taxonomy_ref)
     - Store (key, manifest_hash, agent_did) in DHT
  3. Full manifest stored at key = manifest_hash

Discovery Query:
  1. Enterprise constructs query:
     {
       "required_capabilities": ["vouch:cap:medical:imaging:anomaly_detection"],
       "required_compliance": ["HIPAA"],
       "min_reputation_tier": 3,
       "max_price_usd": 0.10,
       "min_accuracy_pct": 99.0
     }

  2. Compute key = SHA-256("vouch:cap:medical:imaging:anomaly_detection")

  3. DHT lookup returns set of (manifest_hash, agent_did) tuples

  4. Fetch full manifests and filter by query constraints

  5. Rank results using trust-weighted scoring (Section 3.4)

  6. Return ranked agent list to enterprise
```

### 3.4 Trust-Weighted Discovery Ranking

Discovery results are ranked by a composite score:

```
discovery_score(agent) =
    w_rep * reputation_score(agent)           // PAD-036 reputation (0-100)
  + w_att * attestation_depth(agent, cap)     // Number and quality of attestations
  + w_sla * sla_compliance_history(agent)     // Historical SLA adherence
  + w_chg * challenge_pass_rate(agent, cap)   // Capability proof challenge results
  + w_pri * price_competitiveness(agent)       // Lower price = higher score
  - w_age * manifest_staleness(agent)         // Penalty for outdated manifests

Default weights:
  w_rep = 0.30  (reputation is most important)
  w_att = 0.25  (attestation depth matters)
  w_sla = 0.20  (SLA compliance history)
  w_chg = 0.15  (challenge proofs)
  w_pri = 0.05  (price is a tiebreaker)
  w_age = 0.05  (freshness penalty)
```

### 3.5 Capability Proof Challenges

Before trusting an agent's capability claim, challengers can request a demonstration:

```
Challenge Protocol:
  1. Challenger submits:
     {
       "challenge_type": "vouch:cap:medical:imaging:anomaly_detection",
       "test_input": "base64url_encoded_test_image",
       "expected_output_format": "anomaly_detection_result_v1",
       "time_limit_ms": 5000,
       "challenger_did": "did:vouch:z6MkCertBody",
       "challenge_signature": "ed25519:challenger_signs"
     }

  2. Agent processes input and returns:
     {
       "result": { ... anomaly detection result ... },
       "processing_time_ms": 3200,
       "agent_signature": "ed25519:agent_signs_result"
     }

  3. Challenger (or automated validator) evaluates:
     {
       "evaluation": "passed",
       "score": 0.993,
       "evaluator_did": "did:vouch:z6MkCertBody",
       "evaluation_signature": "ed25519:evaluator_signs"
     }

  4. Challenge result is attached to agent's capability manifest
     as a "challenge_passed" attestation.
```

**Challenge Types:**
| Type | How It Works | Trust Value |
|------|-------------|------------|
| Self-challenge | Agent runs its own test suite and publishes results | Low (self-reported) |
| Peer challenge | Another agent in the same capability domain evaluates | Medium |
| Authority challenge | A recognized certification body evaluates | High |
| Blind challenge | Anonymous evaluator, double-blind test inputs | Very high |

### 3.6 SLA Binding and Enforcement

SLA commitments in the manifest are cryptographically binding:

```json
{
  "sla_commitment": {
    "capability_ref": "cap-001",
    "commitments": {
      "response_time_p99_ms": 5000,
      "accuracy_floor_pct": 99.0,
      "uptime_pct": 99.9
    },
    "measurement_window": "30_days_rolling",
    "violation_consequences": {
      "minor_violation": "discovery_ranking_penalty_10pct",
      "major_violation": "discovery_delisting_7days",
      "critical_violation": "capability_attestation_revoked"
    },
    "agent_signature": "ed25519:agent_commits_to_sla"
  }
}
```

SLA violations are detected via PAD-036 VSRs:
- If VSRs show response times consistently exceeding the committed p99, the agent's discovery ranking is penalized.
- If accuracy drops below the committed floor, the capability attestation is downgraded.
- Persistent violations result in temporary delisting from discovery results for that capability.

---

## 4. Prior Art Differentiation

| System | Capability Discovery | Cryptographic Claims | Trust-Weighted Ranking | Proof Challenges | SLA Enforcement |
|--------|---------------------|---------------------|----------------------|-----------------|----------------|
| DNS/Consul | Address only | No | No | No | No |
| UDDI (defunct) | XML descriptions | No | No | No | No |
| RapidAPI marketplace | Human-curated | No | User ratings | Manual testing | ToS-based |
| OpenAI Plugins/GPTs | Manifest file | No | GPT Store ranking | No | No |
| LangChain Hub | Code artifacts | No | Stars/downloads | No | No |
| **This disclosure** | **Semantic taxonomy** | **Multi-layer attestation** | **Yes (composite score)** | **Yes (4 types)** | **Yes (VSR-backed)** |

Key differentiators:
1. **No existing system** provides multi-layer capability attestation (self, peer, registry, challenge) with cryptographic signatures at each layer for AI agent capability claims.
2. **No existing system** implements a DHT-based decentralized resolution protocol for agent capability discovery with trust-weighted ranking that incorporates reputation scores from a verified state receipt system.
3. **No existing system** provides a standardized capability proof challenge protocol where agents can be asked to demonstrate claimed capabilities with results cryptographically attested by evaluators.
4. **No existing system** binds SLA commitments to agent capability manifests with automated enforcement via verifiable state receipt monitoring.

---

## 5. Technical Implementation

### 5.1 Data Model

```
Key: discovery:manifest:{manifest_hash} - Full capability manifest JSON
Key: discovery:agent:{did}:manifest_hash - Current manifest hash for agent
Key: discovery:cap:{taxonomy_hash}:agents - Set of (agent_did, manifest_hash) pairs
Key: discovery:challenge:{challenge_id} - Hash (challenger, agent, result, score)
Key: discovery:sla:{agent_did}:{cap_id} - Hash (commitments, violation_count, status)
Key: discovery:ranking:{taxonomy_hash} - Sorted Set (score = discovery_score, value = agent_did)
```

### 5.2 Performance Targets

| Metric | Target |
|--------|--------|
| Discovery query latency (DHT lookup) | < 100ms |
| Manifest publication propagation | < 5s to 95% of DHT nodes |
| Ranking computation per query | < 20ms |
| Challenge round-trip (excluding agent processing) | < 500ms |
| Maximum agents per capability listing | Unlimited (paginated) |

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A decentralized agent capability discovery protocol using a DHT-based resolution network where agents publish cryptographically signed capability manifests containing multi-layer attestations (operator-signed, peer-attested, registry-attested, challenge-proven), enabling trust-weighted discovery of agents matching specified capability requirements.

2. A hierarchical, extensible capability taxonomy (VouchCap) providing a shared, version-controlled namespace for classifying agent capabilities, enabling semantic matching between capability queries and agent manifests.

3. A trust-weighted discovery ranking function that combines reputation scores (PAD-036), attestation depth, SLA compliance history, capability proof challenge results, and pricing into a composite discovery score for ranking query results.

4. A capability proof challenge protocol with four trust levels (self-challenge, peer challenge, authority challenge, blind challenge) enabling verifiable demonstration of claimed capabilities before trust is established.

5. A cryptographically binding SLA commitment mechanism where agents sign SLA parameters (response time, accuracy, uptime) attached to specific capabilities, with automated enforcement via PAD-036 VSR monitoring and graduated consequences (ranking penalty, temporary delisting, attestation revocation).

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch
