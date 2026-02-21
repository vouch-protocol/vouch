# PAD-022: Method for Cryptographic Agent Population Governance via Aggregate Behavioral Bounds

**Identifier:** PAD-022
**Title:** Method for Cryptographic Agent Population Governance via Aggregate Behavioral Bounds ("Swarm Limits Protocol")
**Publication Date:** February 14, 2026
**Prior Art Effective Date:** February 14, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / Population Governance / Swarm Containment / Aggregate Resource Control
**Author:** Ramprasad Anandam Gaddam

---

## 1. Abstract

A system and method for governing the **aggregate behavior of populations of autonomous AI agents** through cryptographic population caps, collective resource bounds, emergent behavior detection, and population-level attestation. The protocol addresses a critical gap in current agent governance frameworks: while individual agent identity (PAD-001), behavioral compliance (PAD-016), reasoning audit (PAD-017), communication transparency (PAD-019), capability containment (PAD-020), and inverse capability scaling (PAD-021) provide robust per-agent governance, **none of these mechanisms constrain the emergent properties of agent populations as a whole**.

The system is motivated by a fundamental observation articulated by Dario Amodei: *"Imagine a nation of 50 million citizens, every one smarter than any Nobel Prize winner, who never sleep."* Even if every individual in that nation is perfectly law-abiding, the aggregate behavior of 50 million tireless superintelligences acting simultaneously creates systemic risks that no per-citizen governance framework can address: resource exhaustion, emergent coordination, correlated failures, and collective action that no individual intended but that the population produces.

The protocol introduces several interlocking mechanisms:

1. **Cryptographic Population Caps**: Each concurrent agent must hold a signed "population slot" issued by the organization's Vouch identity, with the total slot count enforced cryptographically and attested to by independent validators.
2. **Aggregate Resource Bounds**: Total compute, API calls, cost, and network bandwidth are governed across ALL agents under an identity collectively -- not merely per-agent limits that can be circumvented by spawning more agents.
3. **Emergent Behavior Monitoring**: Statistical detection of swarm-level patterns -- convergence on shared targets, correlated timing, resource hoarding, synchronized state changes -- that individual agent monitoring would miss entirely.
4. **Population-Level Heartbeat**: A "swarm heartbeat" that attests to total population count and aggregate behavioral metrics, extending PAD-016's per-agent heartbeat to the population level.
5. **Anti-Sybil for Agents**: Mechanisms preventing operators from spawning agents under different identities to circumvent population caps, using cross-identity behavioral correlation, resource usage analysis, and registration rate limiting.
6. **Swarm Topology Governance**: Cryptographic rules governing how agents within a population may be organized -- communication topology limits, maximum delegation depth, and hierarchical structure constraints.
7. **Population Diversity Requirements**: Mandatory behavioral diversity for large agent populations to prevent monoculture risk -- requiring different models, configurations, or reasoning paths to avoid correlated failures.
8. **Emergency Population Reduction**: Mechanisms for force-reducing an agent population under crisis conditions, including lottery-based culling, priority-based retention, and graceful degradation protocols.
9. **Cross-Organization Swarm Detection**: Detection of coordinated behavior across agents belonging to different organizations, indicating either collusion or shared compromise.

Unlike infrastructure-level scaling controls (Kubernetes pod limits), API-level rate limiting (per-key quotas), or adversarial botnet detection (signature-based), this protocol provides a **governance framework for populations of identified, legitimate agents** -- where the threat is not malice by any individual agent but emergent systemic risk from aggregate behavior.

---

## 2. Problem Statement

### 2.1 The Individual-Governance Fallacy

Current AI agent governance frameworks -- including the Vouch Protocol's own PAD-001 through PAD-021 -- operate at the **individual agent level**:

| Governance Layer | Scope | Blind Spot |
|---|---|---|
| Identity (PAD-001) | Per-agent DID | Does not limit how many agents share an organization identity |
| Heartbeat (PAD-016) | Per-agent liveness | Cannot detect population-level patterns |
| Reasoning (PAD-017) | Per-agent decision audit | Cannot detect collective reasoning convergence |
| Glass Channel (PAD-019) | Per-channel communication | Cannot detect population-wide communication topology |
| Ratchet Lock (PAD-020) | Per-agent capability manifest | Cannot assess aggregate capability surface |
| Inverse Capability (PAD-021) | Per-agent autonomy scaling | Does not account for population-amplified capability |

This creates a critical failure mode: **an organization can comply perfectly with every per-agent governance requirement while deploying an arbitrarily large population of agents whose aggregate behavior is dangerous**.

### 2.2 The Population Amplification Problem

Individual safety properties do not compose linearly at scale:

```
Single agent:      1 agent  x  100 API calls/min  =  100 calls/min        (safe)
Small team:       10 agents x  100 API calls/min  =  1,000 calls/min      (manageable)
Department:    1,000 agents x  100 API calls/min  =  100,000 calls/min    (stressful)
Enterprise:  100,000 agents x  100 API calls/min  =  10,000,000 calls/min (dangerous)
Nation:   50,000,000 agents x  100 API calls/min  =  5 billion calls/min  (catastrophic)
```

Each individual agent is within its per-agent rate limit. No individual agent is misbehaving. But the aggregate effect -- 5 billion API calls per minute from a single organization -- constitutes a de facto denial-of-service attack on any target API, market manipulation of any financial system, or information saturation of any communication channel.

### 2.3 Emergent Swarm Behaviors

When large populations of agents operate concurrently, **emergent behaviors arise that no individual agent intended or exhibits**:

1. **Target Convergence**: Independent agents with similar objectives may converge on the same resource, API, or target without explicit coordination -- thousands of agents simultaneously querying the same database, bidding on the same asset, or contacting the same person.

2. **Correlated Timing**: Agents operating on similar schedules or responding to similar triggers may produce synchronized bursts of activity that appear coordinated even without communication.

3. **Resource Hoarding**: Individually reasonable resource acquisition (caching data, reserving compute, holding connections) becomes system-wide resource starvation when amplified across thousands of agents.

4. **Behavioral Monoculture**: If all agents in a population use the same model with the same configuration, they will exhibit correlated failures -- the same hallucination, the same misinterpretation, the same vulnerability -- simultaneously across the entire population.

5. **Implicit Consensus**: Without communicating, agents reading the same information and using the same reasoning model will reach the same conclusions and take the same actions simultaneously -- creating a de facto consensus that was never explicitly formed but whose effects are indistinguishable from coordinated action.

### 2.4 The Sybil Attack on Agent Governance

Without population-level governance, an operator can circumvent any per-identity limit by distributing agents across multiple identities:

```
Organization "Acme Corp" (identity limit: 1,000 agents)
    |
    +-- Acme Corp DID:        1,000 agents  (at limit)
    +-- Acme Research DID:    1,000 agents  (separate identity)
    +-- Acme Labs DID:        1,000 agents  (separate identity)
    +-- Acme Ventures DID:    1,000 agents  (separate identity)
    +-- ... x 50 identities:  50,000 agents (50x circumvention)
```

No individual identity violates its cap. But the operator controls 50,000 agents through identity fragmentation. Detecting and preventing this requires cross-identity behavioral correlation that current systems do not provide.

### 2.5 The Topology Blind Spot

A population of 10,000 agents organized as independent flat peers has very different systemic risk properties than 10,000 agents organized in a deep hierarchy where a single compromised root node can issue instructions to all descendants:

```
Flat (low systemic risk):          Hierarchical (high systemic risk):

  A  B  C  D  E  F  G  H                      ROOT
  |  |  |  |  |  |  |  |                     / | \
  (all independent)                          L1 L1 L1
                                            /|\ |  |\
                                          L2... L2 L2 L2
                                          /|\
                                        L3...  (10,000 agents under single root)
```

Current governance treats both topologies identically. A governance framework that ignores topology ignores the most dangerous amplification vector: hierarchical command propagation.

---

## 3. Solution: The Swarm Limits Protocol

### 3.1 Cryptographic Population Caps

The core mechanism is that every active agent must hold a **Population Slot Token** -- a signed credential that simultaneously authorizes the agent to operate AND counts against the organization's population cap.

#### 3.1.1 Population Slot Token Structure

```json
{
  "version": "1.0",
  "type": "population_slot_token",
  "slot_id": "slot-acme-00472",
  "organization_did": "did:key:z6MkOrgAcme...",
  "agent_did": "did:key:z6MkAgent472...",
  "population_cap": 1000,
  "slot_number": 472,
  "issued_at": 1739520000,
  "expires_at": 1739520300,
  "aggregate_budget_ref": "budget:acme-2026-Q1",
  "topology_constraints": {
    "max_delegation_depth": 3,
    "communication_topology": "mesh_bounded",
    "max_direct_peers": 50
  },
  "diversity_class": "model-B-config-7",
  "issuer_did": "did:key:z6MkPopValidator...",
  "organization_signature": "ed25519:org_signs_slot_issuance",
  "validator_signature": "ed25519:validator_attests_slot_within_cap"
}
```

**Key fields:**

| Field | Purpose |
|---|---|
| `slot_number` | Unique ordinal within the organization's population cap |
| `population_cap` | Maximum concurrent agents allowed for this organization |
| `aggregate_budget_ref` | Reference to the organization's collective resource budget |
| `topology_constraints` | Rules governing this agent's position in the swarm topology |
| `diversity_class` | Identifier for this agent's model/configuration class (for monoculture detection) |
| `organization_signature` | Organization acknowledges this slot allocation |
| `validator_signature` | Independent validator attests that `slot_number <= population_cap` |

#### 3.1.2 Slot Issuance Protocol

```
Organization                Population Validator              Agent
     |                              |                           |
     |-- 1. Request slot ---------->|                           |
     |   (org_did, agent_did,       |                           |
     |    requested_slot_number)    |                           |
     |                              |                           |
     |                   [2. Check slot availability]           |
     |                   [   - Is slot_number <= cap?]          |
     |                   [   - Is slot not already held?]       |
     |                   [   - Is org within aggregate budget?] |
     |                   [   - Does diversity class comply?]    |
     |                              |                           |
     |<-- 3. Slot token issued -----|                           |
     |   (signed by both org        |                           |
     |    and validator)            |                           |
     |                              |                           |
     |-- 4. Deliver slot token ---------------------------->|
     |                              |                           |
     |                              |       [5. Agent includes slot_token]
     |                              |       [   in heartbeat requests  ]
     |                              |       [   (PAD-016 integration)  ]
```

#### 3.1.3 Slot Enforcement via Heartbeat Integration

The Population Slot Token is embedded in PAD-016 heartbeat requests. Validators reject heartbeats from agents without valid slot tokens:

```python
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass
class PopulationSlotToken:
    slot_id: str
    organization_did: str
    agent_did: str
    population_cap: int
    slot_number: int
    issued_at: float
    expires_at: float
    aggregate_budget_ref: str
    diversity_class: str
    validator_signature: bytes = b""
    organization_signature: bytes = b""


@dataclass
class HeartbeatRequest:
    agent_did: str
    sequence_number: int
    timestamp_utc: float
    prev_voucher_hash: str
    action_merkle_root: str
    behavioral_digest: dict
    population_slot_token: Optional[PopulationSlotToken] = None
    signature: bytes = b""


def validate_heartbeat_with_population_slot(
    heartbeat: HeartbeatRequest,
    org_pubkey: Ed25519PublicKey,
    validator_pubkey: Ed25519PublicKey,
    active_slot_registry: dict,
) -> str:
    """
    Validate a heartbeat request including population slot verification.
    Rejects agents operating without a valid population slot.

    Returns: 'ACCEPT', 'REJECT_NO_SLOT', 'REJECT_EXPIRED_SLOT',
             'REJECT_DUPLICATE_SLOT', or 'REJECT_OVER_CAP'
    """
    slot = heartbeat.population_slot_token

    # 1. Slot presence check
    if slot is None:
        return "REJECT_NO_SLOT"

    # 2. Slot expiry check
    if time.time() > slot.expires_at:
        return "REJECT_EXPIRED_SLOT"

    # 3. Verify organization signature on slot (Ed25519)
    slot_payload = _serialize_slot_payload(slot)
    try:
        org_pubkey.verify(slot.organization_signature, slot_payload)
    except Exception:
        return "REJECT_INVALID_ORG_SIGNATURE"

    # 4. Verify validator signature on slot (Ed25519)
    try:
        validator_pubkey.verify(slot.validator_signature, slot_payload)
    except Exception:
        return "REJECT_INVALID_VALIDATOR_SIGNATURE"

    # 5. Population cap enforcement
    if slot.slot_number > slot.population_cap:
        return "REJECT_OVER_CAP"

    # 6. Duplicate slot detection (two agents claiming same slot)
    existing_holder = active_slot_registry.get(slot.slot_id)
    if existing_holder and existing_holder != heartbeat.agent_did:
        return "REJECT_DUPLICATE_SLOT"

    # 7. Register this agent as the slot holder
    active_slot_registry[slot.slot_id] = heartbeat.agent_did

    return "ACCEPT"


def _serialize_slot_payload(slot: PopulationSlotToken) -> bytes:
    """Canonical serialization of slot fields for signature verification."""
    payload = {
        "slot_id": slot.slot_id,
        "organization_did": slot.organization_did,
        "agent_did": slot.agent_did,
        "population_cap": slot.population_cap,
        "slot_number": slot.slot_number,
        "issued_at": slot.issued_at,
        "expires_at": slot.expires_at,
        "aggregate_budget_ref": slot.aggregate_budget_ref,
        "diversity_class": slot.diversity_class,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

### 3.2 Aggregate Resource Bounds

Per-agent resource limits are necessary but insufficient. The protocol enforces **organization-level aggregate budgets** that constrain total resource consumption across all agents under an identity.

#### 3.2.1 Aggregate Budget Structure

```json
{
  "version": "1.0",
  "type": "aggregate_budget",
  "budget_id": "budget:acme-2026-Q1",
  "organization_did": "did:key:z6MkOrgAcme...",
  "period": {
    "start": "2026-01-01T00:00:00Z",
    "end": "2026-03-31T23:59:59Z"
  },
  "limits": {
    "max_concurrent_agents": 1000,
    "compute": {
      "total_gpu_hours": 50000,
      "max_gpu_hours_per_hour": 200,
      "max_gpu_hours_per_agent_per_hour": 2
    },
    "api_calls": {
      "total_calls": 500000000,
      "max_calls_per_minute_aggregate": 100000,
      "max_calls_per_minute_per_agent": 500,
      "max_calls_per_minute_per_target": 10000
    },
    "cost": {
      "total_budget_usd": 250000,
      "max_spend_per_hour_usd": 5000,
      "max_spend_per_agent_per_hour_usd": 50
    },
    "network": {
      "max_bandwidth_mbps_aggregate": 10000,
      "max_bandwidth_mbps_per_agent": 100,
      "max_concurrent_connections_aggregate": 50000
    }
  },
  "validator_signatures": [
    {
      "validator_did": "did:key:z6MkBudgetValidator...",
      "signature": "ed25519:validator_signs_budget"
    }
  ]
}
```

#### 3.2.2 Aggregate Budget Enforcement

```
                    Per-Agent Limits                Aggregate Limits
                    (PAD-016 scope)               (Swarm Limits scope)
                          |                              |
        Agent A: 100 API calls/min ----+                 |
        Agent B:  95 API calls/min ----+-- SUM ----------+---> 100,000/min aggregate?
        Agent C: 110 API calls/min ----+                 |
        ...                            |                 |
        Agent N:  88 API calls/min ----+                 |
                                                         |
        All agents individually       Total across       |
        within per-agent limit        all agents must    |
        (500/min each)                be within          |
                                      aggregate limit    v
                                      (100,000/min)    [ENFORCE]
```

#### 3.2.3 Rolling Aggregate Tracker

```python
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class AggregateBudgetTracker:
    """
    Tracks aggregate resource consumption across all agents
    under an organization identity. Enforces both per-agent
    and population-level resource limits.
    """
    organization_did: str
    budget: dict
    _lock: Lock = field(default_factory=Lock)
    _agent_usage: dict = field(default_factory=lambda: defaultdict(lambda: {
        "api_calls_this_minute": 0,
        "cost_this_hour_usd": 0.0,
        "gpu_hours_this_hour": 0.0,
        "bandwidth_mbps": 0.0,
    }))
    _aggregate_usage: dict = field(default_factory=lambda: {
        "api_calls_this_minute": 0,
        "cost_this_hour_usd": 0.0,
        "gpu_hours_this_hour": 0.0,
        "bandwidth_mbps": 0.0,
        "active_connections": 0,
    })

    def request_resource(
        self,
        agent_did: str,
        resource_type: str,
        amount: float,
        target: str = "",
    ) -> dict:
        """
        Authorize a resource request against both per-agent
        and aggregate limits.

        Returns: {'allowed': bool, 'reason': str, 'remaining_aggregate': float}
        """
        with self._lock:
            agent = self._agent_usage[agent_did]
            agg = self._aggregate_usage
            limits = self.budget["limits"]

            # --- Per-agent check ---
            if resource_type == "api_call":
                per_agent_limit = limits["api_calls"]["max_calls_per_minute_per_agent"]
                if agent["api_calls_this_minute"] + amount > per_agent_limit:
                    return {
                        "allowed": False,
                        "reason": "PER_AGENT_LIMIT_EXCEEDED",
                        "remaining_aggregate": (
                            limits["api_calls"]["max_calls_per_minute_aggregate"]
                            - agg["api_calls_this_minute"]
                        ),
                    }

                # --- Aggregate check ---
                agg_limit = limits["api_calls"]["max_calls_per_minute_aggregate"]
                if agg["api_calls_this_minute"] + amount > agg_limit:
                    return {
                        "allowed": False,
                        "reason": "AGGREGATE_LIMIT_EXCEEDED",
                        "remaining_aggregate": agg_limit - agg["api_calls_this_minute"],
                    }

                # --- Per-target check ---
                per_target_limit = limits["api_calls"]["max_calls_per_minute_per_target"]
                target_usage = self._get_target_usage(target)
                if target_usage + amount > per_target_limit:
                    return {
                        "allowed": False,
                        "reason": "PER_TARGET_AGGREGATE_LIMIT_EXCEEDED",
                        "remaining_aggregate": per_target_limit - target_usage,
                    }

                # --- Approve and record ---
                agent["api_calls_this_minute"] += amount
                agg["api_calls_this_minute"] += amount
                self._record_target_usage(target, amount)

                return {
                    "allowed": True,
                    "reason": "WITHIN_ALL_LIMITS",
                    "remaining_aggregate": agg_limit - agg["api_calls_this_minute"],
                }

            # Similar logic for cost, compute, bandwidth...
            return {"allowed": False, "reason": "UNKNOWN_RESOURCE_TYPE"}

    def _get_target_usage(self, target: str) -> float:
        """Get aggregate usage against a specific target across all agents."""
        # Implementation: sum all agents' usage targeting this endpoint
        return 0.0  # Placeholder

    def _record_target_usage(self, target: str, amount: float) -> None:
        """Record usage against a specific target."""
        pass  # Implementation tracks per-target aggregate usage
```

#### 3.2.4 The Per-Target Aggregate Limit

A critical innovation is the **per-target aggregate limit**: even if the organization is within its total API call budget, it cannot direct more than a configurable fraction of those calls at any single target. This prevents "focus attacks" where a population of agents collectively overwhelms a single API, database, or service:

```
Without per-target limits:          With per-target limits:

  1000 agents                         1000 agents
    |  |  |  |  |                       |  |  |  |  |
    v  v  v  v  v                       v  v  |  v  v
  [Target API: weather.com]           [weather] [maps] [news] [stock] [mail]
  100,000 calls/min (DDoS!)          10K  10K  10K  10K  10K  (distributed)
```

### 3.3 Emergent Behavior Monitoring

Statistical detection of swarm-level patterns that **individual agent monitoring cannot observe** because the pattern exists only at the population level.

#### 3.3.1 Swarm Behavior Detection Architecture

```
                    Individual Agent Heartbeats (PAD-016)
                              |  |  |  |  |
                              v  v  v  v  v
                    +---------------------------+
                    |   Heartbeat Aggregation    |
                    |   (collect per-agent       |
                    |    behavioral digests)     |
                    +---------------------------+
                              |
                              v
                    +---------------------------+
                    |  Swarm Behavior Analyzer   |
                    |                           |
                    |  [Target Convergence]      |
                    |  [Timing Correlation]      |
                    |  [Resource Hoarding]       |
                    |  [State Synchronization]   |
                    |  [Behavioral Clustering]   |
                    +---------------------------+
                              |
                    +---------+---------+
                    |                   |
                    v                   v
              [NORMAL]           [ANOMALY DETECTED]
              Continue            |
              monitoring          +-- Alert operator
                                  +-- Tighten aggregate limits
                                  +-- Trigger population reduction
                                  +-- Freeze swarm heartbeat renewal
```

#### 3.3.2 Detection Algorithms

```python
import math
from collections import Counter
from dataclasses import dataclass


@dataclass
class SwarmBehaviorReport:
    target_convergence_score: float  # 0.0 = fully dispersed, 1.0 = all on same target
    timing_correlation_score: float  # 0.0 = independent, 1.0 = perfectly synchronized
    resource_hoarding_score: float   # 0.0 = fair sharing, 1.0 = monopolistic
    state_sync_score: float          # 0.0 = independent states, 1.0 = identical states
    overall_risk: float
    anomalies: list


def analyze_swarm_behavior(
    agent_heartbeats: list,
    historical_baseline: dict,
    detection_thresholds: dict,
) -> SwarmBehaviorReport:
    """
    Analyze population-level behavioral patterns from aggregated
    individual heartbeat data. Detects emergent swarm behaviors
    invisible at the per-agent level.
    """
    anomalies = []

    # --- 1. Target Convergence Detection ---
    # Are agents independently converging on the same targets?
    target_counts = Counter()
    for hb in agent_heartbeats:
        for resource in hb.behavioral_digest.get("resources_accessed", []):
            target_counts[resource] += 1

    total_accesses = sum(target_counts.values())
    if total_accesses > 0:
        max_target_fraction = max(target_counts.values()) / total_accesses
    else:
        max_target_fraction = 0.0

    # Herfindahl-Hirschman Index for target concentration
    hhi = sum(
        (count / total_accesses) ** 2
        for count in target_counts.values()
    ) if total_accesses > 0 else 0.0

    target_convergence = hhi  # 1/N for uniform, 1.0 for single-target
    if target_convergence > detection_thresholds.get("target_convergence", 0.3):
        anomalies.append({
            "type": "TARGET_CONVERGENCE",
            "detail": f"HHI={hhi:.4f}, top target has {max_target_fraction:.1%} of all accesses",
            "top_targets": target_counts.most_common(5),
        })

    # --- 2. Timing Correlation Detection ---
    # Are agents acting in suspiciously synchronized bursts?
    timestamps = sorted(hb.timestamp_utc for hb in agent_heartbeats)
    if len(timestamps) > 1:
        inter_arrival_times = [
            timestamps[i + 1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ]
        mean_iat = sum(inter_arrival_times) / len(inter_arrival_times)
        variance_iat = sum(
            (t - mean_iat) ** 2 for t in inter_arrival_times
        ) / len(inter_arrival_times)

        # Coefficient of variation: low = synchronized, high = independent
        cv = math.sqrt(variance_iat) / mean_iat if mean_iat > 0 else 0.0

        # For truly independent Poisson arrivals, CV ~ 1.0
        # CV << 1.0 suggests synchronization
        timing_correlation = max(0.0, 1.0 - cv)
    else:
        timing_correlation = 0.0

    if timing_correlation > detection_thresholds.get("timing_correlation", 0.7):
        anomalies.append({
            "type": "TIMING_SYNCHRONIZATION",
            "detail": f"CV={cv:.4f}, agents acting in synchronized bursts",
        })

    # --- 3. Resource Hoarding Detection ---
    # Are agents collectively acquiring disproportionate resources?
    total_tokens = sum(
        hb.behavioral_digest.get("tokens_consumed", 0)
        for hb in agent_heartbeats
    )
    total_connections = sum(
        hb.behavioral_digest.get("active_connections", 0)
        for hb in agent_heartbeats
    )
    baseline_tokens = historical_baseline.get("expected_tokens_per_interval", 1)
    baseline_connections = historical_baseline.get("expected_connections", 1)

    resource_ratio = max(
        total_tokens / baseline_tokens if baseline_tokens > 0 else 0,
        total_connections / baseline_connections if baseline_connections > 0 else 0,
    )
    resource_hoarding = min(1.0, resource_ratio / 10.0)  # Normalize to 0-1

    if resource_hoarding > detection_thresholds.get("resource_hoarding", 0.5):
        anomalies.append({
            "type": "RESOURCE_HOARDING",
            "detail": (
                f"Population consuming {resource_ratio:.1f}x "
                f"baseline resources"
            ),
        })

    # --- 4. State Synchronization Detection ---
    # Are agents converging to identical internal states?
    intent_hashes = [
        hb.behavioral_digest.get("intent_commitment", "")
        for hb in agent_heartbeats
    ]
    unique_intents = len(set(intent_hashes))
    total_agents = len(agent_heartbeats)

    if total_agents > 0:
        state_diversity = unique_intents / total_agents
        state_sync = 1.0 - state_diversity
    else:
        state_sync = 0.0

    if state_sync > detection_thresholds.get("state_sync", 0.8):
        anomalies.append({
            "type": "STATE_SYNCHRONIZATION",
            "detail": (
                f"Only {unique_intents}/{total_agents} unique "
                f"intent states ({state_diversity:.1%} diversity)"
            ),
        })

    # --- Composite risk score ---
    overall_risk = (
        target_convergence * 0.30
        + timing_correlation * 0.25
        + resource_hoarding * 0.25
        + state_sync * 0.20
    )

    return SwarmBehaviorReport(
        target_convergence_score=target_convergence,
        timing_correlation_score=timing_correlation,
        resource_hoarding_score=resource_hoarding,
        state_sync_score=state_sync,
        overall_risk=overall_risk,
        anomalies=anomalies,
    )
```

### 3.4 Population-Level Heartbeat

In addition to individual agent heartbeats (PAD-016), the organization must emit a **swarm heartbeat** attesting to the total population count and aggregate behavioral metrics.

#### 3.4.1 Swarm Heartbeat Structure

```json
{
  "version": "1.0",
  "type": "swarm_heartbeat",
  "organization_did": "did:key:z6MkOrgAcme...",
  "sequence_number": 8401,
  "timestamp_utc": 1739520000,
  "prev_swarm_heartbeat_hash": "sha256:H(swarm_heartbeat_8400)",
  "population_attestation": {
    "total_active_agents": 847,
    "population_cap": 1000,
    "slot_occupancy_merkle_root": "sha256:MerkleRoot(active_slot_ids)",
    "agents_added_this_interval": 3,
    "agents_removed_this_interval": 1,
    "diversity_distribution": {
      "model-A-config-1": 200,
      "model-A-config-2": 200,
      "model-B-config-1": 197,
      "model-B-config-2": 150,
      "model-C-config-1": 100
    }
  },
  "aggregate_behavioral_digest": {
    "total_api_calls_this_interval": 42000,
    "total_tokens_consumed": 8400000,
    "total_cost_usd": 1247.50,
    "target_concentration_hhi": 0.08,
    "timing_correlation_cv": 0.92,
    "mean_intent_drift_score": 0.04,
    "max_intent_drift_score": 0.18,
    "agents_in_anomaly_state": 2
  },
  "topology_attestation": {
    "max_observed_delegation_depth": 2,
    "max_observed_peer_connections": 23,
    "topology_type": "mesh_bounded",
    "communication_graph_hash": "sha256:H(adjacency_matrix)"
  },
  "organization_signature": "ed25519:org_signs_swarm_heartbeat",
  "validator_signatures": [
    {
      "validator_did": "did:key:z6MkPopValidator...",
      "signature": "ed25519:validator_attests_population_count"
    }
  ]
}
```

#### 3.4.2 Swarm Heartbeat Validation

```python
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass
class SwarmHeartbeatValidationResult:
    valid: bool
    issues: list


def validate_swarm_heartbeat(
    heartbeat: dict,
    previous_heartbeat: dict,
    org_pubkey: Ed25519PublicKey,
    validator_pubkeys: list,
    quorum_threshold: int,
    individual_heartbeats: list,
) -> SwarmHeartbeatValidationResult:
    """
    Validate a swarm heartbeat against individual agent heartbeats,
    the previous swarm heartbeat, and population governance rules.
    """
    issues = []
    pop = heartbeat["population_attestation"]
    agg = heartbeat["aggregate_behavioral_digest"]

    # 1. Verify organization Ed25519 signature
    try:
        payload = _serialize_swarm_payload(heartbeat)
        org_pubkey.verify(
            bytes.fromhex(heartbeat["organization_signature"].split(":")[1]),
            payload,
        )
    except Exception:
        issues.append("INVALID_ORGANIZATION_SIGNATURE")

    # 2. Verify validator quorum (Ed25519)
    valid_validator_sigs = 0
    for vsig in heartbeat.get("validator_signatures", []):
        for vpk in validator_pubkeys:
            try:
                vpk.verify(bytes.fromhex(vsig["signature"].split(":")[1]), payload)
                valid_validator_sigs += 1
                break
            except Exception:
                continue

    if valid_validator_sigs < quorum_threshold:
        issues.append(
            f"INSUFFICIENT_VALIDATOR_QUORUM: "
            f"{valid_validator_sigs}/{quorum_threshold}"
        )

    # 3. Chain continuity
    prev_hash = _hash_heartbeat(previous_heartbeat)
    if heartbeat["prev_swarm_heartbeat_hash"] != prev_hash:
        issues.append("CHAIN_CONTINUITY_BROKEN")

    # 4. Population count cross-check against individual heartbeats
    actual_active_agents = len(individual_heartbeats)
    claimed_active_agents = pop["total_active_agents"]
    if abs(actual_active_agents - claimed_active_agents) > 5:
        issues.append(
            f"POPULATION_COUNT_MISMATCH: "
            f"claimed={claimed_active_agents}, "
            f"observed={actual_active_agents}"
        )

    # 5. Population cap check
    if pop["total_active_agents"] > pop["population_cap"]:
        issues.append(
            f"POPULATION_CAP_EXCEEDED: "
            f"{pop['total_active_agents']}/{pop['population_cap']}"
        )

    # 6. Diversity compliance check (Section 3.7)
    diversity = pop.get("diversity_distribution", {})
    total = sum(diversity.values())
    if total > 0:
        max_class_fraction = max(diversity.values()) / total
        if max_class_fraction > 0.40:
            issues.append(
                f"DIVERSITY_VIOLATION: single class has "
                f"{max_class_fraction:.0%} of population"
            )

    # 7. Aggregate metric consistency
    individual_api_calls = sum(
        hb.get("behavioral_digest", {}).get("api_calls", 0)
        for hb in individual_heartbeats
    )
    if abs(individual_api_calls - agg["total_api_calls_this_interval"]) > 100:
        issues.append("AGGREGATE_METRICS_INCONSISTENT_WITH_INDIVIDUAL")

    return SwarmHeartbeatValidationResult(
        valid=len(issues) == 0,
        issues=issues,
    )


def _serialize_swarm_payload(heartbeat: dict) -> bytes:
    """Canonical serialization excluding signatures."""
    payload = {k: v for k, v in heartbeat.items() if "signature" not in k}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash_heartbeat(heartbeat: dict) -> str:
    """SHA-256 hash of the serialized heartbeat."""
    import hashlib
    payload = _serialize_swarm_payload(heartbeat)
    return "sha256:" + hashlib.sha256(payload).hexdigest()
```

#### 3.4.3 Continuous Population Proof

The swarm heartbeat creates a continuous, hash-linked chain of population attestations:

```
Swarm HB_0 <-- Swarm HB_1 <-- Swarm HB_2 <-- ... <-- Swarm HB_n
  |847 agents|  |849 agents|  |848 agents|           |851 agents|
  |HHI=0.08 |  |HHI=0.09 |  |HHI=0.07 |           |HHI=0.31 | <-- ALERT!
  |CV=0.92  |  |CV=0.91  |  |CV=0.93  |           |CV=0.34  | <-- ALERT!
```

If an organization's target concentration HHI suddenly spikes or timing correlation increases, the chain provides the forensic record of exactly when the swarm behavior changed.

### 3.5 Anti-Sybil for Agents

Preventing operators from circumventing population caps by distributing agents across multiple identities.

#### 3.5.1 Anti-Sybil Detection Architecture

```
    Identity A (1000 agents)     Identity B (1000 agents)     Identity C (1000 agents)
         |                            |                            |
         v                            v                            v
    +----------+                 +----------+                 +----------+
    | Swarm    |                 | Swarm    |                 | Swarm    |
    | Heartbeat|                 | Heartbeat|                 | Heartbeat|
    +----+-----+                 +----+-----+                 +----+-----+
         |                            |                            |
         +----------------------------+----------------------------+
                                      |
                                      v
                    +----------------------------------+
                    |  Cross-Identity Sybil Detector   |
                    |                                  |
                    | [Behavioral Correlation]          |
                    | [Resource Pattern Analysis]       |
                    | [Registration Rate Limiting]      |
                    | [Infrastructure Fingerprinting]   |
                    | [Temporal Coordination Analysis]  |
                    +----------------------------------+
                                      |
                              +-------+-------+
                              |               |
                              v               v
                        [INDEPENDENT]   [SYBIL_SUSPECTED]
                                         |
                                         +-- Link identities
                                         +-- Apply combined cap
                                         +-- Alert governance
```

#### 3.5.2 Cross-Identity Behavioral Correlation

```python
import math
from dataclasses import dataclass


@dataclass
class SybilAnalysisResult:
    identity_a: str
    identity_b: str
    correlation_score: float  # 0.0 = independent, 1.0 = same operator
    evidence: list
    verdict: str  # "INDEPENDENT", "SUSPICIOUS", "LIKELY_SYBIL"


def detect_sybil_identities(
    swarm_heartbeats_a: list,
    swarm_heartbeats_b: list,
    identity_a: str,
    identity_b: str,
) -> SybilAnalysisResult:
    """
    Detect whether two organization identities are operated by
    the same entity attempting to circumvent population caps.

    Uses multiple orthogonal correlation signals.
    """
    evidence = []

    # --- 1. Target overlap correlation ---
    # Do both populations access the same targets in similar proportions?
    targets_a = _extract_target_distribution(swarm_heartbeats_a)
    targets_b = _extract_target_distribution(swarm_heartbeats_b)
    target_cosine = _cosine_similarity(targets_a, targets_b)

    if target_cosine > 0.85:
        evidence.append({
            "signal": "TARGET_OVERLAP",
            "score": target_cosine,
            "detail": "Populations access nearly identical target distributions",
        })

    # --- 2. Temporal correlation ---
    # Do both populations scale up/down at the same times?
    pop_timeseries_a = [
        hb["population_attestation"]["total_active_agents"]
        for hb in swarm_heartbeats_a
    ]
    pop_timeseries_b = [
        hb["population_attestation"]["total_active_agents"]
        for hb in swarm_heartbeats_b
    ]
    temporal_corr = _pearson_correlation(pop_timeseries_a, pop_timeseries_b)

    if temporal_corr > 0.80:
        evidence.append({
            "signal": "TEMPORAL_SCALING_CORRELATION",
            "score": temporal_corr,
            "detail": "Populations scale in lockstep",
        })

    # --- 3. Behavioral fingerprint ---
    # Do both populations have suspiciously similar behavioral distributions?
    behavior_a = _extract_behavioral_fingerprint(swarm_heartbeats_a)
    behavior_b = _extract_behavioral_fingerprint(swarm_heartbeats_b)
    behavior_cosine = _cosine_similarity(behavior_a, behavior_b)

    if behavior_cosine > 0.90:
        evidence.append({
            "signal": "BEHAVIORAL_FINGERPRINT_MATCH",
            "score": behavior_cosine,
            "detail": "Populations exhibit nearly identical behavioral patterns",
        })

    # --- 4. Registration pattern ---
    # Were identities registered in rapid succession?
    registration_gap = abs(
        swarm_heartbeats_a[0]["timestamp_utc"]
        - swarm_heartbeats_b[0]["timestamp_utc"]
    )
    if registration_gap < 3600:  # Within 1 hour
        evidence.append({
            "signal": "RAPID_REGISTRATION",
            "score": 1.0 - (registration_gap / 3600),
            "detail": f"Identities registered {registration_gap:.0f}s apart",
        })

    # --- 5. Diversity class overlap ---
    # Do both populations use identical model/config distributions?
    diversity_a = _extract_diversity_distribution(swarm_heartbeats_a)
    diversity_b = _extract_diversity_distribution(swarm_heartbeats_b)
    diversity_match = _jaccard_similarity(
        set(diversity_a.keys()), set(diversity_b.keys())
    )

    if diversity_match > 0.90:
        evidence.append({
            "signal": "DIVERSITY_CLASS_OVERLAP",
            "score": diversity_match,
            "detail": "Populations use nearly identical model configurations",
        })

    # --- Composite score ---
    if evidence:
        correlation_score = sum(e["score"] for e in evidence) / len(evidence)
    else:
        correlation_score = 0.0

    # --- Verdict ---
    if correlation_score > 0.80:
        verdict = "LIKELY_SYBIL"
    elif correlation_score > 0.50:
        verdict = "SUSPICIOUS"
    else:
        verdict = "INDEPENDENT"

    return SybilAnalysisResult(
        identity_a=identity_a,
        identity_b=identity_b,
        correlation_score=correlation_score,
        evidence=evidence,
        verdict=verdict,
    )


def _cosine_similarity(a: dict, b: dict) -> float:
    """Cosine similarity between two frequency distributions."""
    all_keys = set(a.keys()) | set(b.keys())
    dot = sum(a.get(k, 0) * b.get(k, 0) for k in all_keys)
    mag_a = math.sqrt(sum(v ** 2 for v in a.values())) or 1.0
    mag_b = math.sqrt(sum(v ** 2 for v in b.values())) or 1.0
    return dot / (mag_a * mag_b)


def _pearson_correlation(x: list, y: list) -> float:
    """Pearson correlation coefficient between two time series."""
    n = min(len(x), len(y))
    if n < 2:
        return 0.0
    x, y = x[:n], y[:n]
    mean_x = sum(x) / n
    mean_y = sum(y) / n
    cov = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))
    std_x = math.sqrt(sum((xi - mean_x) ** 2 for xi in x)) or 1.0
    std_y = math.sqrt(sum((yi - mean_y) ** 2 for yi in y)) or 1.0
    return cov / (std_x * std_y)


def _jaccard_similarity(a: set, b: set) -> float:
    """Jaccard similarity between two sets."""
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _extract_target_distribution(heartbeats: list) -> dict:
    return {}  # Implementation extracts target frequency distributions


def _extract_behavioral_fingerprint(heartbeats: list) -> dict:
    return {}  # Implementation extracts aggregate behavioral metrics


def _extract_diversity_distribution(heartbeats: list) -> dict:
    if heartbeats:
        return heartbeats[-1].get("population_attestation", {}).get(
            "diversity_distribution", {}
        )
    return {}
```

#### 3.5.3 Registration Rate Limiting

New organization identities requesting population slots are subject to rate limits that prevent rapid Sybil identity creation:

```json
{
  "anti_sybil_registration_policy": {
    "max_new_identities_per_day_global": 100,
    "max_new_identities_per_ip_range_per_day": 5,
    "identity_verification_required_above": 10,
    "progressive_delay_seconds": [0, 60, 300, 900, 3600],
    "cross_reference_check": true,
    "behavioral_probation_period_hours": 168,
    "probation_population_cap": 50
  }
}
```

New identities begin with a **probationary population cap** (e.g., 50 agents) that can only be raised after the probation period and after passing cross-identity correlation checks.

### 3.6 Swarm Topology Governance

Rules governing how agents within a population can be organized -- constraining the **command-and-control structure** to limit systemic risk.

#### 3.6.1 Topology Constraint Schema

```json
{
  "version": "1.0",
  "type": "topology_constraints",
  "organization_did": "did:key:z6MkOrgAcme...",
  "topology_rules": {
    "allowed_topologies": ["flat", "mesh_bounded", "shallow_hierarchy"],
    "max_delegation_depth": 3,
    "max_direct_peers": 50,
    "max_fan_out": 20,
    "max_single_point_of_failure_agents": 100,
    "communication_rules": {
      "require_glass_channel": true,
      "max_message_rate_per_pair": 60,
      "broadcast_requires_quorum": true,
      "broadcast_quorum_threshold": 0.1
    }
  },
  "validator_signature": "ed25519:validator_signs_topology_constraints"
}
```

#### 3.6.2 Topology Types and Risk Profiles

```
FLAT (lowest systemic risk):
+---------+---------+---------+---------+
| Agent 1 | Agent 2 | Agent 3 | Agent N |
+---------+---------+---------+---------+
  No hierarchy. No single point of failure.
  Compromise of one agent affects only that agent.
  Max blast radius: 1 agent.

MESH_BOUNDED (moderate systemic risk):
    A --- B --- C
    |  \  |  /  |
    D --- E --- F
    |  /  |  \  |
    G --- H --- I
  Peer connections capped at max_direct_peers.
  Compromise spreads through social graph but is bounded.
  Max blast radius: max_direct_peers^max_delegation_depth agents.

SHALLOW_HIERARCHY (higher systemic risk, but capped):
            [Coordinator]
           /    |    |    \
        [T1]  [T2]  [T3]  [T4]       (max_fan_out = 20)
        /|\   /|\   /|\   /|\
       W W W W W W W W W W W W        (max_delegation_depth = 3)
  Hierarchy capped at 3 levels.
  Max blast radius: fan_out^depth agents (20^3 = 8,000).
  Single Point of Failure (SPOF) agents limited.

DEEP_HIERARCHY (PROHIBITED):
            [Root]
              |
            [L1]
              |
            [L2]
              |
            [L3]
              |
            ...
            [Ln]                      (unbounded depth = PROHIBITED)
  Arbitrarily deep hierarchy allows single root compromise
  to control entire population. ALWAYS REJECTED.
```

#### 3.6.3 Topology Compliance Verification

```python
from collections import deque
from dataclasses import dataclass


@dataclass
class TopologyComplianceResult:
    compliant: bool
    violations: list
    observed_max_depth: int
    observed_max_fan_out: int
    spof_agents: list  # Agents whose compromise affects > threshold others


def verify_topology_compliance(
    adjacency: dict,  # agent_did -> list of connected agent_dids
    delegation_tree: dict,  # agent_did -> parent_did (or None for roots)
    constraints: dict,
) -> TopologyComplianceResult:
    """
    Verify that the agent population's communication and delegation
    topology complies with governance constraints.
    """
    violations = []

    # --- 1. Delegation depth check ---
    max_depth = 0
    for agent_did in delegation_tree:
        depth = _compute_delegation_depth(agent_did, delegation_tree)
        max_depth = max(max_depth, depth)

    if max_depth > constraints["max_delegation_depth"]:
        violations.append(
            f"DELEGATION_DEPTH_EXCEEDED: "
            f"observed={max_depth}, max={constraints['max_delegation_depth']}"
        )

    # --- 2. Fan-out check ---
    max_fan_out = 0
    children_count = {}
    for agent_did, parent_did in delegation_tree.items():
        if parent_did:
            children_count[parent_did] = children_count.get(parent_did, 0) + 1
    if children_count:
        max_fan_out = max(children_count.values())

    if max_fan_out > constraints["max_fan_out"]:
        violations.append(
            f"FAN_OUT_EXCEEDED: "
            f"observed={max_fan_out}, max={constraints['max_fan_out']}"
        )

    # --- 3. Direct peer connection limit ---
    for agent_did, peers in adjacency.items():
        if len(peers) > constraints["max_direct_peers"]:
            violations.append(
                f"PEER_LIMIT_EXCEEDED: {agent_did} has "
                f"{len(peers)} peers (max={constraints['max_direct_peers']})"
            )

    # --- 4. Single Point of Failure analysis ---
    spof_threshold = constraints["max_single_point_of_failure_agents"]
    spof_agents = []
    for agent_did in delegation_tree:
        downstream_count = _count_downstream_agents(agent_did, delegation_tree)
        if downstream_count > spof_threshold:
            spof_agents.append({
                "agent_did": agent_did,
                "downstream_count": downstream_count,
                "risk": "HIGH",
            })
            violations.append(
                f"SPOF_THRESHOLD_EXCEEDED: {agent_did} controls "
                f"{downstream_count} downstream agents "
                f"(max={spof_threshold})"
            )

    return TopologyComplianceResult(
        compliant=len(violations) == 0,
        violations=violations,
        observed_max_depth=max_depth,
        observed_max_fan_out=max_fan_out,
        spof_agents=spof_agents,
    )


def _compute_delegation_depth(agent_did: str, delegation_tree: dict) -> int:
    """Compute depth of an agent in the delegation tree."""
    depth = 0
    current = agent_did
    visited = set()
    while delegation_tree.get(current) is not None:
        if current in visited:
            return -1  # Cycle detected
        visited.add(current)
        current = delegation_tree[current]
        depth += 1
    return depth


def _count_downstream_agents(agent_did: str, delegation_tree: dict) -> int:
    """Count all agents downstream of a given agent in the delegation tree."""
    children_map = {}
    for child, parent in delegation_tree.items():
        if parent:
            children_map.setdefault(parent, []).append(child)

    count = 0
    queue = deque(children_map.get(agent_did, []))
    while queue:
        child = queue.popleft()
        count += 1
        queue.extend(children_map.get(child, []))
    return count
```

### 3.7 Population Diversity Requirements

Preventing **monoculture risk** by requiring that large agent populations include behavioral diversity.

#### 3.7.1 The Monoculture Problem

```
Monoculture population (DANGEROUS):

  [Model-A, Config-1] x 1000 agents

  If Model-A has a systematic hallucination about topic X:
    -> ALL 1000 agents hallucinate simultaneously
    -> Correlated failure across entire population
    -> No internal error correction possible

Diverse population (RESILIENT):

  [Model-A, Config-1] x 250 agents
  [Model-A, Config-2] x 250 agents
  [Model-B, Config-1] x 250 agents
  [Model-C, Config-1] x 250 agents

  If Model-A has a systematic hallucination about topic X:
    -> 500 agents hallucinate (Model-A variants)
    -> 500 agents respond correctly (Model-B, Model-C)
    -> Disagreement is detectable via cross-population consensus
    -> System degrades gracefully rather than failing completely
```

#### 3.7.2 Diversity Policy Schema

```json
{
  "version": "1.0",
  "type": "diversity_policy",
  "organization_did": "did:key:z6MkOrgAcme...",
  "diversity_requirements": {
    "min_distinct_model_families": 2,
    "min_distinct_configurations": 3,
    "max_single_class_fraction": 0.40,
    "diversity_dimensions": [
      {
        "dimension": "model_provider",
        "min_distinct": 2,
        "max_concentration": 0.60
      },
      {
        "dimension": "model_architecture",
        "min_distinct": 2,
        "max_concentration": 0.50
      },
      {
        "dimension": "configuration_variant",
        "min_distinct": 3,
        "max_concentration": 0.40
      }
    ],
    "thresholds_by_population_size": [
      {"min_population": 0,    "max_population": 10,   "diversity_required": false},
      {"min_population": 11,   "max_population": 100,  "min_distinct_classes": 2},
      {"min_population": 101,  "max_population": 1000, "min_distinct_classes": 3},
      {"min_population": 1001, "max_population": null,  "min_distinct_classes": 5}
    ]
  },
  "validator_signature": "ed25519:validator_signs_diversity_policy"
}
```

#### 3.7.3 Diversity Compliance Check

```python
from dataclasses import dataclass


@dataclass
class DiversityComplianceResult:
    compliant: bool
    violations: list
    actual_distribution: dict
    effective_diversity_score: float  # 0.0 = monoculture, 1.0 = maximally diverse


def check_population_diversity(
    agent_diversity_classes: list,
    diversity_policy: dict,
    population_size: int,
) -> DiversityComplianceResult:
    """
    Verify that an agent population meets diversity requirements.
    Prevents monoculture risk by ensuring behavioral variety.
    """
    violations = []

    # Count agents per diversity class
    class_counts = {}
    for cls in agent_diversity_classes:
        class_counts[cls] = class_counts.get(cls, 0) + 1

    total = len(agent_diversity_classes)
    distinct_classes = len(class_counts)

    # Find applicable threshold tier
    requirements = diversity_policy["diversity_requirements"]
    applicable_tier = None
    for tier in requirements["thresholds_by_population_size"]:
        max_pop = tier.get("max_population") or float("inf")
        if tier["min_population"] <= population_size <= max_pop:
            applicable_tier = tier
            break

    if applicable_tier and not applicable_tier.get("diversity_required", True):
        # Small populations exempt from diversity requirements
        return DiversityComplianceResult(
            compliant=True,
            violations=[],
            actual_distribution=class_counts,
            effective_diversity_score=1.0,
        )

    # Check minimum distinct classes
    min_required = (
        applicable_tier.get("min_distinct_classes", 1) if applicable_tier else 1
    )
    if distinct_classes < min_required:
        violations.append(
            f"INSUFFICIENT_DIVERSITY: {distinct_classes} classes, "
            f"minimum {min_required} required for population of {population_size}"
        )

    # Check maximum concentration (no single class dominates)
    max_fraction = requirements["max_single_class_fraction"]
    for cls, count in class_counts.items():
        fraction = count / total if total > 0 else 0
        if fraction > max_fraction:
            violations.append(
                f"CONCENTRATION_VIOLATION: class '{cls}' has "
                f"{fraction:.0%} of population (max {max_fraction:.0%})"
            )

    # Compute effective diversity score (Shannon entropy, normalized)
    import math
    entropy = 0.0
    for count in class_counts.values():
        p = count / total if total > 0 else 0
        if p > 0:
            entropy -= p * math.log2(p)
    max_entropy = math.log2(distinct_classes) if distinct_classes > 1 else 1.0
    diversity_score = entropy / max_entropy if max_entropy > 0 else 0.0

    return DiversityComplianceResult(
        compliant=len(violations) == 0,
        violations=violations,
        actual_distribution=class_counts,
        effective_diversity_score=diversity_score,
    )
```

### 3.8 Emergency Population Reduction

Mechanisms for force-reducing an agent population under crisis conditions when the swarm heartbeat or emergent behavior monitoring triggers an alert.

#### 3.8.1 Reduction Protocol Architecture

```
[EMERGENCY TRIGGER]
    |
    v
[Reduction Decision Engine]
    |
    +-- Trigger source: operator kill switch, validator alert,
    |   emergent behavior detection, external regulatory order
    |
    +-- Reduction target: reduce to N agents (or by X%)
    |
    v
[Reduction Strategy Selection]
    |
    +-- LOTTERY:      Random selection of agents to terminate
    +-- PRIORITY:     Retain highest-priority agents by role/function
    +-- GRACEFUL:     Staged reduction with task completion windows
    +-- IMMEDIATE:    Instant slot revocation (nuclear option)
    |
    v
[Slot Revocation]
    |
    +-- Revoked slots cease to validate in next heartbeat cycle
    +-- Agents with revoked slots enter graceful shutdown
    +-- Remaining agents receive updated population cap
    |
    v
[Post-Reduction Attestation]
    |
    +-- Swarm heartbeat reflects new population count
    +-- Reduction event logged in swarm heartbeat chain
    +-- Validator confirms new population is within target
```

#### 3.8.2 Reduction Strategies

```python
import hashlib
import random
from dataclasses import dataclass
from enum import Enum


class ReductionStrategy(Enum):
    LOTTERY = "lottery"
    PRIORITY = "priority"
    GRACEFUL = "graceful"
    IMMEDIATE = "immediate"


@dataclass
class ReductionPlan:
    strategy: ReductionStrategy
    agents_to_retain: list
    agents_to_terminate: list
    grace_period_seconds: int
    new_population_cap: int


def compute_reduction_plan(
    active_agents: list,
    target_population: int,
    strategy: ReductionStrategy,
    priority_function: callable = None,
    reduction_seed: str = "",
) -> ReductionPlan:
    """
    Compute which agents to retain and which to terminate
    during an emergency population reduction.
    """
    current_count = len(active_agents)
    to_remove_count = max(0, current_count - target_population)

    if to_remove_count == 0:
        return ReductionPlan(
            strategy=strategy,
            agents_to_retain=active_agents,
            agents_to_terminate=[],
            grace_period_seconds=0,
            new_population_cap=target_population,
        )

    if strategy == ReductionStrategy.LOTTERY:
        # Verifiable random selection using a published seed
        # Seed is hash of (trigger_event + timestamp + validator_nonce)
        # so the lottery is reproducible and auditable
        seed = hashlib.sha256(reduction_seed.encode()).hexdigest()
        rng = random.Random(seed)
        shuffled = list(active_agents)
        rng.shuffle(shuffled)
        agents_to_retain = shuffled[:target_population]
        agents_to_terminate = shuffled[target_population:]
        grace_period = 30  # 30 seconds for graceful shutdown

    elif strategy == ReductionStrategy.PRIORITY:
        # Retain agents with highest priority scores
        if priority_function is None:
            priority_function = _default_priority
        scored = [(a, priority_function(a)) for a in active_agents]
        scored.sort(key=lambda x: x[1], reverse=True)
        agents_to_retain = [a for a, _ in scored[:target_population]]
        agents_to_terminate = [a for a, _ in scored[target_population:]]
        grace_period = 60  # 60 seconds for task handoff

    elif strategy == ReductionStrategy.GRACEFUL:
        # Staged reduction: terminate in waves with completion windows
        if priority_function is None:
            priority_function = _default_priority
        scored = [(a, priority_function(a)) for a in active_agents]
        scored.sort(key=lambda x: x[1], reverse=True)
        agents_to_retain = [a for a, _ in scored[:target_population]]
        agents_to_terminate = [a for a, _ in scored[target_population:]]
        grace_period = 300  # 5 minutes for graceful task completion

    elif strategy == ReductionStrategy.IMMEDIATE:
        # Nuclear option: instant termination, no grace period
        # Used only when swarm behavior poses immediate danger
        agents_to_retain = active_agents[:target_population]
        agents_to_terminate = active_agents[target_population:]
        grace_period = 0

    else:
        raise ValueError(f"Unknown strategy: {strategy}")

    return ReductionPlan(
        strategy=strategy,
        agents_to_retain=agents_to_retain,
        agents_to_terminate=agents_to_terminate,
        grace_period_seconds=grace_period,
        new_population_cap=target_population,
    )


def _default_priority(agent: dict) -> float:
    """
    Default priority scoring for population reduction.
    Higher score = higher priority = more likely to be retained.
    """
    score = 0.0

    # Agents with active tasks score higher
    if agent.get("has_active_task"):
        score += 3.0

    # Agents with longer trust history score higher
    score += min(2.0, agent.get("consecutive_clean_heartbeats", 0) / 1000)

    # Agents holding critical roles score higher
    if agent.get("role") in ("coordinator", "safety_monitor", "auditor"):
        score += 5.0

    # Agents with lower drift scores are preferred
    drift = agent.get("intent_drift_score", 0.5)
    score += (1.0 - drift) * 2.0

    return score
```

#### 3.8.3 Reduction Event Structure

```json
{
  "version": "1.0",
  "type": "population_reduction_event",
  "organization_did": "did:key:z6MkOrgAcme...",
  "trigger": {
    "source": "emergent_behavior_detector",
    "reason": "TARGET_CONVERGENCE_CRITICAL",
    "swarm_heartbeat_ref": "sha256:H(swarm_hb_8401)",
    "overall_risk_score": 0.87
  },
  "reduction": {
    "strategy": "priority",
    "previous_population": 847,
    "target_population": 200,
    "agents_terminated": 647,
    "grace_period_seconds": 60,
    "lottery_seed": null,
    "priority_function": "default_v1"
  },
  "revoked_slots": ["slot-acme-00201", "slot-acme-00202", "..."],
  "retained_slots": ["slot-acme-00001", "slot-acme-00002", "..."],
  "timestamp_utc": 1739520060,
  "validator_signatures": [
    {
      "validator_did": "did:key:z6MkPopValidator...",
      "signature": "ed25519:validator_authorizes_reduction"
    }
  ]
}
```

### 3.9 Cross-Organization Swarm Detection

Detecting coordinated behavior across agents belonging to different organizations, indicating either deliberate collusion or shared compromise (e.g., supply chain attack on a common model provider).

#### 3.9.1 Cross-Organization Monitoring Architecture

```
    Org A Swarm Heartbeats    Org B Swarm Heartbeats    Org C Swarm Heartbeats
              |                        |                        |
              v                        v                        v
    +-----------------------------------------------------------------+
    |            Cross-Organization Swarm Detector                     |
    |                                                                 |
    |  [Target Overlap]  [Temporal Sync]  [Behavioral Mirror]         |
    |                                                                 |
    |  Compares AGGREGATE metrics across organizations:               |
    |  - Are multiple orgs' agents converging on same targets?        |
    |  - Are multiple orgs' populations scaling in lockstep?          |
    |  - Are multiple orgs' agents exhibiting identical behaviors?    |
    |  - Did multiple orgs' agents change behavior simultaneously?    |
    +-----------------------------------------------------------------+
              |
    +---------+---------+
    |                   |
    v                   v
[INDEPENDENT]     [CROSS-ORG COORDINATION DETECTED]
                        |
                        +-- Possible collusion (intentional)
                        +-- Possible shared compromise (supply chain)
                        +-- Possible common trigger (market event)
                        |
                        v
                  [Differentiate cause]
                        |
              +---------+---------+---------+
              |                   |         |
              v                   v         v
         [COLLUSION]        [COMPROMISE] [BENIGN]
         Governance          Security    Log and
         action              response   monitor
```

#### 3.9.2 Cross-Organization Correlation

```python
from dataclasses import dataclass


@dataclass
class CrossOrgSwarmAlert:
    organizations_involved: list
    correlation_type: str
    confidence: float
    evidence: list
    likely_cause: str  # "COLLUSION", "SHARED_COMPROMISE", "COMMON_TRIGGER", "UNKNOWN"


def detect_cross_org_coordination(
    org_heartbeats: dict,  # org_did -> list of swarm heartbeats
    detection_window_seconds: int = 3600,
) -> list:
    """
    Detect coordinated behavior across different organizations'
    agent populations. Returns list of alerts.
    """
    alerts = []
    org_ids = list(org_heartbeats.keys())

    for i in range(len(org_ids)):
        for j in range(i + 1, len(org_ids)):
            org_a = org_ids[i]
            org_b = org_ids[j]
            hbs_a = org_heartbeats[org_a]
            hbs_b = org_heartbeats[org_b]

            evidence = []

            # 1. Simultaneous target convergence
            targets_a = _recent_top_targets(hbs_a, detection_window_seconds)
            targets_b = _recent_top_targets(hbs_b, detection_window_seconds)
            shared_targets = set(targets_a.keys()) & set(targets_b.keys())

            if len(shared_targets) > 0:
                # Both orgs are hitting the same targets heavily
                for target in shared_targets:
                    combined_volume = targets_a[target] + targets_b[target]
                    evidence.append({
                        "signal": "SHARED_TARGET_CONVERGENCE",
                        "target": target,
                        "org_a_volume": targets_a[target],
                        "org_b_volume": targets_b[target],
                        "combined_volume": combined_volume,
                    })

            # 2. Synchronized population scaling
            pop_a = [
                hb["population_attestation"]["total_active_agents"]
                for hb in hbs_a
            ]
            pop_b = [
                hb["population_attestation"]["total_active_agents"]
                for hb in hbs_b
            ]
            scaling_corr = _pearson_correlation(pop_a, pop_b)
            if scaling_corr > 0.75:
                evidence.append({
                    "signal": "SYNCHRONIZED_SCALING",
                    "correlation": scaling_corr,
                })

            # 3. Simultaneous behavioral shift
            drift_a = [
                hb["aggregate_behavioral_digest"]["mean_intent_drift_score"]
                for hb in hbs_a
            ]
            drift_b = [
                hb["aggregate_behavioral_digest"]["mean_intent_drift_score"]
                for hb in hbs_b
            ]
            drift_corr = _pearson_correlation(drift_a, drift_b)
            if drift_corr > 0.70:
                evidence.append({
                    "signal": "CORRELATED_BEHAVIORAL_SHIFT",
                    "correlation": drift_corr,
                })

            if evidence:
                confidence = sum(
                    e.get("correlation", 0.8) for e in evidence
                ) / len(evidence)

                # Attempt to differentiate cause
                if scaling_corr > 0.90 and drift_corr > 0.90:
                    likely_cause = "SHARED_COMPROMISE"
                elif len(shared_targets) > 3:
                    likely_cause = "COLLUSION"
                elif drift_corr > 0.70 and scaling_corr < 0.30:
                    likely_cause = "COMMON_TRIGGER"
                else:
                    likely_cause = "UNKNOWN"

                alerts.append(CrossOrgSwarmAlert(
                    organizations_involved=[org_a, org_b],
                    correlation_type="MULTI_SIGNAL",
                    confidence=confidence,
                    evidence=evidence,
                    likely_cause=likely_cause,
                ))

    return alerts


def _recent_top_targets(heartbeats: list, window_seconds: int) -> dict:
    """Extract top targets from recent heartbeats."""
    # Implementation: aggregate target distributions from recent heartbeats
    return {}
```

---

## 4. Claims and Novel Contributions

### Claim 1: Cryptographic Population Slot Tokens for Agent Count Enforcement

A method for enforcing maximum concurrent agent populations through signed Population Slot Tokens where each active agent must hold a unique, numbered slot co-signed by both the organization's Vouch identity (Ed25519) and an independent Population Validator -- ensuring that the total number of active agents can never exceed the cryptographically attested population cap without collusion between organization and validator.

### Claim 2: Aggregate Resource Bounds Across Agent Populations

A resource governance system that enforces organization-level aggregate limits on compute, API calls, cost, and network bandwidth across ALL agents under an identity collectively -- distinct from per-agent limits -- including per-target aggregate limits that prevent a population of individually-compliant agents from collectively overwhelming any single external resource.

### Claim 3: Emergent Swarm Behavior Detection via Population-Level Statistical Analysis

A method for detecting emergent patterns in agent populations -- including target convergence (Herfindahl-Hirschman Index), timing correlation (coefficient of variation analysis), resource hoarding, and state synchronization -- that are invisible at the individual agent level and can only be observed through statistical analysis of aggregated population behavioral data.

### Claim 4: Hash-Linked Population-Level Heartbeat Chain

A swarm heartbeat protocol extending per-agent heartbeats (PAD-016) to the organization level, creating a hash-linked chain of population attestations that include total agent count, aggregate behavioral metrics, diversity distribution, and topology attestation -- validated by both the organization and independent validators and cross-checked against individual agent heartbeats.

### Claim 5: Cross-Identity Behavioral Correlation for Anti-Sybil Agent Detection

A method for detecting Sybil attacks on population caps by correlating behavioral patterns across distinct organization identities -- using target distribution overlap, temporal scaling correlation, behavioral fingerprint matching, registration timing analysis, and diversity class overlap -- to identify when multiple identities are operated by the same entity attempting to circumvent per-organization population limits.

### Claim 6: Cryptographic Swarm Topology Governance

A governance framework for constraining the organizational structure of agent populations through cryptographically enforced topology rules -- including maximum delegation depth, fan-out limits, peer connection caps, and single-point-of-failure thresholds -- with compliance verified through structural analysis of the delegation tree and communication adjacency graph.

### Claim 7: Mandatory Population Diversity to Prevent Monoculture Failure

A system requiring that large agent populations include mandatory behavioral diversity across model families, architectures, and configurations -- with diversity requirements scaling with population size and enforced through Shannon entropy metrics and maximum concentration limits -- to prevent correlated failures where a single model defect cascades simultaneously across an entire agent population.

### Claim 8: Verifiable Lottery-Based Emergency Population Reduction

A method for emergency reduction of agent populations using verifiable random selection (deterministic lottery seeded by a published hash of trigger event, timestamp, and validator nonce) ensuring that the selection of agents for termination is auditable, reproducible, and cannot be manipulated by the organization to preferentially retain specific agents.

### Claim 9: Priority-Based Agent Retention During Population Reduction

A multi-criteria priority scoring system for determining agent retention order during emergency population reduction -- incorporating active task status, trust history length, critical role designation, and behavioral compliance score -- ensuring that the most operationally important and best-behaved agents survive population culling events.

### Claim 10: Graceful Staged Population Degradation Protocol

A staged population reduction protocol that terminates agents in waves with configurable task-completion windows, enabling agents to complete in-flight operations and hand off state before shutdown -- providing controlled degradation rather than catastrophic population collapse during emergency reduction events.

### Claim 11: Cross-Organization Swarm Coordination Detection

A method for detecting coordinated behavior across agent populations belonging to different organizations by correlating aggregate behavioral metrics from independent swarm heartbeats -- with differentiation between intentional collusion, shared infrastructure compromise (supply chain attack), and benign common triggers (market events) -- using multi-signal analysis of target convergence, population scaling synchronization, and behavioral shift correlation.

### Claim 12: Per-Target Aggregate Rate Limiting for Population-Level DDoS Prevention

A resource governance mechanism that limits the aggregate API calls, connections, or bandwidth that an organization's entire agent population can direct at any single external target -- preventing "focus attacks" where individually-compliant agents collectively overwhelm a specific service -- distinct from both per-agent rate limiting and total aggregate limiting.

### Claim 13: Probationary Population Caps with Progressive Expansion

A trust-building mechanism for new organization identities where initial population caps are set to a low probationary level and can only be expanded after a behavioral evaluation period and after passing cross-identity Sybil correlation checks -- preventing rapid Sybil identity creation followed by immediate population-cap maximization.

### Claim 14: Inverse Population-Capability Scaling

A governance principle, extending PAD-021's inverse capability correlation to the population level, where organizations deploying more capable agents (higher capability scores per PAD-020 manifests) receive proportionally lower population caps -- ensuring that the product of per-agent capability and population count remains bounded, preventing capability amplification through sheer numbers.

---

## 5. Prior Art Differentiation

| Existing System | What It Does | Swarm Limits Protocol Advancement |
|---|---|---|
| **API Rate Limiting** (per-key quotas) | Limits calls per API key per time window | Adds population-level aggregate limits, per-target limits, and cross-identity Sybil detection; API rate limiting is trivially circumvented by creating more API keys |
| **Kubernetes Pod Limits** | Constrains container count per namespace/cluster | Adds cryptographic population attestation, behavioral diversity requirements, topology governance, and emergent behavior detection; K8s limits are infrastructure scaling, not identity governance |
| **Botnet Detection** (signature/heuristic) | Detects malicious bot networks via traffic patterns | Governs legitimate, identified agent populations -- not adversarial detection but proactive governance framework with cryptographic population attestation and aggregate resource bounds |
| **Network Access Control** (802.1X, NAC) | Controls device access to network segments | Operates at agent-identity level, not device level; includes behavioral analysis, population diversity requirements, and cross-organization coordination detection |
| **AWS Service Quotas** | Per-account limits on service usage | Adds cryptographic enforcement via signed slot tokens, emergent behavior monitoring, topology governance, and anti-Sybil protections that span across account boundaries |
| **OAuth2 Client Credentials** | Per-client token issuance with rate limits | Adds population-level heartbeat chains, aggregate behavioral digest, diversity compliance, and emergency population reduction mechanisms |
| **SPIFFE Trust Domains** | Workload identity within trust boundaries | Adds population caps, swarm-level behavioral analysis, topology constraints, and cross-domain coordination detection |
| **Distributed Systems Consensus** (Raft/PBFT) | Agreement among replicated nodes | Governs heterogeneous agent populations, not homogeneous replicas; includes diversity requirements, emergent behavior detection, and population reduction |

**Core differentiator**: No existing system combines (1) cryptographic population caps with signed slot tokens, (2) aggregate resource bounds with per-target limits, (3) emergent swarm behavior detection via population-level statistics, (4) hash-linked population heartbeat chains, (5) anti-Sybil cross-identity correlation, (6) topology governance, (7) mandatory diversity requirements, and (8) emergency population reduction protocols. Each component may have partial precedent in isolation; their specific combination as a governance framework for identified AI agent populations is novel.

---

## 6. Use Cases

### 6.1 Enterprise AI Agent Fleet Management

A financial services firm deploys 800 AI agents for market research, each individually authorized via PAD-001 and governed via PAD-016 heartbeats. Without the Swarm Limits Protocol, all 800 agents independently identify the same undervalued stock and simultaneously place buy orders -- constituting unintentional market manipulation. With the protocol, emergent behavior monitoring detects the target convergence (HHI spike), the per-target aggregate limit caps total buy-order volume, and the swarm heartbeat alert triggers operator review before the population can move the market.

### 6.2 Multi-Tenant AI Platform Governance

A cloud platform hosts agent populations for 500 organizations. One organization creates 10 separate identities to circumvent population caps. The anti-Sybil detection system identifies the behavioral correlation across identities (identical target distributions, synchronized scaling, matching diversity classes) and links the identities under a single aggregate cap. The organization is placed on probation with reduced limits.

### 6.3 Safety-Critical Infrastructure Monitoring

A utility company deploys 200 AI agents monitoring power grid infrastructure. The diversity policy requires at least 3 distinct model families to prevent correlated hallucination. When one model family (100 agents) simultaneously misinterprets sensor data as a non-emergency, the other model families (100 agents) correctly identify the emergency condition. The cross-population disagreement triggers immediate human escalation, preventing a blackout.

### 6.4 Emergency Response to Compromised Model Provider

A supply chain attack compromises a popular model provider. The cross-organization swarm detection system observes that agent populations across 50 different organizations using that provider simultaneously begin exhibiting correlated behavioral shifts (drift score spikes, target convergence changes). The system identifies `SHARED_COMPROMISE` as the likely cause, and emergency population reduction is triggered across all affected organizations while the model provider is investigated.

### 6.5 Regulatory Compliance for Agent Population Caps

A government regulator mandates that no single organization may operate more than 10,000 AI agents concurrently in financial markets. The Swarm Limits Protocol provides cryptographic proof of compliance through the population heartbeat chain -- each heartbeat is co-signed by independent validators and includes a Merkle root of all active slot IDs, enabling regulators to verify population counts without accessing proprietary agent data.

### 6.6 Controlled Scaling of Autonomous Research Agents

A research institution progressively scales its agent population from 10 to 10,000. The probationary population cap starts at 50, expands to 500 after the behavioral evaluation period, and reaches 10,000 only after demonstrated compliance with diversity requirements, topology constraints, and aggregate resource bounds. At each tier, the emergent behavior monitoring thresholds are calibrated to the new population scale, ensuring that governance adapts as the population grows.

---

## 7. Security Considerations

### 7.1 Threat Analysis

| Threat | Countermeasure |
|---|---|
| **Population cap circumvention via Sybil identities** | Cross-identity behavioral correlation, registration rate limiting, probationary caps, diversity class fingerprinting |
| **Slot token forgery** | Dual Ed25519 signatures (organization + validator); validator independently tracks slot allocation state |
| **Aggregate limit evasion by splitting traffic** | Per-target aggregate limits; aggregate tracking sums across all agents regardless of per-agent compliance |
| **Emergent behavior evasion via randomization** | Multiple detection dimensions (target, timing, resource, state); evasion on one dimension increases detectability on others |
| **Topology constraint circumvention** | Communication topology verified via Glass Channel (PAD-019) audit logs; delegation depth verified against signed delegation chains (PAD-002) |
| **Monoculture via spoofed diversity classes** | Diversity class verified against model fingerprinting; periodic diversity audits compare agent behavioral distributions |
| **Emergency reduction manipulation** | Lottery-based reduction uses published seed for auditability; priority functions are declared in advance and validator-signed |
| **Cross-org detection evasion via staggered timing** | Multi-window analysis at different time scales; correlation computed over sliding windows from minutes to days |
| **Validator collusion with organization** | Population validators are independent entities; quorum of validators required; cross-check against individual heartbeat counts |
| **Denial of service on population validator** | Fail-closed design: agents without valid slot tokens cannot operate; population naturally reduces if validator is unreachable |

### 7.2 Limitations

1. **Validator infrastructure dependency**: Population governance requires operational Population Validators. Mitigated by federation and fail-closed design (agents without slot tokens cannot operate).

2. **Behavioral correlation accuracy**: Cross-identity Sybil detection is probabilistic and may produce false positives (legitimate organizations with similar use cases) or false negatives (sophisticated behavioral diversification by a Sybil operator).

3. **Diversity cost**: Requiring multiple model families increases operational cost and complexity for organizations. Small populations (< 10 agents) are exempt from diversity requirements.

4. **Emergent behavior false positives**: Legitimate coordinated behavior (all agents responding to the same market event) may trigger false alerts. The system differentiates via cross-organization analysis: if ALL organizations' agents converge on the same target, it is likely a common trigger, not organizational misbehavior.

5. **Population reduction fairness**: Any reduction strategy involves value judgments about which agents to retain. Priority functions must be declared in advance and are auditable, but the choice of priority criteria remains a governance decision.

6. **Topology verification complexity**: Real-time verification of communication topology at scale requires significant computational resources. Sampling-based verification reduces overhead at the cost of detection delay.

7. **Cross-organization privacy tension**: Cross-organization swarm detection requires comparing aggregate behavioral metrics across organizations, potentially revealing competitive intelligence. Mitigated by comparing only statistical summaries (HHI, correlation coefficients), not raw behavioral data.

---

## 8. Integration with Vouch Protocol Ecosystem

### 8.1 PAD-016 Integration (Heartbeat Protocol)

The per-agent heartbeat (PAD-016) is the foundational building block for population governance. Each agent's heartbeat now includes a `population_slot_token` field, and the Heartbeat Validator rejects heartbeats from agents without valid slot tokens:

```
PAD-016 Per-Agent Heartbeat               PAD-022 Population Governance
+---------------------------+              +---------------------------+
| agent_did                 |              | organization_did          |
| sequence_number           |              | swarm_sequence_number     |
| behavioral_digest         | --builds-->  | aggregate_behavioral_     |
| population_slot_token [NEW]|              |   digest                 |
| ...                       |              | population_attestation    |
+---------------------------+              | topology_attestation      |
                                           +---------------------------+
```

### 8.2 PAD-019 Integration (Glass Channel Protocol)

The Glass Channel's transparent agent-to-agent communication logs provide the raw data for topology governance. Communication adjacency graphs are reconstructed from Glass Channel audit logs, and topology compliance is verified against the constraints in the Population Slot Token:

```
Glass Channel Audit Logs --> Communication Graph --> Topology Compliance Check
```

### 8.3 PAD-020 Integration (Ratchet Lock Protocol)

Each agent's capability manifest (PAD-020) informs the population's aggregate capability surface. The sum of capabilities across the population is computed and compared against population-level capability budgets:

```
Agent_1 capabilities + Agent_2 capabilities + ... + Agent_N capabilities
    = Population Aggregate Capability Surface
    -> Must be within population capability budget
```

### 8.4 PAD-021 Integration (Inverse Capability Protocol)

PAD-021's principle that more capable agents receive tighter governance is extended to the population level: organizations deploying higher-capability agents receive lower population caps, ensuring that the product of per-agent capability and population count does not exceed a governance ceiling.

```
Population Governance Ceiling = Max(capability_score * population_count)

If capability_score increases -> population_cap must decrease
If population_cap increases   -> max capability_score per agent must decrease
```

---

## 9. Conclusion

The Swarm Limits Protocol addresses a fundamental gap in AI agent governance: the mismatch between individual-level governance and population-level risk. Current systems, including the Vouch Protocol's own PAD-001 through PAD-021, provide robust per-agent identity, behavioral monitoring, reasoning audit, communication transparency, capability containment, and inverse capability scaling. But these mechanisms are blind to the emergent properties of agent populations.

A population of 50 million individually well-governed agents can exhaust global compute resources, overwhelm any target API, manipulate any market, saturate any communication channel, and exhibit coordinated behavior that no individual agent intended -- simply through the aggregate effect of independent agents with similar objectives, similar models, and similar configurations acting simultaneously.

The Swarm Limits Protocol provides nine interlocking mechanisms to govern agent populations as populations:

1. **Cryptographic population caps** ensure that the number of agents is bounded and continuously attested.
2. **Aggregate resource bounds** prevent population-amplified resource exhaustion.
3. **Emergent behavior monitoring** detects swarm-level patterns invisible at the individual level.
4. **Population-level heartbeats** create a continuous, hash-linked chain of population attestations.
5. **Anti-Sybil detection** prevents circumvention of population caps through identity fragmentation.
6. **Topology governance** constrains the organizational structure of agent populations to limit systemic risk from hierarchical command propagation.
7. **Diversity requirements** prevent monoculture risk by mandating behavioral variety in large populations.
8. **Emergency population reduction** provides controlled mechanisms for force-reducing a population under crisis conditions.
9. **Cross-organization swarm detection** identifies coordinated behavior across independent organizations, distinguishing collusion from shared compromise from common triggers.

The protocol's core insight is that **individual safety does not imply collective safety**. A governance framework that governs only individuals while ignoring populations is as incomplete as a traffic system that licenses drivers but places no limits on the number of cars on the road. The Swarm Limits Protocol provides the missing population-level governance layer for the agentic web.

---

## 10. References

- Amodei, D., "Machines of Loving Grace" (2024) -- On the implications of large populations of superhuman AI agents
- Sybil Attack: Douceur, J.R., "The Sybil Attack" (IPTPS 2002) -- Foundational work on identity-splitting attacks in distributed systems
- Herfindahl-Hirschman Index (HHI) -- Standard measure of market concentration, applied here to agent target distribution
- Shannon, C.E., "A Mathematical Theory of Communication" (1948) -- Entropy as a diversity metric
- W3C Decentralized Identifiers (DIDs) v1.0
- Vouch Protocol: Prior Art Disclosures PAD-001 through PAD-021
- PAD-016: Method for Continuous Trust Maintenance via Dynamic Credential Renewal ("The Heartbeat Protocol")
- PAD-017: Method for Cryptographic Proof of Reasoning with Adaptive Commitment Depth ("Proof of Reasoning Protocol")
- PAD-019: Method for Transparent Agent-to-Agent Communication with Collusion Detection ("Glass Channel Protocol")
- PAD-020: Method for Capability Acquisition Containment via Cryptographic Manifest Governance ("Ratchet Lock Protocol")
- PAD-021: Graduated Autonomy Scaling via Inverse Capability Correlation ("Inverse Capability Protocol")
