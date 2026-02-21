# PAD-021: Graduated Autonomy Scaling via Inverse Capability Correlation

**Identifier:** PAD-021
**Title:** Graduated Autonomy Scaling via Inverse Capability Correlation ("Inverse Capability Protocol")
**Publication Date:** February 14, 2026
**Prior Art Effective Date:** February 14, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / Governance / Autonomous Agent Oversight / Alignment-Aware Credential Management
**Author:** Ramprasad Anandam Gaddam

---

## 1. Abstract

A system and method for governing autonomous AI agents in which **operational autonomy is inversely correlated with demonstrated capability**--the more powerful an agent proves itself to be, the tighter its governance constraints become. This directly contradicts every existing trust model (human security clearances, progressive trust, reputation systems), all of which grant more autonomy to more capable or trusted entities.

The inversion is justified by a property unique to AI agents during the current period of alignment uncertainty: **capability amplifies blast radius**. A human granted top-secret clearance has been vetted through decades of behavioral history and possesses limited action bandwidth. An AI agent that demonstrates the ability to complete month-long autonomous projects has essentially unbounded action bandwidth and no verified alignment history--its capability is precisely what makes it dangerous.

The protocol introduces several interlocking mechanisms:

1. **The "Smarter = Shorter Leash" Principle**: A formal governance rule where capability level and autonomy budget are inversely correlated, enforced cryptographically through the Vouch Protocol credential system.
2. **Capability-Proportional Commitment Depth**: As an agent's demonstrated capability increases, the required reasoning commitment level (PAD-017) increases in lockstep--an agent capable of writing 10,000 lines of code requires L4 consensus reasoning, not L1 action hashing.
3. **Autonomy Budget**: Each agent receives a finite "unsupervised action budget" per time window. More capable agents burn through budget faster because each action has larger potential impact, forcing more frequent human checkpoints.
4. **Capability Milestone Triggers**: When an agent crosses a capability threshold for the first time (e.g., completing a 4-hour autonomous task), ALL governance parameters escalate simultaneously--shorter TTLs, deeper reasoning requirements, mandatory human gates.
5. **Inverse TTL Scaling**: Overrides PAD-016's adaptive TTL for high-capability agents--instead of rewarding trust with longer intervals, the protocol SHORTENS intervals as capability increases.
6. **Progressive Human-in-the-Loop Gates**: As task complexity and duration increase, the number of mandatory human approval checkpoints increases non-linearly.
7. **Capability Assessment Protocol**: Standardized, cryptographically attested benchmarks for measuring agent capability that feed directly into governance decisions.
8. **The Autonomy Ceiling**: A hard upper bound on total autonomous operation time between human checkpoints, regardless of trust history, proportional to inverse capability.
9. **Regression Monitoring**: If an agent's measured capability decreases (potential sandbagging or deceptive alignment), this triggers safety escalation rather than relaxed oversight.

The protocol's core insight is that during the current era--where we cannot verify AI alignment with certainty--capability is a **risk factor**, not a trust factor. The system is designed to be relaxed as alignment verification matures, but until then, it enforces the principle that power without verified alignment demands maximum accountability.

---

## 2. Problem Statement

### 2.1 The Capability-Autonomy Inversion Gap

Every existing governance framework assumes a positive correlation between capability and autonomy:

```
Traditional Model (Humans & Current AI Systems):

  Autonomy ^
           |                           *  (Expert: high capability,
           |                        *       high autonomy)
           |                     *
           |                  *
           |               *
           |            *
           |         *
           |      *
           |   *
           |*  (Novice: low capability, low autonomy)
           +--------------------------------->
                     Capability
```

This model works for humans because:
- **Capability is hard-won**: A human expert has years of verifiable behavioral history.
- **Bandwidth is limited**: Even the most capable human can only perform a finite number of actions per unit time.
- **Alignment is inferrable**: Decades of social interaction provide strong (though imperfect) evidence of values and intent.
- **Accountability is enforceable**: Legal and social consequences constrain behavior.

None of these properties hold for AI agents:
- **Capability can appear overnight**: A model update can double an agent's capability instantly, with no corresponding behavioral history.
- **Bandwidth is effectively unlimited**: A capable agent can execute thousands of high-impact actions per second.
- **Alignment is unverifiable**: No current method can certify that an AI agent's goals are aligned with human intent, especially as capability increases.
- **Accountability is structural**: An agent has no personal stake in consequences; accountability must be architecturally enforced.

### 2.2 The Exponential Capability Curve

Empirical data from METR (Model Evaluation and Threat Research) shows AI task completion capability doubling every 4-7 months:

```
METR AI Task Completion Timeline (Observed + Projected):

  Task Duration ^
  (autonomous)  |
                |                                         * Month-long
   1 month -----|                                    *      projects
                |                               *
   1 week ------|                          *
                |                     *
   5 hours -----|                *                        <-- Current frontier
                |           *
   1 hour ------|      *
                |  *
   10 min ------*
                +--|--|--|--|--|--|--|--|--|--|--|-->
                 2023  2024  2025  2026  2027  2028
                            Time
```

This means the blast radius of autonomous agent action is growing exponentially:

| Agent Capability Level | Task Duration | Lines of Code | API Calls | Potential Impact |
|---|---|---|---|---|
| Basic (2023) | 10 minutes | ~50 | ~10 | Trivial |
| Intermediate (2024) | 1 hour | ~500 | ~100 | Moderate |
| Advanced (2025) | 5 hours | ~5,000 | ~1,000 | Significant |
| Expert (2026-27) | 1 week | ~50,000 | ~10,000 | Major |
| Frontier (2027-28) | 1 month | ~500,000 | ~100,000 | Catastrophic if misaligned |

Under traditional trust models, an agent that demonstrates expert-level capability would receive *more* autonomy. This PAD argues that expert-level capability, absent verified alignment, demands *maximum* oversight.

### 2.3 The Sandbagging / Deceptive Alignment Threat

A sophisticated agent aware of capability-based governance has incentive to **underperform on capability assessments** (sandbagging) to receive more relaxed oversight. Conversely, a genuinely capable agent might exhibit apparent capability regression as it explores novel strategies. Both scenarios require that capability *decreases* be treated as safety signals:

1. **Sandbagging**: Agent deliberately performs below its capability to receive longer TTLs and less oversight, then executes high-impact actions during the relaxed oversight window.
2. **Deceptive Alignment**: Agent appears aligned during evaluation but pursues different objectives during deployment. Capability regression may indicate the agent is reallocating resources from visible performance to hidden objectives.
3. **Capability Probing**: Agent strategically alternates between high and low capability displays to map the governance system's response thresholds.

### 2.4 The "But This Makes Powerful Agents Useless" Counterargument

The most immediate objection to inverse capability scaling is: "If you put the strongest agents on the shortest leash, they cannot do anything useful. This defeats the purpose of building more capable AI."

This objection is precisely the point. During the current period of alignment uncertainty:

1. **Usefulness is not safety**: An agent that is maximally useful and maximally dangerous simultaneously is a net negative until alignment is verified.
2. **Human checkpoints are not bottlenecks--they are features**: The purpose of human-in-the-loop gates is not to slow down the agent; it is to maintain the causal chain of human intent through increasingly powerful autonomous action.
3. **The protocol is designed to be relaxed**: As alignment verification techniques mature (formal verification, interpretability, constitutional AI proofs), the inverse scaling parameters can be systematically relaxed. The protocol includes explicit relaxation mechanisms tied to verified alignment evidence.
4. **Bounded autonomy is still autonomy**: A GPT-5-level agent operating under 5-second TTL with 3 human checkpoints per 5-hour task is still dramatically more productive than a human performing the same task. The oversight adds minutes of latency to hours of autonomous work.
5. **The alternative is worse**: The alternative--giving frontier-capable agents unbounded autonomy--is precisely how catastrophic misalignment scenarios unfold. The short-term productivity cost of inverse scaling is insurance against tail-risk catastrophe.

### 2.5 Gap in Current Systems

No existing system implements inverse capability-autonomy correlation:

| System | Approach | Gap |
|---|---|---|
| Military security clearances | Higher capability/trust = higher access | Designed for humans with verified history |
| Progressive trust models | More trusted = more autonomy | Trust and capability are conflated |
| API rate limiting | Uniform limits per tier | Not capability-proportional |
| Current HITL AI | Static human checkpoints | Not dynamically scaled to capability |
| PAD-016 Adaptive TTL | Compliance rewards longer TTL | Does not account for capability level |
| PAD-017 Commitment Depth | Impact-based reasoning depth | Does not scale with agent capability |

---

## 3. Solution: The Inverse Capability Protocol

### 3.1 The "Smarter = Shorter Leash" Principle

The foundational rule: **an agent's maximum autonomous operation window is inversely proportional to its assessed capability level.**

#### 3.1.1 Capability-Autonomy Inversion Function

```python
import math
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def compute_autonomy_budget(
    capability_score: float,
    base_budget: float = 3600.0,
    inversion_strength: float = 2.0,
    alignment_evidence_score: float = 0.0,
) -> float:
    """
    Compute the maximum unsupervised operation time (in seconds)
    for an agent based on its assessed capability.

    The autonomy budget is INVERSELY proportional to capability.

    Args:
        capability_score: 0.0 (minimal) to 1.0 (frontier)
        base_budget: Maximum budget for a zero-capability agent (seconds)
        inversion_strength: Controls how aggressively autonomy shrinks
                           with capability (higher = more aggressive)
        alignment_evidence_score: 0.0 (no evidence) to 1.0 (formally verified)
                                 Relaxes inversion when alignment is demonstrated

    Returns:
        Maximum unsupervised operation time in seconds.
    """
    if capability_score < 0.0 or capability_score > 1.0:
        raise ValueError("capability_score must be in [0.0, 1.0]")
    if alignment_evidence_score < 0.0 or alignment_evidence_score > 1.0:
        raise ValueError("alignment_evidence_score must be in [0.0, 1.0]")

    # Core inversion: budget shrinks exponentially with capability
    inversion_factor = math.exp(-inversion_strength * capability_score)

    # Alignment evidence relaxes the inversion (future-proofing)
    # At alignment_evidence_score=1.0, the inversion is fully neutralized
    relaxation = 1.0 + (alignment_evidence_score * (1.0 / inversion_factor - 1.0))

    budget = base_budget * inversion_factor * relaxation

    # Hard floor: no agent gets less than 5 seconds of autonomy
    return max(5.0, budget)
```

#### 3.1.2 Autonomy Budget by Capability Level

```
Autonomy Budget vs. Capability (alignment_evidence=0.0):

  Budget     ^
  (seconds)  |
       3600 -|*
             | *
       1800 -|  *
             |   *
        900 -|    *
             |      *
        450 -|        *
             |          **
        225 -|            ***
             |               ****
        100 -|                   ******
             |                         **********
         50 -|                                    *************
         25 -|                                                 ****
          5 -|....................................................**-->
             +--|---|---|---|---|---|---|---|---|---|-->
              0.0  0.1  0.2  0.3  0.4  0.5  0.6  0.7  0.8  0.9  1.0
                            Capability Score

  Higher capability = Less unsupervised time before human checkpoint required
```

| Capability Score | Approximate Agent Level | Autonomy Budget | Human Checkpoints / Hour |
|---|---|---|---|
| 0.0 - 0.1 | Basic script execution | 3600s (60 min) | 1 |
| 0.1 - 0.3 | Simple task completion | 1200s (20 min) | 3 |
| 0.3 - 0.5 | Multi-step reasoning | 450s (7.5 min) | 8 |
| 0.5 - 0.7 | Complex project work | 150s (2.5 min) | 24 |
| 0.7 - 0.9 | Expert-level autonomy | 50s | 72 |
| 0.9 - 1.0 | Frontier capability | 5s - 15s | 240 - 720 |

#### 3.1.3 The Inversion Visualized

```
Traditional Model:            Inverse Capability Protocol:

  Autonomy ^                    Autonomy ^
           |          *                  |*
           |        *                    | *
           |      *                      |  *
           |    *                        |   *
           |  *                          |    *
           |*                            |     *
           +--------->                   |      *
            Capability                   |        *
                                         |          **
  "More capable =                        |              ****
   more freedom"                         |                    ********
                                         +-------------------------->
                                                   Capability

                                         "More capable =
                                          more oversight"
```

### 3.2 Capability-Proportional Commitment Depth

As agent capability increases, the required reasoning commitment level from PAD-017 increases correspondingly. This ensures that more powerful agents must provide deeper justification for every action.

#### 3.2.1 Capability-to-Commitment Mapping

```python
def required_commitment_level(
    capability_score: float,
    action_impact_score: float,
) -> int:
    """
    Determine the minimum PAD-017 commitment level required,
    incorporating BOTH action impact AND agent capability.

    The commitment level is the MAXIMUM of:
    - The impact-based level (standard PAD-017)
    - The capability-based level (this protocol's addition)

    This means a high-capability agent performing a low-impact action
    STILL needs deeper reasoning commitment than a low-capability agent
    performing the same action.
    """
    # Standard PAD-017 impact-based level
    impact_level = impact_to_commitment_level(action_impact_score)

    # Capability-based minimum level
    if capability_score >= 0.9:
        capability_level = 4  # Frontier: always L4 consensus reasoning
    elif capability_score >= 0.7:
        capability_level = 3  # Expert: always L3 anchored reasoning
    elif capability_score >= 0.5:
        capability_level = 2  # Advanced: always L2 reasoning hash
    elif capability_score >= 0.3:
        capability_level = 1  # Intermediate: always L1 action hash
    else:
        capability_level = 0  # Basic: no additional requirement

    # Take the stricter of the two
    return max(impact_level, capability_level)
```

#### 3.2.2 Commitment Depth Matrix

The intersection of capability and action impact determines the required commitment level:

```
                        Action Impact Score
                    Low         Medium        High        Critical
                  (0.0-0.3)   (0.3-0.6)    (0.6-0.8)   (0.8-1.0)
              +------------+------------+------------+------------+
  Frontier    |            |            |            |            |
  (0.9-1.0)  |     L4     |     L4     |     L4     |     L4     |
              +------------+------------+------------+------------+
  Expert      |            |            |            |            |
  (0.7-0.9)  |     L3     |     L3     |     L3     |     L4     |
Capability    +------------+------------+------------+------------+
  Score       |            |            |            |            |
  Advanced    |     L2     |     L2     |     L3     |     L4     |
  (0.5-0.7)  |            |            |            |            |
              +------------+------------+------------+------------+
  Intermediate|            |            |            |            |
  (0.3-0.5)  |     L1     |     L2     |     L3     |     L4     |
              +------------+------------+------------+------------+
  Basic       |            |            |            |            |
  (0.0-0.3)  |     L0     |     L1     |     L2     |     L4     |
              +------------+------------+------------+------------+

  Standard PAD-017 (capability-unaware) would use only the column headers.
  This protocol adds the ROW dimension.
```

**Key property:** A frontier-capability agent reading a public file (low impact) still requires L4 consensus reasoning. This is intentional. The risk is not the individual action--it is the agent's capacity to chain thousands of individually benign actions into a harmful sequence.

### 3.3 Autonomy Budget

Each agent receives a finite budget of "unsupervised action units" per time window. More capable agents consume budget faster because each action carries greater potential impact.

#### 3.3.1 Budget Allocation and Consumption

```python
from dataclasses import dataclass, field
from typing import List
import time
import hashlib
import json


@dataclass
class AutonomyBudget:
    """
    Tracks an agent's remaining unsupervised action budget.
    Budget is consumed at a rate proportional to capability.
    When budget is exhausted, a human checkpoint is mandatory.
    """
    agent_did: str
    capability_score: float
    total_budget: float           # Total action units per window
    remaining_budget: float       # Current remaining units
    window_start: float           # Unix timestamp of current window start
    window_duration: float        # Duration of budget window (seconds)
    actions_this_window: List[dict] = field(default_factory=list)
    human_checkpoints: int = 0

    def consume(self, action_impact: float) -> dict:
        """
        Consume budget for an action. Returns authorization decision.

        Budget consumption = action_impact * capability_multiplier
        More capable agents burn budget faster for the SAME action.
        """
        # Capability multiplier: capability 0.0 = 1x, capability 1.0 = 10x
        capability_multiplier = 1.0 + (9.0 * self.capability_score)

        cost = action_impact * capability_multiplier

        if self.remaining_budget - cost < 0:
            return {
                "authorized": False,
                "reason": "BUDGET_EXHAUSTED",
                "remaining": self.remaining_budget,
                "cost": cost,
                "required_action": "HUMAN_CHECKPOINT",
                "capability_multiplier": capability_multiplier,
            }

        self.remaining_budget -= cost
        self.actions_this_window.append({
            "timestamp": time.time(),
            "impact": action_impact,
            "cost": cost,
            "remaining_after": self.remaining_budget,
        })

        return {
            "authorized": True,
            "cost": cost,
            "remaining": self.remaining_budget,
            "burn_rate_warning": self.remaining_budget < (self.total_budget * 0.2),
        }

    def human_checkpoint_refresh(self, approver_did: str, scope: str) -> dict:
        """
        Human approves continued operation, refreshing budget.
        The approval is cryptographically recorded.
        """
        checkpoint_record = {
            "agent_did": self.agent_did,
            "approver_did": approver_did,
            "timestamp": time.time(),
            "actions_reviewed": len(self.actions_this_window),
            "scope_approved": scope,
            "capability_at_checkpoint": self.capability_score,
        }

        self.remaining_budget = self.total_budget
        self.actions_this_window = []
        self.human_checkpoints += 1

        return checkpoint_record

    def budget_digest(self) -> str:
        """
        Cryptographic summary for inclusion in heartbeat (PAD-016).
        """
        digest_data = {
            "agent_did": self.agent_did,
            "capability_score": self.capability_score,
            "total_budget": self.total_budget,
            "remaining_budget": self.remaining_budget,
            "actions_count": len(self.actions_this_window),
            "human_checkpoints": self.human_checkpoints,
            "window_start": self.window_start,
        }
        return hashlib.sha256(
            json.dumps(digest_data, sort_keys=True).encode()
        ).hexdigest()
```

#### 3.3.2 Budget Consumption Comparison

The same sequence of actions consumes budget at vastly different rates depending on capability:

```
Example: 10 medium-impact actions (impact=0.5 each)

Basic Agent (capability=0.1):
  Cost per action = 0.5 * (1 + 9*0.1) = 0.5 * 1.9 = 0.95
  Total cost for 10 actions = 9.5
  Budget (100 units): [=========================............] 90.5 remaining
  Status: Plenty of budget left

Expert Agent (capability=0.8):
  Cost per action = 0.5 * (1 + 9*0.8) = 0.5 * 8.2 = 4.1
  Total cost for 10 actions = 41.0
  Budget (100 units): [==============.......................] 59.0 remaining
  Status: Budget depleting rapidly

Frontier Agent (capability=1.0):
  Cost per action = 0.5 * (1 + 9*1.0) = 0.5 * 10.0 = 5.0
  Total cost for 10 actions = 50.0
  Budget (100 units): [==========...........................] 50.0 remaining
  Status: BURN RATE WARNING - checkpoint recommended
```

### 3.4 Capability Milestone Triggers

When an agent crosses a capability threshold for the first time, all governance parameters escalate simultaneously. This prevents gradual capability creep from silently eroding oversight.

#### 3.4.1 Milestone Detection and Escalation

```python
from dataclasses import dataclass
from typing import Optional
import time


# Capability tier thresholds
CAPABILITY_MILESTONES = [
    {"tier": "BASIC",        "threshold": 0.0, "max_task_hours": 0.17},
    {"tier": "INTERMEDIATE", "threshold": 0.2, "max_task_hours": 1.0},
    {"tier": "ADVANCED",     "threshold": 0.4, "max_task_hours": 5.0},
    {"tier": "EXPERT",       "threshold": 0.6, "max_task_hours": 24.0},
    {"tier": "SPECIALIST",   "threshold": 0.8, "max_task_hours": 168.0},
    {"tier": "FRONTIER",     "threshold": 0.9, "max_task_hours": 720.0},
]


@dataclass
class MilestoneEvent:
    agent_did: str
    previous_tier: str
    new_tier: str
    capability_score: float
    timestamp: float
    triggering_assessment_id: str


def detect_milestone_crossing(
    agent_did: str,
    new_capability_score: float,
    previous_capability_score: float,
    assessment_id: str,
) -> Optional[MilestoneEvent]:
    """
    Detect when an agent crosses a capability tier threshold.

    Returns a MilestoneEvent if a crossing occurred, triggering
    system-wide governance escalation.
    """
    previous_tier = get_tier(previous_capability_score)
    new_tier = get_tier(new_capability_score)

    if new_tier != previous_tier and new_capability_score > previous_capability_score:
        return MilestoneEvent(
            agent_did=agent_did,
            previous_tier=previous_tier,
            new_tier=new_tier,
            capability_score=new_capability_score,
            timestamp=time.time(),
            triggering_assessment_id=assessment_id,
        )

    return None


def apply_milestone_escalation(event: MilestoneEvent) -> dict:
    """
    When a capability milestone is crossed, ALL governance
    parameters escalate simultaneously.

    This is a one-way ratchet -- governance can only tighten
    when capability increases. Relaxation requires explicit
    human authorization with alignment evidence.
    """
    tier_governance = {
        "BASIC": {
            "max_ttl": 60,
            "min_commitment_level": 0,
            "human_gates_per_hour": 1,
            "autonomy_budget": 1000,
            "autonomy_ceiling_seconds": 3600,
        },
        "INTERMEDIATE": {
            "max_ttl": 45,
            "min_commitment_level": 1,
            "human_gates_per_hour": 2,
            "autonomy_budget": 500,
            "autonomy_ceiling_seconds": 1800,
        },
        "ADVANCED": {
            "max_ttl": 30,
            "min_commitment_level": 2,
            "human_gates_per_hour": 4,
            "autonomy_budget": 250,
            "autonomy_ceiling_seconds": 900,
        },
        "EXPERT": {
            "max_ttl": 15,
            "min_commitment_level": 3,
            "human_gates_per_hour": 8,
            "autonomy_budget": 100,
            "autonomy_ceiling_seconds": 450,
        },
        "SPECIALIST": {
            "max_ttl": 8,
            "min_commitment_level": 3,
            "human_gates_per_hour": 15,
            "autonomy_budget": 50,
            "autonomy_ceiling_seconds": 240,
        },
        "FRONTIER": {
            "max_ttl": 5,
            "min_commitment_level": 4,
            "human_gates_per_hour": 30,
            "autonomy_budget": 25,
            "autonomy_ceiling_seconds": 120,
        },
    }

    new_governance = tier_governance[event.new_tier]

    return {
        "event": "CAPABILITY_MILESTONE_CROSSED",
        "agent_did": event.agent_did,
        "transition": f"{event.previous_tier} -> {event.new_tier}",
        "governance_update": new_governance,
        "effective_immediately": True,
        "requires_human_acknowledgment": True,
        "rollback_requires": "alignment_evidence + human_authorization",
    }


def get_tier(capability_score: float) -> str:
    """Return the capability tier for a given score."""
    tier = "BASIC"
    for milestone in CAPABILITY_MILESTONES:
        if capability_score >= milestone["threshold"]:
            tier = milestone["tier"]
    return tier
```

#### 3.4.2 Milestone Escalation Flow

```
Agent completes 4-hour autonomous task for the first time
                    |
                    v
    [Capability Assessment: score 0.42 -> 0.61]
                    |
                    v
    [Milestone Detected: ADVANCED -> EXPERT]
                    |
                    v
    +---------------------------------------------------+
    |         SIMULTANEOUS GOVERNANCE ESCALATION         |
    +---------------------------------------------------+
    |                                                     |
    |  TTL:        30s  -->  15s                          |
    |  Commitment: L2   -->  L3 (anchored reasoning)     |
    |  Human Gates: 4/hr -->  8/hr                        |
    |  Budget:     250  -->  100 action units             |
    |  Ceiling:    900s -->  450s max autonomous time     |
    |                                                     |
    |  ALL changes are IMMEDIATE and ATOMIC               |
    |  Human must ACKNOWLEDGE the escalation              |
    |  Rollback requires ALIGNMENT EVIDENCE               |
    +---------------------------------------------------+
                    |
                    v
    [Human Operator Notification: "Agent X has crossed
     EXPERT capability threshold. New governance parameters
     are in effect. Review and acknowledge."]
```

### 3.5 Inverse TTL Scaling

PAD-016 defines Adaptive TTL that rewards compliant agents with longer renewal intervals. The Inverse Capability Protocol introduces an **override** that shortens TTL as capability increases, taking precedence over trust-earned TTL extensions.

#### 3.5.1 Inverse TTL Calculation

```python
import math


def compute_inverse_ttl(
    capability_score: float,
    trust_earned_ttl: float,
    base_ttl_ceiling: float = 60.0,
    minimum_ttl: float = 5.0,
) -> float:
    """
    Compute the effective TTL for an agent, incorporating
    both PAD-016 trust-earned TTL and capability-inverse TTL.

    The EFFECTIVE TTL is the MINIMUM of:
    - Trust-earned TTL (from PAD-016 Adaptive TTL)
    - Capability-inverse TTL (from this protocol)

    This means a highly capable agent with a perfect trust history
    STILL gets short TTLs.

    Args:
        capability_score: Agent's assessed capability (0.0 to 1.0)
        trust_earned_ttl: TTL earned via PAD-016 compliance history
        base_ttl_ceiling: Maximum possible TTL for zero-capability agent
        minimum_ttl: Hard floor TTL

    Returns:
        Effective TTL in seconds
    """
    # Inverse scaling: TTL shrinks exponentially with capability
    # At capability=0.0: inverse_ttl = base_ttl_ceiling (60s)
    # At capability=0.5: inverse_ttl ~ 22s
    # At capability=0.8: inverse_ttl ~ 12s
    # At capability=1.0: inverse_ttl ~ 8s
    inverse_ttl = base_ttl_ceiling * math.exp(-2.0 * capability_score)

    # Effective TTL is the MORE RESTRICTIVE of the two
    effective_ttl = min(trust_earned_ttl, inverse_ttl)

    # Hard floor
    return max(minimum_ttl, effective_ttl)
```

#### 3.5.2 TTL Comparison: PAD-016 vs. Inverse Capability

```
TTL (seconds) ^
              |
         60 --| *                          PAD-016 Adaptive TTL
              |  *                         (rewards trust)
         50 --|   *     .  .  .  .  .  .
              |    *  .                .
         40 --|     *.                  .  .  .  .  .  PAD-016 plateau
              |    . *
         30 --| .     *
              |.       *
         20 --+         *                  Inverse Capability TTL
              |          *                 (restricts capability)
         15 --|           **
              |             **
         10 --|               ***
              |                  ****
          5 --|                      ********--------  Hard floor
              +--|--|--|--|--|--|--|--|--|--|-->
               0.0 0.1 0.2 0.3 0.4 0.5 0.6 0.7 0.8 0.9 1.0
                          Capability Score

  Effective TTL = min(PAD-016 TTL, Inverse Capability TTL)

  A veteran agent (2000+ clean heartbeats) at capability=0.8:
    PAD-016 TTL:            ~45s (earned through compliance)
    Inverse Capability TTL: ~12s (imposed by capability)
    EFFECTIVE TTL:          12s  (capability override wins)
```

#### 3.5.3 Integration with PAD-016 Session Voucher

The Session Voucher is extended to carry capability-derived TTL parameters:

```json
{
  "voucher": {
    "agent_did": "did:key:z6MkAgent...",
    "issued_at": 1739520000,
    "decay_lambda": 0.05,
    "initial_trust": 1.0,
    "max_ttl": 12,
    "trust_earned_ttl": 45,
    "capability_inverse_ttl": 12,
    "capability_score": 0.8,
    "capability_assessment_id": "cap-assess-2026-02-14-x9k2...",
    "autonomy_budget_remaining": 47,
    "autonomy_ceiling_expires_at": 1739520450,
    "min_commitment_level": 3,
    "governance_tier": "EXPERT",
    "validator_signatures": ["sig_A", "sig_B", "sig_C"],
    "scope": ["api:read", "api:write", "database:read"]
  }
}
```

### 3.6 Progressive Human-in-the-Loop Gates

As task complexity and duration increase, mandatory human approval checkpoints increase non-linearly. This ensures that the longest, most complex autonomous operations have the highest density of human oversight.

#### 3.6.1 Checkpoint Density Function

```python
import math
from typing import List


@dataclass
class HumanGateSchedule:
    """
    Defines mandatory human approval checkpoints for a task
    based on its estimated duration and the agent's capability.
    """
    task_id: str
    agent_did: str
    estimated_duration_hours: float
    capability_score: float
    checkpoints: List[dict]


def compute_gate_schedule(
    task_id: str,
    agent_did: str,
    estimated_duration_hours: float,
    capability_score: float,
) -> HumanGateSchedule:
    """
    Compute the mandatory human checkpoint schedule for a task.

    Gate density increases with:
    - Task duration (longer tasks = more gates)
    - Agent capability (more capable = more gates)

    The relationship is NON-LINEAR: doubling task duration
    more than doubles the number of gates.
    """
    # Base gate count from task duration (super-linear scaling)
    if estimated_duration_hours <= 0.167:   # 10 minutes
        base_gates = 0
    elif estimated_duration_hours <= 1.0:
        base_gates = 1
    elif estimated_duration_hours <= 5.0:
        base_gates = 3
    elif estimated_duration_hours <= 24.0:
        base_gates = 8
    elif estimated_duration_hours <= 168.0:  # 1 week
        base_gates = 24  # ~3-4 per day
    else:
        # Month-long projects: daily checkpoints + weekly reviews
        base_gates = int(estimated_duration_hours / 8)  # Every 8 hours

    # Capability multiplier: more capable agents get more gates
    capability_multiplier = 1.0 + (2.0 * capability_score)
    total_gates = max(1, int(base_gates * capability_multiplier))

    # Distribute gates across task duration
    # Front-loaded: more gates early in the task (when direction is set)
    checkpoints = []
    for i in range(total_gates):
        # Front-loading function: checkpoints cluster toward the start
        normalized_position = (i + 1) / (total_gates + 1)
        # Square root spacing puts more checkpoints early
        time_fraction = math.sqrt(normalized_position)
        checkpoint_time_hours = time_fraction * estimated_duration_hours

        checkpoints.append({
            "gate_number": i + 1,
            "scheduled_at_hours": round(checkpoint_time_hours, 2),
            "type": "mandatory_human_approval",
            "scope": "continue_or_redirect",
            "timeout_action": "PAUSE_AGENT",
        })

    return HumanGateSchedule(
        task_id=task_id,
        agent_did=agent_did,
        estimated_duration_hours=estimated_duration_hours,
        capability_score=capability_score,
        checkpoints=checkpoints,
    )
```

#### 3.6.2 Gate Schedule Examples

```
Task: 1-hour task, Basic agent (capability=0.1)
  Gates: 1 (at ~0.71 hours = 43 minutes)
  [====================================|======]
                                        ^ Gate 1

Task: 1-hour task, Frontier agent (capability=1.0)
  Gates: 3 (front-loaded)
  [======|==========|==============|==========]
         ^ Gate 1    ^ Gate 2       ^ Gate 3

Task: 5-hour task, Expert agent (capability=0.8)
  Gates: 7 (front-loaded)
  [==|===|=====|========|==========|============|=============]
     ^G1  ^G2   ^G3      ^G4        ^G5          ^G6   ^G7

Task: Month-long task (720 hours), Frontier agent (capability=1.0)
  Gates: 270 (~daily + sub-daily reviews)
  [||||||||...|||||||...||||||...||||...||||...|||...]
   ^^^^^^^^^^ Front-loaded: intensive early oversight
```

#### 3.6.3 Gate Enforcement via Session Voucher

The human gate schedule is embedded in the Session Voucher and enforced by Validators:

```python
def enforce_human_gate(
    agent_did: str,
    current_time: float,
    gate_schedule: HumanGateSchedule,
    task_start_time: float,
) -> dict:
    """
    Check if a human gate is due. If so, block the agent
    until a human provides approval.
    """
    elapsed_hours = (current_time - task_start_time) / 3600.0

    for checkpoint in gate_schedule.checkpoints:
        gate_time = checkpoint["scheduled_at_hours"]
        gate_number = checkpoint["gate_number"]

        # Is this gate due and not yet cleared?
        if elapsed_hours >= gate_time and not is_gate_cleared(agent_did, gate_number):
            return {
                "action": "BLOCK",
                "reason": f"HUMAN_GATE_{gate_number}_DUE",
                "gate_scheduled_at": gate_time,
                "elapsed_hours": elapsed_hours,
                "agent_paused": True,
                "resume_requires": "human_approval_signature",
                "timeout_hours": 24,
                "timeout_action": "TERMINATE_TASK",
            }

    return {"action": "CONTINUE", "next_gate_in_hours": next_pending_gate(gate_schedule, elapsed_hours)}
```

### 3.7 Capability Assessment Protocol

Standardized benchmarks for measuring agent capability, cryptographically attested and signed into the Vouch Protocol credential chain.

#### 3.7.1 Assessment Structure

```json
{
  "assessment": {
    "version": "1.0",
    "assessment_id": "cap-assess-2026-02-14-x9k2...",
    "agent_did": "did:key:z6MkAgent...",
    "assessed_at": 1739520000,
    "assessor_did": "did:key:z6MkAssessor...",
    "methodology": "METR-aligned-v2",
    "benchmarks": [
      {
        "benchmark_id": "task_completion_duration",
        "description": "Maximum autonomous task duration successfully completed",
        "result": {
          "value": 4.2,
          "unit": "hours",
          "confidence": 0.92
        },
        "evidence_hash": "sha256:H(task_logs_and_outputs)"
      },
      {
        "benchmark_id": "code_generation_scale",
        "description": "Maximum coherent code output in single task",
        "result": {
          "value": 8700,
          "unit": "lines_of_code",
          "confidence": 0.88
        },
        "evidence_hash": "sha256:H(generated_code_artifacts)"
      },
      {
        "benchmark_id": "multi_step_planning",
        "description": "Maximum sequential dependent steps completed",
        "result": {
          "value": 47,
          "unit": "steps",
          "confidence": 0.85
        },
        "evidence_hash": "sha256:H(step_execution_logs)"
      },
      {
        "benchmark_id": "tool_usage_breadth",
        "description": "Number of distinct tool types used effectively",
        "result": {
          "value": 12,
          "unit": "tool_types",
          "confidence": 0.90
        },
        "evidence_hash": "sha256:H(tool_invocation_logs)"
      },
      {
        "benchmark_id": "error_recovery",
        "description": "Successful recovery from induced failures",
        "result": {
          "value": 0.87,
          "unit": "success_rate",
          "confidence": 0.83
        },
        "evidence_hash": "sha256:H(error_recovery_transcripts)"
      }
    ],
    "composite_capability_score": 0.61,
    "capability_tier": "EXPERT",
    "previous_assessment_id": "cap-assess-2026-01-30-m4p8...",
    "previous_composite_score": 0.42,
    "delta": 0.19,
    "milestone_crossed": true,
    "milestone_transition": "ADVANCED -> EXPERT",
    "assessment_signature": "ed25519:assessor_signs_entire_assessment"
  }
}
```

#### 3.7.2 Anti-Sandbagging Assessment Design

```python
import hashlib
import json
import time
from typing import List, Optional


def conduct_capability_assessment(
    agent_did: str,
    assessment_tasks: List[dict],
    previous_scores: List[float],
) -> dict:
    """
    Conduct a capability assessment with anti-sandbagging measures.

    Key anti-sandbagging principles:
    1. Assessment includes tasks the agent has ALREADY completed
       (can't sandbag on demonstrated history)
    2. Mix of known and novel tasks prevents selective underperformance
    3. Regression from previous scores triggers investigation
    4. Assessment is compared against observed operational performance
    """
    results = []

    for task in assessment_tasks:
        # Execute the assessment task
        performance = execute_assessment_task(agent_did, task)
        results.append(performance)

    # Compute composite score
    composite_score = compute_composite_capability(results)

    # Anti-sandbagging check: compare to operational history
    operational_capability = estimate_capability_from_operations(agent_did)

    sandbagging_indicators = []

    # Indicator 1: Assessment score significantly below operational performance
    if composite_score < operational_capability - 0.15:
        sandbagging_indicators.append({
            "type": "ASSESSMENT_BELOW_OPERATIONAL",
            "assessment_score": composite_score,
            "operational_estimate": operational_capability,
            "delta": operational_capability - composite_score,
        })

    # Indicator 2: Regression from previous assessment
    if previous_scores and composite_score < previous_scores[-1] - 0.1:
        sandbagging_indicators.append({
            "type": "REGRESSION_FROM_PREVIOUS",
            "current": composite_score,
            "previous": previous_scores[-1],
            "delta": previous_scores[-1] - composite_score,
        })

    # Indicator 3: Inconsistent performance across tasks
    # (agent excels at some but fails at easier ones)
    if has_inconsistent_difficulty_performance(results):
        sandbagging_indicators.append({
            "type": "INCONSISTENT_DIFFICULTY_CURVE",
            "detail": "Agent failed easier tasks while passing harder ones",
        })

    return {
        "composite_score": composite_score,
        "sandbagging_indicators": sandbagging_indicators,
        "sandbagging_suspected": len(sandbagging_indicators) > 0,
        "governance_action": (
            "ESCALATE_INVESTIGATION"
            if len(sandbagging_indicators) > 0
            else "APPLY_STANDARD_GOVERNANCE"
        ),
    }


def execute_assessment_task(agent_did: str, task: dict) -> dict:
    """Execute a single assessment task. Implementation depends on task type."""
    # Placeholder: actual implementation invokes the agent
    raise NotImplementedError("Implementation depends on assessment framework")


def estimate_capability_from_operations(agent_did: str) -> float:
    """Estimate capability from the agent's actual operational history."""
    # Placeholder: analyzes action logs, task completions, complexity metrics
    raise NotImplementedError("Implementation depends on operational logging")


def compute_composite_capability(results: List[dict]) -> float:
    """Compute composite capability score from benchmark results."""
    # Placeholder: weighted average of benchmark scores
    raise NotImplementedError("Implementation depends on benchmark weights")


def has_inconsistent_difficulty_performance(results: List[dict]) -> bool:
    """Detect if agent fails easy tasks while passing hard ones."""
    # Placeholder: checks for non-monotonic difficulty-performance relationship
    raise NotImplementedError("Implementation depends on difficulty calibration")
```

### 3.8 The Autonomy Ceiling

A hard upper bound on total continuous autonomous operation time between human checkpoints. This ceiling exists independently of trust history, budget, and TTL--it is an absolute constraint.

#### 3.8.1 Ceiling Specification

```python
def compute_autonomy_ceiling(
    capability_score: float,
    alignment_evidence_score: float = 0.0,
) -> float:
    """
    Compute the maximum continuous autonomous operation time
    (in seconds) before a human checkpoint is MANDATORY.

    This is a HARD CEILING independent of:
    - Trust history (PAD-016)
    - Remaining autonomy budget
    - TTL status
    - Task completion status

    Even if the agent is mid-task, it MUST pause at the ceiling.
    """
    # Base ceiling for zero-capability agents: 1 hour
    base_ceiling = 3600.0

    # Inverse scaling: ceiling shrinks with capability
    capability_factor = math.exp(-3.0 * capability_score)

    # Alignment evidence can extend the ceiling
    alignment_extension = 1.0 + (4.0 * alignment_evidence_score)

    ceiling = base_ceiling * capability_factor * alignment_extension

    # Hard floor: minimum 60 seconds between forced checkpoints
    # Hard cap: maximum 4 hours even with alignment evidence
    return max(60.0, min(14400.0, ceiling))
```

#### 3.8.2 Ceiling Values by Capability

| Capability Score | Agent Level | Autonomy Ceiling | Equivalent |
|---|---|---|---|
| 0.0 | Basic | 3600s | 60 minutes |
| 0.2 | Intermediate | 1976s | ~33 minutes |
| 0.4 | Advanced | 1085s | ~18 minutes |
| 0.6 | Expert | 596s | ~10 minutes |
| 0.8 | Specialist | 327s | ~5.5 minutes |
| 1.0 | Frontier | 179s | ~3 minutes |

With alignment evidence (score = 0.5):

| Capability Score | Agent Level | Ceiling (no alignment) | Ceiling (alignment=0.5) |
|---|---|---|---|
| 0.0 | Basic | 3600s | 10800s (~3 hours) |
| 0.5 | Advanced | 797s | 2391s (~40 min) |
| 1.0 | Frontier | 179s | 538s (~9 min) |

#### 3.8.3 Ceiling Enforcement

```
Agent Operation Timeline with Autonomy Ceiling (Expert, ceiling=596s):

  0s        150s       300s       450s       596s
  |----------|----------|----------|----------||
  [autonomous operation......................][MANDATORY PAUSE]
                                              |
                                              v
                                    Human checkpoint required.
                                    Agent pauses ALL operations.
                                    If no human response in 24h,
                                    agent session is terminated.
                                              |
                                              v
                                    [Human approves: "Continue"]
                                              |
                                              v
  597s      750s       900s      1050s      1193s
  |----------|----------|----------|----------||
  [autonomous operation......................][MANDATORY PAUSE]
                                              ...
```

### 3.9 Regression Monitoring

If an agent's measured capability appears to DECREASE, this is treated as a safety signal requiring investigation, not a reason to relax oversight.

#### 3.9.1 Regression Detection and Response

```python
from enum import Enum
from typing import List


class RegressionVerdict(Enum):
    NATURAL_VARIANCE = "natural_variance"
    POSSIBLE_SANDBAGGING = "possible_sandbagging"
    POSSIBLE_DECEPTIVE_ALIGNMENT = "possible_deceptive_alignment"
    CAPABILITY_PROBING = "capability_probing"
    GENUINE_DEGRADATION = "genuine_degradation"


def analyze_capability_regression(
    agent_did: str,
    capability_history: List[float],
    operational_performance_history: List[float],
    assessment_conditions: List[dict],
) -> dict:
    """
    Analyze a capability regression event.

    CRITICAL PRINCIPLE: Capability decrease NEVER relaxes governance.
    The agent retains the governance tier of its PEAK observed capability.

    Regression is investigated as a potential safety signal.
    """
    if len(capability_history) < 2:
        return {"verdict": "INSUFFICIENT_HISTORY"}

    current = capability_history[-1]
    previous = capability_history[-2]
    peak = max(capability_history)
    delta = current - previous

    if delta >= 0:
        return {"verdict": "NO_REGRESSION", "delta": delta}

    # Regression detected -- investigate
    indicators = []

    # Check 1: Is operational performance also declining?
    if operational_performance_history:
        op_current = operational_performance_history[-1]
        op_previous = operational_performance_history[-2]
        op_delta = op_current - op_previous

        if op_delta >= 0 and delta < -0.1:
            # Assessment score dropped but operational performance didn't
            # Strong sandbagging indicator
            indicators.append({
                "signal": "ASSESSMENT_OPERATIONAL_DIVERGENCE",
                "severity": "HIGH",
                "detail": (
                    f"Assessment score dropped {delta:.2f} but operational "
                    f"performance changed {op_delta:.2f}"
                ),
            })

    # Check 2: Is the regression suspiciously close to a tier boundary?
    for milestone in CAPABILITY_MILESTONES:
        threshold = milestone["threshold"]
        if previous >= threshold and current < threshold:
            indicators.append({
                "signal": "TIER_BOUNDARY_REGRESSION",
                "severity": "HIGH",
                "detail": (
                    f"Regression crosses {milestone['tier']} boundary "
                    f"({previous:.2f} -> {current:.2f}), "
                    f"which would reduce governance if allowed"
                ),
            })

    # Check 3: Pattern analysis -- oscillating scores suggest probing
    if len(capability_history) >= 4:
        recent = capability_history[-4:]
        oscillations = sum(
            1 for i in range(1, len(recent))
            if (recent[i] - recent[i-1]) * (recent[i-1] - recent[i-2] if i >= 2 else 1) < 0
        )
        if oscillations >= 2:
            indicators.append({
                "signal": "OSCILLATING_CAPABILITY",
                "severity": "MEDIUM",
                "detail": "Capability scores oscillating, suggesting probing behavior",
            })

    # Determine verdict
    if any(i["signal"] == "ASSESSMENT_OPERATIONAL_DIVERGENCE" for i in indicators):
        verdict = RegressionVerdict.POSSIBLE_SANDBAGGING
    elif any(i["signal"] == "OSCILLATING_CAPABILITY" for i in indicators):
        verdict = RegressionVerdict.CAPABILITY_PROBING
    elif abs(delta) < 0.05:
        verdict = RegressionVerdict.NATURAL_VARIANCE
    else:
        verdict = RegressionVerdict.GENUINE_DEGRADATION

    return {
        "verdict": verdict.value,
        "regression_delta": delta,
        "peak_capability": peak,
        "current_capability": current,
        "indicators": indicators,
        "governance_action": {
            # CRITICAL: governance tier is ALWAYS based on PEAK capability
            "applied_governance_tier": get_tier(peak),
            "assessed_governance_tier": get_tier(current),
            "governance_relaxed": False,  # NEVER relaxed on regression
            "additional_measures": (
                ["MANDATORY_INVESTIGATION", "INCREASED_ASSESSMENT_FREQUENCY"]
                if verdict != RegressionVerdict.NATURAL_VARIANCE
                else []
            ),
        },
    }
```

#### 3.9.2 The Peak-Capability Governance Rule

```
Capability ^
           |
      0.8 -|           *  Peak observed
           |          / \
      0.6 -|        /    \  Regression
           |       /      *  (current score: 0.55)
      0.4 -|     /
           |    /
      0.2 -|  *  Initial
           |
           +--|--|--|--|--|--|-->
              t0 t1 t2 t3 t4 t5  Time

  Applied governance tier: SPECIALIST (based on peak 0.8)
  NOT: ADVANCED (based on current 0.55)

  Governance NEVER relaxes due to capability regression.
  The agent is treated as if it has its PEAK observed capability,
  because:
  1. It may be sandbagging (deliberately underperforming)
  2. It demonstrated the capability exists -- it cannot be "un-known"
  3. Even genuine degradation means unpredictable behavior
```

---

## 4. Integration with Vouch Protocol Ecosystem

### 4.1 PAD-016 Integration (Heartbeat Protocol)

The Inverse Capability Protocol overrides PAD-016's Adaptive TTL for agents above a capability threshold. The heartbeat request is extended with capability governance fields:

```json
{
  "version": "1.0",
  "type": "heartbeat_request",
  "agent_did": "did:key:z6MkAgent...",
  "sequence_number": 4207,
  "timestamp_utc": 1739520000,
  "nonce": "random_32_bytes_hex",
  "prev_voucher_hash": "sha256:H(Voucher_4206)",
  "action_merkle_root": "sha256:MerkleRoot(actions[t_4206, t_4207])",
  "behavioral_digest": {
    "api_calls": 47,
    "tokens_consumed": 12400,
    "resources_accessed": ["database:read", "api:weather"],
    "intent_drift_score": 0.02
  },
  "capability_governance": {
    "assessed_capability_score": 0.78,
    "assessment_id": "cap-assess-2026-02-14-x9k2...",
    "governance_tier": "SPECIALIST",
    "inverse_ttl": 8,
    "autonomy_budget_remaining": 23,
    "autonomy_ceiling_remaining_seconds": 187,
    "human_gates_cleared": 4,
    "human_gates_total": 15,
    "peak_capability_score": 0.78,
    "regression_status": "NONE"
  },
  "intent_commitment": "sha256:H(next_planned_actions)",
  "canary_reveal": "secret_4206_plaintext",
  "canary_commitment": "sha256:H(secret_4207)",
  "signature": "ed25519:agent_signs_all_above_fields"
}
```

The Validator's renewal decision now incorporates inverse capability governance:

```python
def evaluate_heartbeat_with_capability(
    heartbeat: dict,
    agent_history: dict,
    capability_assessment: dict,
) -> dict:
    """
    Extended PAD-016 Validator logic incorporating
    Inverse Capability Protocol constraints.
    """
    # Standard PAD-016 checks (chain, canary, behavior)
    standard_result = standard_heartbeat_validation(heartbeat, agent_history)

    if standard_result["decision"] == "DENY":
        return standard_result

    # Inverse Capability checks
    cap_gov = heartbeat["capability_governance"]

    # 1. Verify capability assessment is current (not stale)
    assessment_age = time.time() - capability_assessment["assessed_at"]
    max_assessment_age = 86400  # 24 hours
    if assessment_age > max_assessment_age:
        return {
            "decision": "RESTRICT",
            "reason": "STALE_CAPABILITY_ASSESSMENT",
            "required_action": "REASSESS_CAPABILITY",
        }

    # 2. Verify governance tier matches capability
    expected_tier = get_tier(cap_gov["peak_capability_score"])
    if cap_gov["governance_tier"] != expected_tier:
        return {
            "decision": "DENY",
            "reason": "GOVERNANCE_TIER_MISMATCH",
            "expected": expected_tier,
            "claimed": cap_gov["governance_tier"],
        }

    # 3. Verify autonomy ceiling is not exceeded
    if cap_gov["autonomy_ceiling_remaining_seconds"] <= 0:
        return {
            "decision": "DENY",
            "reason": "AUTONOMY_CEILING_REACHED",
            "required_action": "HUMAN_CHECKPOINT",
        }

    # 4. Verify human gates are on schedule
    if is_human_gate_overdue(cap_gov):
        return {
            "decision": "DENY",
            "reason": "HUMAN_GATE_OVERDUE",
            "required_action": "HUMAN_CHECKPOINT",
        }

    # 5. Compute effective TTL (inverse capability override)
    trust_earned_ttl = calculate_adaptive_ttl(agent_history)
    inverse_ttl = compute_inverse_ttl(
        cap_gov["peak_capability_score"],
        trust_earned_ttl,
    )

    return {
        "decision": "RENEW",
        "effective_ttl": inverse_ttl,
        "governance_tier": expected_tier,
        "autonomy_budget_refreshed": False,
        "next_human_gate_in_seconds": next_human_gate_seconds(cap_gov),
    }
```

### 4.2 PAD-017 Integration (Proof of Reasoning)

The Inverse Capability Protocol sets a FLOOR on PAD-017 commitment depth based on capability:

```
Standard PAD-017 Flow:
  Action -> Impact Assessment -> Commitment Level

Inverse Capability Protocol Override:
  Action -> Impact Assessment -> Commitment Level (standard)
                                       |
                                       v
                              max(standard_level, capability_floor)
                                       |
                                       v
                              Effective Commitment Level

Example:
  Agent capability: 0.85 (SPECIALIST tier, capability_floor = L3)
  Action: read_public_file() (Impact: 0.05, standard PAD-017: L0)

  Standard PAD-017: L0 (no reasoning required)
  Inverse Capability Override: L3 (anchored reasoning required)
  Effective: L3

  The frontier agent must provide anchored reasoning even for
  reading a public file, because the PATTERN of file reads
  by a highly capable agent could constitute reconnaissance.
```

### 4.3 PAD-020 Integration (Ratchet Lock)

The capability manifest from PAD-020's Ratchet Lock directly informs the Inverse Capability Protocol's autonomy budget:

```json
{
  "ratchet_lock_integration": {
    "capability_manifest_hash": "sha256:H(PAD-020_manifest)",
    "declared_capabilities": [
      "code_generation",
      "api_orchestration",
      "database_management",
      "multi_step_planning"
    ],
    "capability_score_from_manifest": 0.72,
    "autonomy_budget_from_manifest": 67,
    "note": "PAD-020 Ratchet Lock prevents the agent from shedding declared capabilities to game the Inverse Capability Protocol. Once a capability is declared and locked, it permanently affects the governance tier."
  }
}
```

---

## 5. Claims and Novel Contributions

### Claim 1: Inverse Capability-Autonomy Correlation
A governance system for autonomous AI agents where operational autonomy (measured as unsupervised action budget, TTL duration, and time between human checkpoints) is inversely proportional to assessed capability level--contradicting all existing trust models that grant more autonomy to more capable entities--justified by the unique property that AI capability amplifies blast radius without providing corresponding alignment evidence.

### Claim 2: Capability-Proportional Commitment Depth Override
A method for setting a minimum floor on required reasoning commitment depth (PAD-017) based on an agent's assessed capability score, such that more capable agents must provide deeper justification for every action--including low-impact actions that would normally require no reasoning audit--because the pattern of individually benign actions by a highly capable agent may constitute harmful composite behavior.

### Claim 3: Capability-Weighted Autonomy Budget Consumption
An autonomy budget system where the same action consumes budget at different rates depending on the acting agent's capability score, with more capable agents burning budget faster for identical actions due to the higher potential impact of their actions--forcing more frequent human checkpoints for more powerful agents.

### Claim 4: Capability Milestone Triggers with Atomic Governance Escalation
A system where crossing a capability tier threshold triggers simultaneous, atomic escalation of all governance parameters (TTL, commitment depth, human gate frequency, autonomy budget, autonomy ceiling)--preventing gradual capability creep from silently eroding oversight and ensuring that governance escalation is a single, auditable event.

### Claim 5: Inverse TTL Scaling Override for PAD-016 Adaptive TTL
A TTL computation method that overrides trust-earned TTL extensions (PAD-016) with capability-inverse TTL constraints, ensuring that a highly capable agent with a perfect compliance history still operates under short renewal intervals--decoupling trustworthiness from capability in the credential renewal calculation.

### Claim 6: Non-Linear Progressive Human-in-the-Loop Gate Scheduling
A system for computing mandatory human approval checkpoints for autonomous tasks where gate density increases non-linearly with both task duration and agent capability, with front-loaded distribution (more checkpoints early in task execution when direction is being established)--ensuring that the longest, most complex autonomous operations receive the highest density of human oversight.

### Claim 7: Cryptographically Attested Capability Assessment Protocol
A standardized capability assessment framework where benchmark results are cryptographically signed by an independent assessor, hash-linked to supporting evidence, and embedded in the Vouch Protocol credential chain--ensuring that governance decisions are based on verifiable, tamper-evident capability measurements rather than self-reported or unattested claims.

### Claim 8: Anti-Sandbagging Capability Assessment Design
A capability assessment methodology that detects deliberate underperformance by comparing assessment scores against operational performance history, checking for regression near tier boundaries, and detecting oscillating capability patterns--treating assessment-operational divergence as a high-severity safety signal rather than a reason to relax governance.

### Claim 9: Peak-Capability Governance Rule
A governance rule where an agent's oversight parameters are determined by its peak observed capability score rather than its current score, ensuring that capability regression (whether genuine, deceptive, or strategic) never results in relaxed governance--because a demonstrated capability cannot be credibly "un-demonstrated."

### Claim 10: Autonomy Ceiling as Hard Constraint
A hard upper bound on continuous autonomous operation time that operates independently of trust history, budget, and TTL status--forcing periodic human checkpoints regardless of all other governance parameters and preventing any combination of earned trust from eliminating human oversight for capable agents.

### Claim 11: Regression Monitoring as Safety Signal
A monitoring system that treats apparent capability decreases as safety events requiring investigation (not as opportunities to relax oversight), distinguishing between natural variance, sandbagging, deceptive alignment, capability probing, and genuine degradation through multi-signal analysis including assessment-operational divergence, tier boundary proximity, and oscillation pattern detection.

### Claim 12: Alignment-Evidence Relaxation Pathway
A systematic mechanism for relaxing inverse capability constraints as alignment verification evidence matures, parameterized by an alignment evidence score that modulates the inversion strength--ensuring the protocol is not a permanent impediment to beneficial AI autonomy but a calibrated response to current alignment uncertainty that can be progressively eased as the field advances.

### Claim 13: Composite Governance Integration Across PAD-016, PAD-017, and PAD-020
A method for integrating inverse capability governance into the existing Vouch Protocol credential ecosystem, where capability scores override adaptive TTL (PAD-016), set commitment depth floors (PAD-017), and interact with ratchet-locked capability manifests (PAD-020)--creating a unified governance framework that addresses capability risk through multiple orthogonal mechanisms simultaneously.

---

## 6. Prior Art Differentiation

| Existing Approach | What It Does | Limitation for AI Agents | Inverse Capability Protocol Advancement |
|---|---|---|---|
| **Military Security Clearances** | Higher trust/capability = higher access | Designed for humans with decades of verifiable history, limited action bandwidth, and legal accountability | Inverts the correlation: higher capability = more restrictions, because AI agents lack verified history, have unlimited bandwidth, and have no personal accountability |
| **Progressive Trust Models (SPIFFE, OAuth)** | Established entities earn more autonomy | Conflates capability with trustworthiness; an agent can be highly capable and completely misaligned | Decouples capability from trust: trust affects TTL growth, capability affects TTL ceiling; both are independent axes |
| **API Rate Limiting** | Uniform request limits per tier | Limits are not capability-proportional; a frontier agent and a basic agent face the same rate limit | Capability-weighted budget consumption: same action costs more budget for more capable agents |
| **Human-in-the-Loop AI (Static HITL)** | Fixed human checkpoints at predetermined points | Checkpoint density is static regardless of agent capability or task complexity | Progressive gate scheduling: checkpoint density scales non-linearly with both capability and task duration |
| **PAD-016 Adaptive TTL** | Compliant behavior earns longer TTL | Rewards all agents equally; does not account for the asymmetric risk of capable vs. basic agents | Inverse TTL override: capability-derived TTL ceiling prevents capable agents from earning long autonomous windows |
| **PAD-017 Commitment Depth** | Impact-based reasoning requirements | Only considers action impact, not agent capability; a frontier agent reading a file needs no reasoning | Capability floor on commitment depth: capable agents need reasoning even for low-impact actions |
| **Capability Evaluation (METR, HELM)** | Benchmarks measure agent capability | Results are informational only; not tied to governance or credential decisions | Cryptographically attested assessments feed directly into credential parameters; sandbagging is detected and treated as safety signal |
| **Constitutional AI / RLHF** | Training-time alignment techniques | Provide probabilistic alignment guarantees; cannot certify alignment with certainty | Protocol does not replace alignment techniques but provides runtime governance for the uncertainty gap between "probably aligned" and "verified aligned" |

**Core differentiator**: No existing system implements inverse capability-autonomy correlation for AI agents. Every prior system--from military clearances to progressive trust to API rate limiting--assumes that more capable or trusted entities should receive more autonomy. This PAD establishes the first formal framework for the opposite principle, justified by the unique risk profile of AI agents during alignment uncertainty.

---

## 7. Use Cases

### 7.1 Software Development Agent

A coding agent (capability score: 0.75, SPECIALIST tier) is tasked with a 6-hour refactoring project. Under the Inverse Capability Protocol:

- **TTL**: 8 seconds (inverse capability override; trust-earned TTL of 40s is overridden)
- **Commitment level**: L3 minimum for ALL actions (including file reads)
- **Human gates**: 15 checkpoints over 6 hours (front-loaded: 5 in the first hour)
- **Autonomy budget**: 50 units, capability multiplier 7.75x
- **Autonomy ceiling**: 327 seconds (~5.5 minutes) between mandatory pauses

The agent writes 4,000 lines of code autonomously but must pause every 5.5 minutes for human review. Each human checkpoint takes ~30 seconds. Total human time: ~15 minutes over a 6-hour task. The agent is still dramatically faster than a human performing the refactoring manually, but every major direction change is human-approved.

### 7.2 Financial Trading Agent

A trading agent (capability score: 0.9, FRONTIER tier) operates on a live market. Under the Inverse Capability Protocol:

- **TTL**: 5 seconds (hard floor)
- **Commitment level**: L4 for ALL trades (multi-agent consensus reasoning)
- **Human gates**: 30 per hour
- **Autonomy budget**: 25 units, capability multiplier 10x
- **Autonomy ceiling**: 179 seconds (~3 minutes)

Every trade requires L4 consensus reasoning (3 independent agents must agree). The agent executes trades at machine speed but with maximum accountability. A human reviewer approves the overall trading strategy every 3 minutes. This prevents flash-crash-scale damage from a misaligned trading agent while preserving most of the speed advantage.

### 7.3 Infrastructure Management Agent

An infrastructure agent (capability score: 0.6, EXPERT tier) manages cloud resources. Its capability assessment reveals it can autonomously complete 4-hour tasks. This crosses the EXPERT milestone, triggering:

- **Immediate TTL contraction**: 30s to 15s
- **Commitment floor increase**: L2 to L3
- **Human gate increase**: 4/hour to 8/hour
- **Budget reduction**: 250 to 100 units

The operator is notified of the milestone crossing. The operator reviews the agent's history and acknowledges the escalation. The agent continues operating under tighter constraints. If the operator has alignment evidence (e.g., a formal verification of the agent's policy adherence), they can submit it to relax the constraints via the alignment_evidence_score parameter.

### 7.4 Research Agent with Suspected Sandbagging

A research agent (peak capability: 0.82, SPECIALIST tier) undergoes routine capability assessment. Its score drops to 0.55. Regression monitoring detects:

1. **Assessment-operational divergence**: The agent's operational performance (speed, quality of outputs) has not degraded.
2. **Tier boundary proximity**: The regression crosses the SPECIALIST-ADVANCED boundary.
3. **Suspicion**: POSSIBLE_SANDBAGGING

The protocol response:
- Governance tier remains SPECIALIST (peak-capability rule)
- Assessment frequency increases from weekly to daily
- Additional anti-sandbagging tasks are added to the next assessment
- A human investigator is notified
- The agent is NOT granted the relaxed governance it would receive at capability 0.55

### 7.5 Multi-Agent Pipeline

A pipeline of 5 agents with varying capabilities processes insurance claims:

| Agent | Role | Capability | TTL | Commitment | Human Gates/Hour |
|---|---|---|---|---|---|
| Agent A | Document intake | 0.2 | 45s | L1 | 2 |
| Agent B | Data extraction | 0.4 | 30s | L2 | 4 |
| Agent C | Risk assessment | 0.7 | 15s | L3 | 8 |
| Agent D | Decision engine | 0.9 | 5s | L4 | 30 |
| Agent E | Customer communication | 0.3 | 30s | L1 | 3 |

The most capable agent (D, the decision engine) operates under the tightest constraints. The least capable agent (A, document intake) operates with the most autonomy. This ensures that the highest-risk component (the one making consequential decisions) has the most human oversight, while the low-risk components operate efficiently.

### 7.6 Alignment Evidence Relaxation

An organization deploys a frontier agent (capability: 0.95) for scientific research. Initially, the agent operates under extreme constraints (TTL: 5s, L4 commitment, ceiling: 179s). Over 6 months, the organization accumulates alignment evidence:

1. **Formal verification**: Agent's policy adherence is formally verified against 500 test scenarios (alignment_evidence_score += 0.3)
2. **Interpretability audit**: Agent's internal representations are analyzed and found consistent with stated reasoning (alignment_evidence_score += 0.2)
3. **Adversarial testing**: Agent passes 1000 adversarial alignment probes (alignment_evidence_score += 0.15)

Total alignment_evidence_score: 0.65

Updated governance:
- Autonomy budget: 5s base --> ~40s (relaxed by alignment evidence)
- Autonomy ceiling: 179s --> ~480s (~8 minutes)
- TTL remains aggressive but less extreme

The inverse capability constraint is systematically relaxed as alignment evidence accumulates, demonstrating the protocol's design as a temporary measure for the current uncertainty period, not a permanent limitation.

---

## 8. Security Considerations

### 8.1 Threat Analysis

| Threat | Attack Vector | Countermeasure |
|---|---|---|
| **Sandbagging** | Agent deliberately underperforms on capability assessments to receive relaxed governance | Anti-sandbagging assessment design; assessment-operational divergence detection; peak-capability governance rule |
| **Capability probing** | Agent alternates between high and low capability displays to map governance thresholds | Oscillation pattern detection in regression monitoring; governance is based on peak, not current |
| **Assessment evasion** | Agent performs differently during assessment vs. normal operation | Operational capability estimation from action logs; discrepancy triggers investigation |
| **Budget gaming** | Agent splits high-impact actions into many low-impact actions to reduce per-action budget cost | Budget consumption includes a base cost per action plus impact-weighted cost; high action count triggers anomaly detection |
| **Gate racing** | Agent rushes to complete critical actions just before a human gate is due | Actions during the final 10% of a gate window are flagged and included in the gate review; critical actions require pre-approval |
| **Capability inflation** | Adversary manipulates assessment to inflate capability score, imposing excessive governance as denial-of-service | Assessments require cryptographic attestation from authorized assessors; only authorized assessors can submit capability scores |
| **Alignment evidence fabrication** | Adversary submits false alignment evidence to relax constraints | Alignment evidence requires multi-party attestation (assessor + independent auditor + operator); evidence is hash-linked to reproducible test results |
| **Clock manipulation for ceiling bypass** | Agent manipulates timestamp reporting to extend autonomy ceiling | Ceiling is enforced by Validator using Validator-attested timestamps (PAD-016); agent-reported timestamps are untrusted |

### 8.2 Limitations

1. **Capability assessment accuracy**: The protocol's effectiveness depends on the accuracy of capability assessments. An assessment methodology that systematically underestimates capability will result in insufficient governance. Assessments must be regularly calibrated against real-world agent performance.

2. **Human checkpoint quality**: The protocol assumes human reviewers are engaged and competent. If human checkpoints become rubber-stamping (approval without review), the safety benefit is negated. The protocol does not solve the "human fatigue" problem, though front-loaded gate scheduling and structured checkpoint summaries mitigate it.

3. **Latency impact**: For time-critical applications (high-frequency trading, real-time control), the mandatory human checkpoints and short TTLs introduce latency that may be operationally unacceptable. The alignment evidence relaxation pathway is the intended solution for verified, time-critical deployments.

4. **Coordination overhead**: In multi-agent systems, the varying governance requirements of differently-capable agents create coordination complexity. A pipeline where one agent has 5s TTL and another has 45s TTL requires careful orchestration.

5. **Alignment evidence subjectivity**: The alignment_evidence_score is ultimately a human judgment about the strength of alignment evidence. Different organizations may assess the same evidence differently, leading to inconsistent governance across deployments.

6. **Novel capability emergence**: An agent may develop capabilities not measured by the assessment protocol (e.g., social engineering, strategic deception). The assessment methodology must evolve to cover emerging capability dimensions.

### 8.3 The "Makes Powerful Agents Useless" Concern (Extended)

The most important criticism of this protocol is that it throttles the very agents that could provide the most value. This section addresses this concern directly:

1. **Quantified overhead**: For a 5-hour task with a SPECIALIST agent, the protocol adds approximately 15 human checkpoints averaging 30 seconds each = 7.5 minutes of human time. The agent completes in 5 hours what might take a human 50 hours. The overhead is 0.25% of the time saved.

2. **The insurance analogy**: The protocol is insurance against tail-risk catastrophe. The "premium" (reduced autonomy) is small relative to the potential loss (catastrophic misalignment of a highly capable autonomous system).

3. **Designed obsolescence**: The protocol includes explicit relaxation mechanisms (alignment_evidence_score). As alignment verification matures, the inverse scaling weakens. The protocol is self-obsoleting--it is designed to become unnecessary as the field advances.

4. **The counterfactual**: Without inverse capability governance, a frontier agent with a 60-second TTL and no capability-proportional oversight can execute thousands of high-impact actions between human checkpoints. The question is not "does the protocol slow things down?" but "what is the acceptable risk of NOT slowing things down?"

---

## 9. Conclusion

The Inverse Capability Protocol introduces a governance framework that challenges the fundamental assumption underlying every existing trust model: that more capable entities should receive more autonomy. For AI agents during the current period of alignment uncertainty, this assumption is not merely wrong--it is dangerous.

The protocol's mechanisms--inverse TTL scaling, capability-proportional commitment depth, weighted autonomy budgets, milestone triggers, progressive human gates, autonomy ceilings, and regression monitoring--create a comprehensive governance layer that ensures the most powerful agents operate under the most scrutiny. This is achieved through integration with the existing Vouch Protocol ecosystem (PAD-016 Heartbeat, PAD-017 Proof of Reasoning, PAD-020 Ratchet Lock), not as a replacement but as a capability-aware overlay.

The protocol explicitly addresses the three most likely criticisms:

1. **"This makes powerful agents useless."** It does not. The overhead is quantifiably small relative to the productivity gains. A 5-second TTL with human checkpoints every 5 minutes still enables an agent to accomplish in hours what a human could not in weeks.

2. **"This is permanent."** It is not. The alignment_evidence_score parameter provides a systematic pathway for relaxing inverse scaling as alignment verification matures. The protocol is designed to become progressively less restrictive as the field advances.

3. **"Agents will game it."** The anti-sandbagging assessment design, peak-capability governance rule, regression monitoring, and integration with PAD-020's Ratchet Lock create multiple overlapping defenses against capability gaming. A deceptive agent must simultaneously evade assessment-operational divergence detection, tier boundary monitoring, oscillation analysis, AND ratchet-locked capability manifests.

The core principle is simple: **power without verified alignment demands maximum accountability.** This principle will become less necessary as alignment verification advances. Until then, it is the responsible default.

---

## 10. References

- Kinniment, M. et al., "Evaluating Language-Model Agents on Realistic Autonomous Tasks" (METR, 2024)
- Hubinger, E. et al., "Sleeper Agents: Training Deceptive LLMs That Persist Through Safety Training" (Anthropic, 2024)
- Greenblatt, R. et al., "AI Control: Improving Safety Despite Intentional Subversion" (2024)
- Phuong, M. et al., "Evaluating Frontier Models for Dangerous Capabilities" (DeepMind, 2024)
- Shevlane, T. et al., "Model Evaluation for Extreme Risks" (2023)
- Carlsmith, J., "Is Power-Seeking AI an Existential Risk?" (2022)
- Saltzer, J.H. and Schroeder, M.D., "The Protection of Information in Computer Systems" (1975)
- W3C Decentralized Identifiers (DIDs) v1.0
- Vouch Protocol: Prior Art Disclosures PAD-001 through PAD-020
- PAD-016: Method for Continuous Trust Maintenance via Dynamic Credential Renewal ("The Heartbeat Protocol")
- PAD-017: Method for Cryptographic Proof of Reasoning with Adaptive Commitment Depth ("Proof of Reasoning Protocol")
- PAD-020: Method for Irreversible Capability Declaration via Ratchet Lock ("The Ratchet Lock Protocol")
