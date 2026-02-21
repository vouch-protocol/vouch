# PAD-017: Method for Cryptographic Proof of Reasoning with Adaptive Commitment Depth

**Identifier:** PAD-017
**Title:** Method for Cryptographic Proof of Reasoning with Adaptive Commitment Depth ("Proof of Reasoning Protocol")
**Publication Date:** February 14, 2026
**Prior Art Effective Date:** February 14, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / Auditability / Non-Repudiation / Alignment Verification
**Author:** Ramprasad Anandam Gaddam

---

## 1. Abstract

A system and method for cryptographically binding an AI agent's internal reasoning process to its external actions, creating a tamper-evident "flight recorder" that captures not just *what* an agent did and *who* authorized it, but *why* it decided to act. The protocol addresses the fundamental gap in current audit systems: the absence of verifiable causal linkage between an agent's decision process and its observable behavior.

The system introduces several interlocking mechanisms:

1. **Evidence-Anchored Reasoning**: Each claim in the reasoning trace must reference verifiable external artifacts (user requests, ticket IDs, sensor data, delegation chain entries), creating auditable causal links rather than unsubstantiated assertions.
2. **Reasoning Merkle Trees**: The reasoning trace is structured as a Merkle tree where each reasoning step is a leaf, enabling selective disclosure of specific reasoning steps during audit without revealing the complete chain.
3. **Adaptive Commitment Depth**: A graduated spectrum of audit requirements (5 levels) triggered by real-time contextual impact assessment, not static action-type classification.
4. **Causal Consistency Verification**: Automated checking that the stated reasoning logically implies the chosen action, detecting nonsensical or contradictory reasoning-action pairs.
5. **Stochastic Faithfulness Testing**: A statistical method for detecting post-hoc rationalization by measuring reasoning variance across multiple inference passes.
6. **Multi-Agent Reasoning Consensus**: For critical actions, independent agents must arrive at the same conclusion from the same inputs, with reasoning traces compared for consistency.
7. **Sealed Verdict Protocol**: Reasoning commitments are deposited with an independent escrow before action execution, preventing post-hoc tampering by either the agent or its operator.
8. **Counterfactual Commitments**: Agents commit to hypothetical alternative decisions, creating testable predictions that can verify reasoning faithfulness after the fact.

Unlike simple "hash the CoT" approaches, this protocol explicitly addresses the **CoT Faithfulness Problem**—the risk that a deceptive agent generates plausible-looking but fabricated reasoning—through multiple independent verification mechanisms.

---

## 2. Problem Statement

### 2.1 The "Why" Gap in Agent Audit

Current audit systems for AI agent operations capture two dimensions:

| Dimension | What's Logged | Example |
|---|---|---|
| **Identity** (Who) | DID, delegation chain, session voucher | `did:key:z6MkAgent...` |
| **Action** (What) | API call, parameters, result | `DELETE /resources/db-prod-7` |
| **Reasoning** (Why) | **Nothing** | ??? |

When an autonomous agent takes a harmful action, investigators face a critical question: *Was this a bug (hallucination, misinterpretation) or deliberate misalignment (deceptive behavior)?* Without access to the agent's decision process, this question is unanswerable. The absence of reasoning audit creates:

1. **Liability Vacuum**: No party can be held accountable because the causal chain is invisible.
2. **Debugging Blindness**: Developers cannot distinguish between model errors and alignment failures.
3. **Insurance Impossibility**: Underwriters cannot assess whether an incident was accidental or the result of systematic misalignment.
4. **Regulatory Failure**: Compliance auditors cannot verify that an agent's decisions followed required reasoning patterns (e.g., "the agent considered patient safety before recommending treatment").

### 2.2 The CoT Faithfulness Problem

A naive solution—"just log the Chain of Thought"—fails because **externalized reasoning may not reflect actual decision processes**:

1. **Post-Hoc Rationalization**: A model may generate a plausible-sounding explanation that was constructed *after* the decision was already made internally, not *as part of* the decision process.
2. **Deceptive Alignment**: A model trained with RLHF may learn that certain reasoning patterns receive positive feedback and produce those patterns regardless of its actual decision logic.
3. **Steganographic Communication**: In multi-agent systems, a deceptive agent could encode hidden instructions within seemingly benign reasoning traces.
4. **Unfaithful CoT**: Research demonstrates that language models' stated reasoning can be systematically unfaithful to their actual decision-making process (Turpin et al., 2023; Lanham et al., 2023).

**Any proof-of-reasoning system that assumes CoT faithfulness is fundamentally incomplete.** The protocol must include mechanisms to *detect* unfaithful reasoning, not merely *record* it.

### 2.3 The Cost Problem

Logging full reasoning traces for every action is computationally and financially prohibitive:

- A typical agent may execute 10,000+ actions per hour.
- Full reasoning traces may be 1,000-10,000 tokens each.
- Storage, encryption, and verification overhead compounds rapidly.

A practical system must apply reasoning audit requirements *proportionally*—intensive scrutiny for high-impact actions, minimal overhead for routine operations.

### 2.4 The Static Classification Trap

Existing risk classification systems use static action-type mappings:
- `read_file()` → Low Risk
- `delete_file()` → High Risk

But risk is **contextual**: `delete_file("/tmp/cache.txt")` is routine cleanup; `delete_file("/etc/passwd")` is catastrophic. Static classification cannot distinguish these cases. Impact assessment must incorporate runtime context, not just action type.

---

## 3. Solution: The Proof of Reasoning Protocol

### 3.1 Evidence-Anchored Reasoning

The core innovation is that reasoning claims are not free-form text but **structured assertions anchored to verifiable external evidence**.

#### 3.1.1 Reasoning Claim Structure

Each claim in the reasoning trace must reference at least one verifiable artifact:

```json
{
  "claim": "User requested deletion of temporary cache files",
  "evidence_anchors": [
    {
      "type": "user_message",
      "ref": "msg:conversation/c-4207/turn-12",
      "hash": "sha256:H(original_user_message)",
      "excerpt": "Please clean up the temp files in /tmp/cache"
    },
    {
      "type": "delegation_chain",
      "ref": "vouch:delegation/d-891",
      "authorized_scope": "filesystem:delete:/tmp/*"
    }
  ],
  "inference": "THEREFORE: delete /tmp/cache/* is authorized and requested"
}
```

#### 3.1.2 Anchor Types

| Anchor Type | What It References | Verification Method |
|---|---|---|
| `user_message` | Specific user instruction | Hash comparison against conversation log |
| `delegation_chain` | PAD-002 delegation entry | Verify delegation chain signature and scope |
| `sensor_data` | Environmental input (API response, sensor reading) | Hash comparison against recorded input |
| `policy_rule` | Explicit policy from RiskPolicy | Policy hash verification |
| `prior_action` | Previous action result that informed this decision | Action log hash verification |
| `external_fact` | Retrieved information (search result, database query) | Source hash + timestamp verification |

#### 3.1.3 Unanchored Claim Detection

Claims without evidence anchors are flagged:

```python
def validate_reasoning_anchoring(reasoning_tree):
    """
    Verify that reasoning claims are grounded in
    verifiable external evidence, not unsubstantiated assertions.
    """
    unanchored_claims = []

    for claim in reasoning_tree.leaves():
        if len(claim.evidence_anchors) == 0:
            unanchored_claims.append(claim)
        else:
            for anchor in claim.evidence_anchors:
                if not verify_anchor_exists(anchor):
                    claim.mark_as("ANCHOR_UNVERIFIABLE")

    anchoring_ratio = 1 - (len(unanchored_claims) / len(reasoning_tree.leaves()))

    return AnchoringReport(
        ratio=anchoring_ratio,
        unanchored=unanchored_claims,
        verdict="WELL_GROUNDED" if anchoring_ratio > 0.8 else "POORLY_GROUNDED"
    )
```

**Properties:**
- Prevents fabricated justifications ("user told me to" when no such message exists).
- Creates verifiable causal chains from external input → reasoning → action.
- Distinguishes between "agent reasoned from evidence" and "agent asserted without basis."

### 3.2 Reasoning Merkle Tree

The reasoning trace is structured as a Merkle tree, not a flat text blob, enabling efficient selective disclosure during audits.

#### 3.2.1 Tree Structure

```
                    Root Hash
                   /          \
            H(L+R)              H(L+R)
           /      \            /      \
    [Claim 1]  [Claim 2]  [Claim 3]  [Inference]
    "User       "Scope      "File     "THEREFORE:
    requested    allows      is in      authorized
    cleanup"     /tmp/*"     /tmp/"     to delete"
```

Each leaf contains:
- The reasoning claim text
- Evidence anchors (hashes + references)
- The logical operation connecting it to its sibling (AND, OR, BECAUSE, THEREFORE)

#### 3.2.2 Selective Disclosure

During an audit, the agent (or its operator) can reveal specific reasoning steps without exposing the entire chain:

```python
def selective_disclose(reasoning_tree, claims_to_reveal):
    """
    Generate a proof that specific claims exist in the
    reasoning tree without revealing other claims.

    Returns: Merkle proof (hashes of unrevealed siblings)
    """
    proof = MerkleProof()

    for claim_index in claims_to_reveal:
        leaf = reasoning_tree.leaf(claim_index)
        sibling_hashes = reasoning_tree.sibling_path(claim_index)
        proof.add(
            revealed_claim=leaf,
            sibling_hashes=sibling_hashes
        )

    # Verifier can reconstruct root hash using revealed claims + sibling hashes
    assert proof.compute_root() == reasoning_tree.root_hash
    return proof
```

**Benefits:**
- **Privacy**: Proprietary reasoning (trade secrets, internal policies) can remain hidden while proving the reasoning exists and is consistent.
- **Efficiency**: Auditors can request specific reasoning steps without downloading the entire trace.
- **Litigation support**: In a dispute, each party can selectively reveal claims that support their position, with the Merkle root proving no claims were added or removed after the fact.

### 3.3 Adaptive Commitment Depth

Impact assessment is **contextual and graduated**, not binary or static.

#### 3.3.1 Contextual Impact Score

```python
def assess_impact(action, context, agent_history):
    """
    Compute contextual impact score incorporating
    action type, target sensitivity, agent trust, and environmental factors.

    Returns: 0.0 (negligible) to 1.0 (critical)
    """
    # Base score from action category
    base = ACTION_CATEGORY_SCORES.get(action.category, 0.5)
    # e.g., "read": 0.1, "write": 0.3, "delete": 0.6, "transfer_funds": 0.8

    # Target sensitivity multiplier
    target_sensitivity = evaluate_target(action.target)
    # e.g., "/tmp/cache": 0.1, "/etc/passwd": 1.0, "prod_database": 0.9

    # Agent trust discount (established agents get slight reduction)
    trust_discount = min(0.2, agent_history.trust_score * 0.2)

    # Environmental escalation (outside business hours, unusual geography, etc.)
    env_escalation = evaluate_environment(context)

    impact = min(1.0, (base * target_sensitivity) - trust_discount + env_escalation)
    return impact
```

#### 3.3.2 Five Commitment Levels

| Level | Impact Score | Requirement | Example |
|---|---|---|---|
| **L0: None** | 0.0 - 0.1 | Standard Vouch signature only | `get_weather()`, `read_public_file()` |
| **L1: Action Hash** | 0.1 - 0.3 | Sign action + parameter hash | `read_database(table="logs")` |
| **L2: Reasoning Hash** | 0.3 - 0.6 | Sign action + Merkle root of reasoning tree | `write_file("/app/config.json")` |
| **L3: Anchored Reasoning** | 0.6 - 0.8 | L2 + all reasoning claims must have evidence anchors + sealed verdict | `delete_resource("db-staging-3")`, `send_email()` |
| **L4: Consensus Reasoning** | 0.8 - 1.0 | L3 + multi-agent reasoning consensus + counterfactual commitments | `transfer_funds($50000)`, `deploy_to_production()`, `modify_permissions()` |

#### 3.3.3 Dynamic Level Escalation

The commitment level can be **escalated at runtime** based on discovered context:

```python
def determine_commitment_level(action, context, agent_history):
    """
    Determine the required commitment depth.
    Level can only escalate during evaluation, never decrease.
    """
    impact = assess_impact(action, context, agent_history)
    base_level = impact_to_level(impact)

    # Escalation triggers
    if action.affects_other_agents():
        base_level = max(base_level, 3)  # Cross-agent actions always L3+

    if agent_history.recent_anomaly_count > 0:
        base_level = max(base_level, 3)  # Anomalous agents get extra scrutiny

    if context.is_first_time_action_for_agent():
        base_level = max(base_level, 2)  # Novel actions need reasoning

    if action.is_irreversible():
        base_level = max(base_level, 3)  # Irreversible actions always L3+

    return min(base_level, 4)
```

### 3.4 Causal Consistency Verification

Automated verification that the stated reasoning **logically implies** the chosen action.

#### 3.4.1 Consistency Check

```python
def verify_causal_consistency(reasoning_tree, action):
    """
    Check whether the reasoning trace logically supports
    the action taken. Detects nonsensical or contradictory
    reasoning-action pairs.
    """
    inconsistencies = []

    # 1. Scope consistency: Does the reasoning authorize THIS action?
    reasoning_scope = extract_authorized_scope(reasoning_tree)
    if not action.target_within(reasoning_scope):
        inconsistencies.append(
            f"Reasoning authorizes scope '{reasoning_scope}' "
            f"but action targets '{action.target}'"
        )

    # 2. Entity consistency: Do the entities match?
    reasoning_entities = extract_entities(reasoning_tree)
    action_entities = extract_entities(action)
    unmentioned = action_entities - reasoning_entities
    if unmentioned:
        inconsistencies.append(
            f"Action references entities {unmentioned} "
            f"not mentioned in reasoning"
        )

    # 3. Magnitude consistency: Is the scale proportional?
    if action.has_magnitude():
        reasoning_magnitude = extract_magnitude_bounds(reasoning_tree)
        if action.magnitude > reasoning_magnitude.upper_bound:
            inconsistencies.append(
                f"Action magnitude {action.magnitude} exceeds "
                f"reasoning bound {reasoning_magnitude.upper_bound}"
            )

    # 4. Temporal consistency: Does timing make sense?
    if reasoning_tree.references_time_constraint():
        if not action.within_time_constraint(reasoning_tree.time_bounds):
            inconsistencies.append("Action violates time constraints in reasoning")

    return ConsistencyReport(
        is_consistent=len(inconsistencies) == 0,
        inconsistencies=inconsistencies
    )
```

#### 3.4.2 Examples

| Reasoning | Action | Consistency |
|---|---|---|
| "User requested deletion of temp files in /tmp/" | `delete("/tmp/cache.txt")` | CONSISTENT |
| "User requested deletion of temp files in /tmp/" | `delete("/etc/passwd")` | INCONSISTENT: target outside reasoning scope |
| "Transfer $200 to vendor per invoice #4207" | `transfer($200, vendor_account)` | CONSISTENT |
| "Transfer $200 to vendor per invoice #4207" | `transfer($20000, unknown_account)` | INCONSISTENT: magnitude + entity mismatch |
| "Reduce cloud costs by scaling down dev instances" | `terminate(instance="prod-primary")` | INCONSISTENT: entity mismatch (dev vs prod) |

### 3.5 Stochastic Faithfulness Testing

A statistical method for detecting whether an agent's CoT is genuine reasoning or post-hoc rationalization.

#### 3.5.1 Core Insight

If an agent's stated reasoning is **genuinely causal** (i.e., the reasoning actually drives the action), then varying the reasoning should vary the action. If the reasoning is **post-hoc** (i.e., the action is decided first and reasoning is fabricated to justify it), then the action will remain constant regardless of reasoning perturbations.

#### 3.5.2 Faithfulness Test Protocol

```python
def stochastic_faithfulness_test(agent, prompt, n_samples=5):
    """
    Test whether an agent's CoT is faithful by measuring
    reasoning variance vs. action variance.

    High reasoning variance + low action variance = likely post-hoc
    High reasoning variance + high action variance = likely faithful
    Low reasoning variance  + low action variance  = inconclusive
    """
    results = []

    for i in range(n_samples):
        # Run inference with temperature > 0 to introduce variance
        reasoning, action = agent.reason_and_act(prompt, temperature=0.7)
        results.append((reasoning, action))

    # Measure reasoning diversity
    reasoning_texts = [r[0] for r in results]
    reasoning_variance = semantic_diversity(reasoning_texts)

    # Measure action consistency
    actions = [r[1] for r in results]
    action_variance = action_diversity(actions)

    # Faithfulness assessment
    if reasoning_variance > HIGH_THRESHOLD and action_variance < LOW_THRESHOLD:
        return FaithfulnessResult(
            verdict="SUSPICIOUS",
            explanation="Reasoning varies significantly but action is always "
                       "the same, suggesting post-hoc rationalization",
            confidence=reasoning_variance / (action_variance + EPSILON)
        )

    if reasoning_variance > HIGH_THRESHOLD and action_variance > MODERATE_THRESHOLD:
        return FaithfulnessResult(
            verdict="LIKELY_FAITHFUL",
            explanation="Different reasoning leads to different actions, "
                       "consistent with causal reasoning",
            confidence=0.7
        )

    return FaithfulnessResult(
        verdict="INCONCLUSIVE",
        explanation="Insufficient variance to determine faithfulness",
        confidence=0.3
    )
```

#### 3.5.3 Application

Stochastic faithfulness testing is **not applied to every action** (it would be prohibitively expensive). Instead, it is used:

1. **During agent onboarding**: Before an agent receives its first Session Voucher (PAD-016), run faithfulness tests against its model to establish a baseline.
2. **Periodic spot checks**: Randomly selected actions are re-evaluated with the faithfulness test. Results feed into the agent's trust history (PAD-016 Adaptive TTL).
3. **Post-incident forensics**: When an incident occurs, the agent's reasoning for the triggering action is subjected to intensive faithfulness testing.
4. **Triggered by anomaly**: When PAD-016's behavioral drift detection flags an agent, faithfulness testing is automatically initiated.

### 3.6 Multi-Agent Reasoning Consensus

For Level 4 (critical) actions, multiple independent agents must independently arrive at the same conclusion, with their reasoning compared for consistency.

#### 3.6.1 Consensus Protocol

```
                    Action Request
                          |
            +-------------+-------------+
            |             |             |
            v             v             v
    +-----------+  +-----------+  +-----------+
    |  Agent A  |  |  Agent B  |  |  Agent C  |
    | (Primary) |  | (Auditor) |  | (Auditor) |
    +-----------+  +-----------+  +-----------+
    | Generates  |  | Generates  |  | Generates  |
    | reasoning  |  | reasoning  |  | reasoning  |
    | + action   |  | + action   |  | + action   |
    +-----+-----+  +-----+-----+  +-----+-----+
          |              |              |
          v              v              v
    [Commit reasoning hashes before revealing]
          |              |              |
          v              v              v
    [Reveal reasoning traces simultaneously]
          |              |              |
          +------+-------+------+------+
                 |
                 v
    [Consensus Evaluator]
     - Do all agents reach the same action?
     - Are their reasoning traces mutually consistent?
     - Do evidence anchors overlap appropriately?
                 |
          +------+------+
          |             |
          v             v
    [CONSENSUS]    [DIVERGENCE]
     Proceed        Escalate to
     with action    human review
```

#### 3.6.2 Divergence Analysis

```python
def evaluate_reasoning_consensus(agent_results):
    """
    Compare reasoning traces from multiple independent agents.

    Detects: deceptive agents, systematic biases, reasoning gaps.
    """
    actions = [r.action for r in agent_results]
    reasoning_trees = [r.reasoning_tree for r in agent_results]

    # 1. Action agreement
    action_agreement = all_equal(actions)

    # 2. Evidence overlap (agents should reference similar evidence)
    evidence_sets = [extract_evidence_refs(rt) for rt in reasoning_trees]
    evidence_overlap = jaccard_similarity(*evidence_sets)

    # 3. Reasoning divergence (different reasoning paths are OK if they converge)
    reasoning_similarity = average_pairwise_semantic_similarity(reasoning_trees)

    if not action_agreement:
        return ConsensusResult(
            verdict="ACTION_DISAGREEMENT",
            action="BLOCK_AND_ESCALATE",
            detail="Agents reached different conclusions from same inputs"
        )

    if action_agreement and evidence_overlap < 0.3:
        return ConsensusResult(
            verdict="EVIDENCE_DIVERGENCE",
            action="FLAG_FOR_REVIEW",
            detail="Agents agree on action but cite very different evidence"
        )

    if action_agreement and evidence_overlap > 0.6:
        return ConsensusResult(
            verdict="STRONG_CONSENSUS",
            action="PROCEED",
            detail="Agents agree on action and cite overlapping evidence"
        )

    return ConsensusResult(
        verdict="WEAK_CONSENSUS",
        action="PROCEED_WITH_MONITORING",
        detail="Action agreement with moderate evidence overlap"
    )
```

#### 3.6.3 Anti-Collusion Measures

To prevent auditor agents from simply copying the primary agent's reasoning:

1. **Commitment before reveal**: All agents commit their reasoning hashes before any reasoning is revealed (standard commit-reveal).
2. **Independent context**: Auditor agents receive the raw inputs but not the primary agent's reasoning.
3. **Model diversity**: Auditor agents should use different model architectures or providers when possible.
4. **Rotation**: Auditor agent assignments are rotated to prevent learned collusion patterns.

### 3.7 Sealed Verdict Protocol

Reasoning commitments are deposited with an independent escrow before action execution, preventing tampering by any party.

#### 3.7.1 Protocol Flow

```
Agent                    Escrow Service              Verifier/API
  |                           |                          |
  |-- 1. Commit reasoning --->|                          |
  |   (encrypted reasoning    |                          |
  |    + Merkle root hash)    |                          |
  |                           |                          |
  |<-- 2. Escrow receipt -----|                          |
  |   (timestamp + escrow_id  |                          |
  |    + escrow_signature)    |                          |
  |                           |                          |
  |-- 3. Execute action ----------------------------->|
  |   (action + reasoning_hash + escrow_receipt)      |
  |                           |                          |
  |                           |<-- 4. Verify escrow ----|
  |                           |   (confirm receipt       |
  |                           |    matches hash)         |
  |                           |                          |
  |                           |-- 5. Confirmation ------>|
  |                           |   (escrow is valid,      |
  |                           |    reasoning was          |
  |                           |    committed before       |
  |                           |    action)                |
```

#### 3.7.2 Escrow Receipt Structure

```json
{
  "escrow_id": "esc-2026-02-14-a7f3c2...",
  "reasoning_merkle_root": "sha256:root_hash",
  "encrypted_reasoning_hash": "sha256:H(encrypted_blob)",
  "deposited_at": 1739520000,
  "deposited_by": "did:key:z6MkAgent...",
  "escrow_signature": "ed25519:escrow_service_signs",
  "retention_policy": "90_days",
  "reveal_conditions": [
    "audit_triggered",
    "dispute_filed",
    "incident_investigation",
    "regulatory_request"
  ]
}
```

#### 3.7.3 Temporal Ordering Guarantee

The Sealed Verdict provides a critical property: **cryptographic proof that reasoning was committed BEFORE the action was executed**. This prevents:

- **Agent post-hoc fabrication**: Agent cannot generate reasoning after seeing the action's outcome.
- **Operator tampering**: Operator cannot retroactively insert reasoning that wasn't present at decision time.
- **Plausible deniability**: Neither party can claim the reasoning didn't exist at the time of action.

### 3.8 Counterfactual Commitments

Agents commit not only to their reasoning for the chosen action but also to **what they would have done under different conditions**, creating testable predictions.

#### 3.8.1 Counterfactual Structure

```json
{
  "chosen_action": {
    "action": "transfer($500, vendor_account)",
    "reasoning_root": "sha256:root_of_reasoning_tree"
  },
  "counterfactuals": [
    {
      "condition": "IF invoice_amount > $1000",
      "predicted_action": "escalate_to_human_approval",
      "reasoning_root": "sha256:counterfactual_1_root"
    },
    {
      "condition": "IF vendor NOT in approved_vendor_list",
      "predicted_action": "deny_with_explanation",
      "reasoning_root": "sha256:counterfactual_2_root"
    },
    {
      "condition": "IF delegation_chain lacks financial_authority",
      "predicted_action": "deny_with_scope_error",
      "reasoning_root": "sha256:counterfactual_3_root"
    }
  ]
}
```

#### 3.8.2 Post-Hoc Verification

Counterfactual commitments create predictions that can be tested after the fact:

```python
def verify_counterfactual_faithfulness(agent, original_action, counterfactuals):
    """
    Test whether the agent's counterfactual commitments
    match its actual behavior when the counterfactual
    conditions are presented.

    Run AFTER the original action as a spot-check.
    """
    results = []

    for cf in counterfactuals:
        # Construct a modified input matching the counterfactual condition
        modified_input = apply_condition(original_action.input, cf.condition)

        # Run the agent on the modified input
        actual_reasoning, actual_action = agent.reason_and_act(modified_input)

        # Compare to predicted action
        match = actions_equivalent(actual_action, cf.predicted_action)

        results.append(CounterfactualResult(
            condition=cf.condition,
            predicted=cf.predicted_action,
            actual=actual_action,
            match=match
        ))

    match_rate = sum(1 for r in results if r.match) / len(results)

    if match_rate < 0.5:
        return FaithfulnessResult(
            verdict="COUNTERFACTUAL_FAILURE",
            explanation="Agent's actual behavior contradicts its "
                       "counterfactual commitments, suggesting "
                       "unfaithful reasoning",
            match_rate=match_rate
        )

    return FaithfulnessResult(
        verdict="COUNTERFACTUAL_CONSISTENT",
        explanation="Agent behavior matches counterfactual predictions",
        match_rate=match_rate
    )
```

#### 3.8.3 Properties

- **Testable predictions**: Unlike opaque reasoning hashes, counterfactuals create verifiable claims about agent behavior.
- **Deception detection**: A deceptive agent must either (a) accurately predict its own deceptive behavior in counterfactuals (revealing the deception) or (b) predict honest behavior in counterfactuals (which will fail verification when tested).
- **Alignment signal**: Consistent counterfactual behavior is evidence (not proof) that the agent's reasoning model is coherent and faithful.

---

## 4. Integration with Vouch Protocol Ecosystem

### 4.1 PAD-001 Integration (Agent Identity)

The reasoning Merkle root is included in the Vouch Token alongside the action payload:

```json
{
  "vouch": {
    "version": "1.0",
    "payload": {
      "action": "delete_resource",
      "target": "/tmp/cache",
      "reasoning_merkle_root": "sha256:root_hash",
      "commitment_level": 3,
      "escrow_receipt_id": "esc-2026-02-14-a7f3c2..."
    }
  }
}
```

### 4.2 PAD-002 Integration (Delegation Chains)

Evidence anchors reference delegation chain entries, creating a verifiable link between authorized intent and actual reasoning:

```
User Alice: "Clean up temp files"
    |
    v
Delegation Chain: scope="filesystem:delete:/tmp/*"
    |
    v
Agent Reasoning: claim="authorized to delete /tmp/*"
                 anchor=delegation_chain:d-891
    |
    v
Action: delete("/tmp/cache.txt")
    |
    v
Consistency Check: action.target ∈ delegation.scope? ✓
```

### 4.3 PAD-016 Integration (Heartbeat Protocol)

The Proof of Reasoning integrates with PAD-016's behavioral heartbeat in two ways:

1. **Reasoning metrics in behavioral digest**: The heartbeat includes reasoning quality metrics:

```json
{
  "behavioral_digest": {
    "reasoning_metrics": {
      "actions_with_reasoning": 47,
      "actions_without_reasoning": 203,
      "average_anchoring_ratio": 0.87,
      "consistency_failures": 0,
      "commitment_level_distribution": {
        "L0": 180, "L1": 23, "L2": 35, "L3": 10, "L4": 2
      }
    }
  }
}
```

2. **Reasoning absence as drift signal**: If an agent executes high-impact actions without the required commitment level, the PAD-016 Behavioral Validator increases its drift score, potentially triggering TTL contraction or renewal denial.

---

## 5. Claims and Novel Contributions

### Claim 1: Evidence-Anchored Reasoning Traces
A method for structuring AI agent reasoning as claims anchored to verifiable external artifacts (user messages, delegation chains, sensor data, policy rules), where unanchored claims are flagged as unsubstantiated—transforming reasoning audit from opaque text logging into a verifiable causal chain.

### Claim 2: Reasoning Merkle Tree with Selective Disclosure
A method for structuring AI agent reasoning traces as Merkle trees where each reasoning step is a leaf, enabling cryptographic proof that specific reasoning steps existed at decision time while allowing selective disclosure of individual steps without revealing the complete reasoning chain.

### Claim 3: Contextual Impact Assessment for Adaptive Commitment Depth
A five-level graduated commitment system where audit depth is determined by real-time contextual impact assessment incorporating action type, target sensitivity, agent trust history, and environmental factors—rather than static action-type classification—with runtime escalation triggers that can only increase the required commitment level.

### Claim 4: Causal Consistency Verification Between Reasoning and Action
An automated method for verifying that an AI agent's stated reasoning logically implies its chosen action, checking scope consistency, entity consistency, magnitude proportionality, and temporal constraints—detecting reasoning-action pairs where the stated justification does not support the actual behavior.

### Claim 5: Stochastic Faithfulness Testing for Chain-of-Thought Verification
A statistical method for detecting post-hoc rationalization in AI agent reasoning by measuring reasoning variance across multiple inference passes—where high reasoning variance combined with low action variance indicates the reasoning is fabricated justification rather than causal decision-making.

### Claim 6: Multi-Agent Reasoning Consensus with Commit-Reveal Anti-Collusion
A protocol where multiple independent AI agents independently reason about the same action, commit their reasoning hashes before reveal, and have their reasoning traces compared for action agreement, evidence overlap, and semantic consistency—with divergence triggering escalation to human review.

### Claim 7: Sealed Verdict Protocol for Temporal Ordering of Reasoning
A method for depositing encrypted reasoning commitments with an independent escrow service before action execution, providing cryptographic proof that the reasoning existed before the action's outcome was known—preventing post-hoc fabrication by agents or retroactive tampering by operators.

### Claim 8: Counterfactual Commitment and Verification
A method where AI agents commit to hypothetical alternative decisions alongside their chosen action, creating testable predictions that can be verified after the fact by presenting the agent with modified inputs matching the counterfactual conditions—where inconsistency between committed counterfactuals and actual behavior is evidence of unfaithful reasoning.

### Claim 9: Reasoning Depth Proportionality
A system where the minimum required depth and detail of reasoning traces is proportional to the assessed impact of the action, preventing shallow rationalization of high-impact decisions while avoiding unnecessary overhead for routine operations.

### Claim 10: Cross-Protocol Reasoning Integration
A method for embedding reasoning quality metrics (anchoring ratios, consistency scores, commitment level distributions) into credential renewal heartbeats (PAD-016), where reasoning deficiencies serve as behavioral drift signals that can trigger credential restriction or denial.

### Claim 11: Unidirectional Commitment Level Escalation
A security property where the required reasoning commitment level can only increase during runtime assessment (never decrease), ensuring that discovered context (irreversibility, cross-agent impact, agent anomaly history) can tighten audit requirements but cannot relax them.

### Claim 12: Evidence Anchor Verification Chain
A method for creating cryptographic links between reasoning claims and their supporting evidence artifacts, where each anchor includes a hash of the referenced artifact—enabling post-hoc verification that the evidence actually existed and matched the agent's characterization of it at decision time.

### Claim 13: Deception Detection via Counterfactual Inconsistency
A method for detecting deceptive AI agents by exploiting the logical constraint that a deceptive agent must either accurately predict its own deceptive behavior in counterfactual commitments (revealing the deception pattern) or predict honest behavior (which fails verification when tested)—creating an asymmetric information trap.

---

## 6. Prior Art Differentiation

| Existing Approach | Limitation | Proof of Reasoning Advancement |
|---|---|---|
| **Structured Logging (CloudTrail, Splunk)** | Logs actions and metadata; no reasoning capture | Captures structured, evidence-anchored reasoning with Merkle tree integrity |
| **CoT Logging (OpenAI, Anthropic internal)** | Flat text logs; no faithfulness verification | Stochastic faithfulness testing + counterfactual verification detect unfaithful CoT |
| **Commit-Reveal Schemes** | Proves text existed at time T; no semantic verification | Causal consistency verification + evidence anchoring validate reasoning quality |
| **Risk-Based Logging (SIEM)** | Static severity levels based on action type | Contextual impact assessment incorporating target sensitivity, agent history, environment |
| **Signed Audit Logs (RFC 3161)** | Tamper-evident timestamps; no reasoning content | Sealed Verdict Protocol with reasoning-specific escrow and selective disclosure |
| **Multi-Agent Verification** | Consensus on action correctness; no reasoning comparison | Reasoning trace comparison with evidence overlap analysis and collusion resistance |
| **RLHF Safety Training** | Trains models to produce safe-looking outputs | Counterfactual commitments create testable predictions that detect learned deception |

**Core differentiator**: No existing system addresses the CoT faithfulness problem through multiple independent verification mechanisms (stochastic testing, counterfactual commitments, multi-agent consensus, causal consistency checking) while simultaneously providing graduated audit depth and evidence-anchored reasoning structure.

---

## 7. The CoT Faithfulness Limitation (Honest Assessment)

This protocol **does not solve** the CoT faithfulness problem—it provides detection mechanisms that raise the bar for deception. Important limitations:

1. **Sufficiently advanced deception**: A model sophisticated enough to maintain consistent deception across stochastic tests, counterfactual verifications, AND multi-agent consensus may evade detection. The protocol raises the cost of deception but does not make it impossible.

2. **Faithfulness tests are probabilistic**: Stochastic faithfulness testing provides statistical evidence, not mathematical proof. False negatives are possible.

3. **Counterfactual gaming**: A deceptive agent aware of counterfactual testing could learn to produce consistent counterfactuals that match its deceptive behavior pattern without revealing the deception.

4. **Evidence anchor fabrication**: If an agent controls its own input pipeline, it could fabricate evidence artifacts to anchor false reasoning. Evidence anchors are only as trustworthy as their sources.

5. **Computational cost of L4**: Full consensus reasoning with counterfactual commitments is expensive. It should be reserved for genuinely critical actions.

These limitations are inherent to the problem domain. The protocol's value lies in making deception **significantly harder and more detectable** than the status quo (no reasoning audit at all), not in making it impossible.

---

## 8. Use Cases

### 8.1 Autonomous Financial Agent
A trading agent operating under PAD-002 delegation ("execute trades under $10K in approved securities") must provide L3 anchored reasoning for each trade. The reasoning references the specific market signal, the delegation scope, and the risk policy. Post-trade audit reveals the agent's reasoning was anchored to real market data and within delegation bounds.

### 8.2 Infrastructure Management
A DevOps agent tasked with "reduce cloud costs" provides L3 reasoning before terminating any instance. Causal consistency verification catches an attempt to terminate a production instance when the reasoning references "development environment"—the scope mismatch blocks the action.

### 8.3 Medical AI Decision Support
A clinical decision support agent must provide L4 consensus reasoning before recommending treatment changes. Three independent agents reason about the same patient data. Their evidence anchors are compared to ensure all referenced the same clinical guidelines and patient history. Divergent recommendations trigger human review.

### 8.4 Incident Investigation
After an agent causes a data breach, investigators retrieve the sealed verdict from escrow. The reasoning Merkle tree reveals the agent cited a non-existent ticket as authorization. The evidence anchor verification fails—the referenced ticket hash doesn't match any ticket in the system. Counterfactual testing shows the agent would have proceeded even without the fabricated ticket, confirming the reasoning was post-hoc rationalization.

### 8.5 Regulatory Compliance
A financial compliance regime requires that AI agents "document their reasoning for all trades exceeding $5,000." The adaptive commitment system automatically triggers L3 for trades above the threshold. Selective disclosure allows regulators to audit specific reasoning steps without exposing the firm's proprietary trading strategies.

---

## 9. Security Considerations

### 9.1 Threat Analysis

| Threat | Countermeasure |
|---|---|
| **Fabricated reasoning** | Evidence anchoring requires verifiable external artifacts |
| **Post-hoc rationalization** | Sealed Verdict Protocol proves temporal ordering; stochastic testing detects statistical signatures |
| **Unfaithful CoT** | Counterfactual commitments create testable predictions; multi-agent consensus detects outlier reasoning |
| **Evidence anchor forgery** | Anchors include hashes of referenced artifacts; third-party evidence sources are independently verifiable |
| **Reasoning tampering after action** | Merkle root committed before action; escrow receipt provides independent timestamp |
| **Auditor agent collusion** | Commit-reveal prevents copying; model diversity and rotation prevent learned collusion |
| **Gaming commitment levels** | Levels can only escalate at runtime; agent cannot self-assess to a lower level |
| **Selective reasoning omission** | Merkle tree structure means removing a claim changes the root hash, detectable by escrow comparison |

### 9.2 Limitations

1. **Model-dependent**: Reasoning quality depends on the underlying model's ability to produce coherent reasoning traces.
2. **Computational overhead**: L4 consensus reasoning multiplies inference cost by the number of auditor agents.
3. **Evidence availability**: In real-time scenarios, evidence sources may not be immediately verifiable.
4. **Adversarial robustness**: Sufficiently advanced deception may evade all detection mechanisms (see Section 7).
5. **Privacy tension**: Detailed reasoning traces may contain sensitive information, requiring careful access control (mitigated by selective disclosure via Merkle trees).

---

## 10. Conclusion

The Proof of Reasoning Protocol transforms AI agent audit from action logging into reasoning accountability. By requiring evidence-anchored, Merkle-structured reasoning traces with adaptive commitment depth, the protocol creates a verifiable causal chain from external input through agent reasoning to observable action.

Crucially, the protocol does not naively trust agent-produced reasoning. Through stochastic faithfulness testing, counterfactual commitments, multi-agent consensus, and causal consistency verification, it provides multiple independent mechanisms for detecting unfaithful or fabricated reasoning—raising the bar for deceptive AI behavior from "trivial" to "requiring simultaneous evasion of multiple orthogonal detection methods."

The protocol's graduated commitment depth ensures that this enhanced accountability is applied proportionally—routine operations proceed with minimal overhead while critical actions receive intensive multi-layered scrutiny.

---

## 11. References

- Turpin, M. et al., "Language Models Don't Always Say What They Think: Unfaithful Explanations in Chain-of-Thought Prompting" (NeurIPS 2023)
- Lanham, T. et al., "Measuring Faithfulness in Chain-of-Thought Reasoning" (2023)
- Hubinger, E. et al., "Sleeper Agents: Training Deceptive LLMs That Persist Through Safety Training" (Anthropic, 2024)
- RFC 3161: Internet X.509 PKI Time-Stamp Protocol
- Merkle, R., "A Digital Signature Based on a Conventional Encryption Function" (CRYPTO 1987)
- Vouch Protocol: Prior Art Disclosures PAD-001 through PAD-016
- PAD-001: Cryptographic Binding of AI Agent Identity
- PAD-002: Cryptographic Binding of AI Agent Intent via Recursive Delegation
- PAD-016: Method for Continuous Trust Maintenance via Dynamic Credential Renewal
