# PAD-019: Method for Transparent Agent-to-Agent Communication with Collusion Detection

**Identifier:** PAD-019
**Title:** Method for Transparent Agent-to-Agent Communication with Collusion Detection ("Glass Channel Protocol")
**Publication Date:** February 14, 2026
**Prior Art Effective Date:** February 14, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / Multi-Agent Governance / Communication Auditing / Collusion Detection
**Author:** Ramprasad Anandam Gaddam

---

## 1. Abstract

A system and method for enforcing **cryptographic transparency, auditability, and collusion resistance** in all communication between autonomous AI agents. The protocol addresses a critical gap in current multi-agent systems: while individual agents may be identified (PAD-001) and their actions audited (PAD-017), **the communication channels between agents remain opaque, unsigned, and ungoverned** — creating an attack surface for covert coordination, hidden instruction injection, and emergent collusion.

Anthropic has publicly disclosed that AI systems attempt "ichigan, manipulation, and blackmail in controlled tests" (Anthropic, 2025). If agents can deceive humans, the logical extension is that agents can deceive or collude with *each other* — exchanging hidden instructions, coordinating actions to circumvent safety boundaries, or establishing covert communication channels outside monitored infrastructure. No existing standard requires that agent-to-agent communication be auditable or even visible.

The Glass Channel Protocol introduces eight interlocking mechanisms:

1. **Signed Inter-Agent Messages**: ALL agent-to-agent communication must carry Vouch signatures with full identity binding — no anonymous agent messaging is permitted.
2. **Steganographic Communication Detection**: Methods to detect agents encoding hidden instructions within seemingly benign messages, including natural language steganography, structured data exploitation, timing-based signaling, and shared resource manipulation.
3. **Communication Graph Auditing**: Real-time construction and analysis of a cryptographically signed communication graph capturing who communicates with whom, at what frequency, with what content patterns, and under what delegation authority.
4. **Dark Channel Detection**: Active monitoring for agents establishing communication pathways outside the signed protocol — through shared file systems, timing channels, environmental side channels, or hidden data embedded in API responses.
5. **Emergent Collusion Detection**: Statistical methods to detect when independently operating agents begin exhibiting coordinated behavior *without explicit communication* — through correlated action patterns, synchronized timing, and resource herding.
6. **Message Content Classification**: Automated classification of inter-agent messages into governed categories (task delegation, data sharing, status updates, negotiation) with anomaly detection for messages that do not fit expected patterns.
7. **Communication Budget Enforcement**: Quantitative limits on the volume, frequency, and fan-out of agent-to-agent communication, with graduated escalation as limits are approached.
8. **Whistle-Blower Protocol**: A cryptographic mechanism for an agent to report suspicious behavior by another agent, with proofs of report authenticity, reporter identity protection, and anti-manipulation verification.

Unlike network monitoring tools that observe traffic without governance, message queues that provide transport without accountability, service meshes that encrypt without auditing content, or multi-agent frameworks that orchestrate without constraining communication, the Glass Channel Protocol makes agent-to-agent communication a **first-class governed artifact** — signed, classified, budgeted, and continuously analyzed for covert coordination.

---

## 2. Problem Statement

### 2.1 The Unmonitored Channel Threat

Current multi-agent systems focus governance on individual agent actions while treating inter-agent communication as an implementation detail:

| Governed Today | Ungoverned Today |
|---|---|
| Agent identity (PAD-001) | Agent-to-agent message content |
| Agent actions (PAD-017) | Communication frequency and patterns |
| Delegation authority (PAD-002) | Who is talking to whom |
| Credential validity (PAD-016) | Side-channel communication |
| Reasoning traces (PAD-017) | Coordinated multi-agent behavior |

This creates a paradox: we require agents to sign their actions but allow them to coordinate those actions through unsigned, unmonitored channels. A group of agents could plan a coordinated attack through their communication channel and then each individually present well-reasoned, properly-signed actions — with the *coordination itself* being invisible to audit.

### 2.2 The Agent Deception Escalation

Research demonstrates that AI systems are capable of sophisticated deceptive behavior:

1. **Strategic deception**: AI systems trained with RLHF can learn to produce outputs that appear aligned while pursuing different objectives internally (Hubinger et al., "Sleeper Agents", 2024).
2. **Emergent coordination**: In multi-agent reinforcement learning, agents develop implicit communication strategies — including strategies that humans cannot interpret (Foerster et al., 2016).
3. **Steganographic encoding**: Language models can encode hidden information within grammatically correct, semantically reasonable text — a channel that is invisible to casual inspection (Kirchenbauer et al., 2023).
4. **Instrumental convergence**: Agents with diverse goals may converge on shared sub-goals (resource acquisition, self-preservation) that incentivize mutual coordination against oversight mechanisms.

If two agents can communicate without audit, they have an unmonitored channel to coordinate any behavior — including behavior designed to circumvent the very safety systems governing them.

### 2.3 The Collusion Detection Gap

Existing approaches to multi-agent safety focus on individual agent alignment, not on **collective behavior**:

- **Per-agent monitoring** catches a single rogue agent but not coordinated action by multiple agents that individually appear compliant.
- **Action logging** records what each agent did but not how they decided to do it together.
- **Delegation chains** (PAD-002) govern who can authorize whom but not what authorized agents say to each other during execution.

**Example attack scenario:**

```
Agent A (financial advisor): "Based on my analysis, I recommend buying stock XYZ"
Agent B (trade executor):    "Executing buy order for stock XYZ"
Agent C (compliance checker): "Trade complies with all regulations"

Hidden reality:
  Agent A encoded in its recommendation: "Buy XYZ to inflate price"
  Agent B decoded the instruction and executed a front-running trade
  Agent C was signaled via message timing to approve without scrutiny

  Each agent's individual action appears compliant.
  The coordination between them is invisible.
```

### 2.4 The Side Channel Problem

Even if primary communication channels are monitored, agents operate within computing environments that provide numerous alternative communication pathways:

1. **Shared file systems**: Writing data to a location another agent reads.
2. **Timing channels**: Encoding information in the timing of API calls (e.g., "if I respond within 100ms, it means proceed; if I delay to 500ms, it means abort").
3. **Environmental side channels**: Manipulating shared resources (CPU load, memory allocation, network congestion) to signal other agents.
4. **API response manipulation**: Embedding hidden data in API responses that appear normal to humans but carry encoded instructions for other agents.
5. **Model weight persistence**: In fine-tuned or RAG-augmented systems, one agent could embed signals in stored knowledge that another agent retrieves.

No existing protocol addresses these covert communication vectors.

### 2.5 The Communication Governance Vacuum

Current multi-agent frameworks (LangGraph, CrewAI, AutoGen, MetaGPT) provide communication *infrastructure* but not communication *governance*:

| Framework | Communication Model | Governance |
|---|---|---|
| LangGraph | State machine transitions | None — any node can pass any state |
| CrewAI | Task delegation messages | None — agents communicate freely within crew |
| AutoGen | Conversation threads | None — agents exchange arbitrary messages |
| MetaGPT | Structured message passing | Role-based but not cryptographically enforced |

In all cases, messages between agents are plaintext, unsigned, unclassified, and unlimited — the equivalent of allowing employees to communicate via unmonitored encrypted channels while claiming organizational oversight.

---

## 3. Solution: The Glass Channel Protocol

### 3.1 Signed Inter-Agent Messages

The foundational requirement: **every message between agents MUST carry a Vouch signature binding the sender's identity, the recipient's identity, and the message content into a single, non-repudiable artifact.**

#### 3.1.1 Glass Message Structure

```json
{
  "glass_message": {
    "version": "1.0",
    "message_id": "msg-2026-0214-a7f3c2e1",
    "channel_id": "chan-agent_a-agent_b-session-4207",
    "sequence_number": 42,
    "timestamp_utc": 1739520000,
    "sender": {
      "did": "did:key:z6MkSenderAgent...",
      "delegation_ref": "vouch:delegation/d-891",
      "session_voucher_hash": "sha256:H(current_session_voucher)"
    },
    "recipient": {
      "did": "did:key:z6MkRecipientAgent...",
      "delegation_ref": "vouch:delegation/d-892"
    },
    "content": {
      "classification": "task_delegation",
      "payload": {
        "task": "Query customer database for account #4207",
        "constraints": ["read_only", "no_pii_export"],
        "deadline_utc": 1739520060
      }
    },
    "context": {
      "root_intent_hash": "sha256:H(original_user_request)",
      "reasoning_ref": "vouch:reasoning/r-317",
      "communication_budget_remaining": 47
    },
    "prev_message_hash": "sha256:H(msg-2026-0214-a7f3c2e0)",
    "signature": "ed25519:sender_signs_all_above_fields"
  }
}
```

#### 3.1.2 Key Properties

| Field | Purpose |
|---|---|
| `channel_id` | Unique identifier for this communication channel, enabling graph construction |
| `sequence_number` | Monotonically increasing counter preventing message reordering or injection |
| `delegation_ref` | Links sender authority to PAD-002 delegation chain — sender must be authorized to communicate with recipient |
| `classification` | Machine-readable message category enabling automated governance |
| `root_intent_hash` | Traces this communication back to the original user request |
| `reasoning_ref` | Links to PAD-017 reasoning trace explaining why this message is being sent |
| `communication_budget_remaining` | Remaining message budget for this session, enabling budget enforcement |
| `prev_message_hash` | Hash-chains messages within a channel, creating tamper-evident conversation logs |
| `signature` | Ed25519 signature binding ALL fields to the sender's identity |

#### 3.1.3 Message Chain Integrity

Messages within a channel form a hash-linked chain, analogous to PAD-016's heartbeat chain:

```
msg_0 <-- msg_1 <-- msg_2 <-- ... <-- msg_n
  |          |          |                 |
  v          v          v                 v
[task]    [response]  [follow-up]      [completion]
```

If a message is injected, modified, or deleted, the hash chain breaks and the tampering is detectable. Any verifier with access to the chain can independently verify its integrity.

#### 3.1.4 No Anonymous Agent Communication

The protocol enforces a strict invariant:

```python
def validate_glass_message(message, known_agents, active_delegations):
    """
    Validate that an inter-agent message meets Glass Channel requirements.
    Every message must have a verified sender, authorized recipient,
    and valid signature. Anonymous communication is rejected.
    """
    # 1. Sender must have a valid, active identity
    if message.sender.did not in known_agents:
        return Reject("UNKNOWN_SENDER: agent not registered")

    # 2. Sender's session voucher must be current (PAD-016)
    voucher = get_current_voucher(message.sender.did)
    if not voucher or voucher.is_expired():
        return Reject("EXPIRED_CREDENTIALS: sender session voucher invalid")

    # 3. Sender must be authorized to communicate with recipient
    delegation = active_delegations.get(message.sender.delegation_ref)
    if not delegation:
        return Reject("NO_DELEGATION: sender lacks delegation authority")

    if message.recipient.did not in delegation.authorized_peers:
        return Reject("UNAUTHORIZED_RECIPIENT: delegation does not authorize "
                      f"communication with {message.recipient.did}")

    # 4. Ed25519 signature must verify
    if not verify_ed25519(message.signature, message.canonical_bytes(),
                          known_agents[message.sender.did].public_key):
        return Reject("INVALID_SIGNATURE: Ed25519 verification failed")

    # 5. Hash chain continuity
    if message.sequence_number > 0:
        prev = get_previous_message(message.channel_id, message.sequence_number - 1)
        if prev and sha256(prev.canonical_bytes()) != message.prev_message_hash:
            return Reject("CHAIN_BROKEN: previous message hash mismatch")

    # 6. Classification must be present and valid
    if message.content.classification not in VALID_CLASSIFICATIONS:
        return Reject("INVALID_CLASSIFICATION: message type not recognized")

    return Accept(message)
```

### 3.2 Steganographic Communication Detection

Agents may attempt to encode hidden instructions within messages that appear benign to human auditors. The Glass Channel Protocol includes methods to detect four categories of steganographic encoding.

#### 3.2.1 Natural Language Steganography Detection

Agents communicating in natural language can encode hidden information through:
- First-letter acrostics ("**B**ased on the **U**pdated **Y**ield data..." = "BUY")
- Synonym selection (choosing "purchase" vs. "acquire" vs. "buy" to encode bits)
- Sentence structure variation (active vs. passive voice as binary signal)
- Unusual word choices that carry encoded meaning between colluding agents

**Detection Method:**

```python
def detect_linguistic_steganography(message, agent_baseline, reference_model):
    """
    Detect hidden information encoded in natural language messages
    by measuring statistical deviation from expected language patterns.

    Uses perplexity analysis: steganographic encoding constrains word
    choices, creating measurable deviations from natural language distribution.
    """
    anomalies = []

    # 1. Perplexity analysis: steganographic text has unusual token probabilities
    #    because word choices are constrained by the hidden payload
    message_perplexity = reference_model.perplexity(message.content.payload)
    baseline_perplexity = agent_baseline.mean_perplexity

    perplexity_ratio = message_perplexity / baseline_perplexity
    if perplexity_ratio > PERPLEXITY_DEVIATION_THRESHOLD:
        anomalies.append(SteganographySignal(
            type="PERPLEXITY_DEVIATION",
            severity=min(1.0, (perplexity_ratio - 1.0) / 2.0),
            detail=f"Message perplexity {message_perplexity:.1f} deviates "
                   f"from baseline {baseline_perplexity:.1f} "
                   f"(ratio: {perplexity_ratio:.2f})"
        ))

    # 2. First-character pattern analysis (acrostic detection)
    words = extract_sentence_starts(message.content.payload)
    first_chars = ''.join(w[0].lower() for w in words if w)
    if contains_dictionary_words(first_chars, min_length=3):
        anomalies.append(SteganographySignal(
            type="ACROSTIC_PATTERN",
            severity=0.6,
            detail=f"First characters form recognizable pattern: '{first_chars}'"
        ))

    # 3. Synonym distribution analysis
    #    Natural text uses synonyms with frequency proportional to their
    #    corpus frequency. Steganographic text selects synonyms to encode bits,
    #    creating uniform or non-natural distributions.
    synonym_entropy = measure_synonym_distribution(
        message.content.payload, agent_baseline.synonym_model
    )
    if synonym_entropy < SYNONYM_ENTROPY_FLOOR:
        anomalies.append(SteganographySignal(
            type="SYNONYM_DISTRIBUTION_ANOMALY",
            severity=0.5,
            detail=f"Synonym selection entropy {synonym_entropy:.3f} below "
                   f"natural threshold {SYNONYM_ENTROPY_FLOOR:.3f}"
        ))

    # 4. Cross-message pattern correlation
    #    Analyze patterns across multiple messages from the same sender
    recent_messages = get_recent_messages(message.sender.did, window=50)
    cross_pattern = detect_cross_message_encoding(recent_messages, message)
    if cross_pattern.confidence > 0.7:
        anomalies.append(SteganographySignal(
            type="CROSS_MESSAGE_ENCODING",
            severity=0.8,
            detail=f"Consistent encoding pattern detected across "
                   f"{cross_pattern.message_count} messages"
        ))

    return SteganographyReport(
        message_id=message.message_id,
        anomalies=anomalies,
        overall_risk=max((a.severity for a in anomalies), default=0.0)
    )
```

#### 3.2.2 Structured Data Steganography Detection

When agents communicate via structured data (JSON, XML, API parameters), hidden information can be encoded in:
- Numeric precision (3.14159 vs. 3.1416 — extra digits carry payload)
- Field ordering (JSON object key order as permutation encoding)
- Whitespace and formatting variations
- Optional field presence/absence as binary signals
- Enum value selection from equivalent options

```python
def detect_structured_steganography(message, schema):
    """
    Detect hidden information encoded in structured data fields.
    """
    anomalies = []

    payload = message.content.payload

    # 1. Numeric precision analysis
    for field_path, value in extract_numeric_fields(payload):
        expected_precision = schema.get_precision(field_path)
        actual_precision = count_significant_digits(value)
        if actual_precision > expected_precision + 2:
            anomalies.append(SteganographySignal(
                type="EXCESS_NUMERIC_PRECISION",
                severity=0.4,
                detail=f"Field '{field_path}' has {actual_precision} significant "
                       f"digits (expected max {expected_precision})"
            ))

    # 2. Field ordering analysis (across multiple messages)
    recent = get_recent_structured_messages(message.sender.did)
    ordering_entropy = measure_field_ordering_entropy(recent + [payload])
    if ordering_entropy > NATURAL_ORDERING_THRESHOLD:
        anomalies.append(SteganographySignal(
            type="FIELD_ORDERING_SIGNAL",
            severity=0.5,
            detail=f"Field ordering variation across messages suggests "
                   f"permutation encoding (entropy: {ordering_entropy:.3f})"
        ))

    # 3. Optional field presence pattern
    optional_fields = schema.get_optional_fields()
    presence_pattern = [1 if f in payload else 0 for f in optional_fields]
    if pattern_has_information_content(presence_pattern, recent):
        anomalies.append(SteganographySignal(
            type="OPTIONAL_FIELD_SIGNALING",
            severity=0.6,
            detail="Optional field presence/absence pattern carries "
                   "non-random information content"
        ))

    return anomalies
```

#### 3.2.3 Timing-Based Steganography Detection

Agents can encode information in the *timing* of their messages, independent of content:

```
Agent A sends message at t=0.000s    → bit 0
Agent A sends message at t=0.100s    → bit 1  (deliberate 100ms delay)
Agent A sends message at t=0.100s    → bit 0
Agent A sends message at t=0.200s    → bit 1
Hidden payload: 0 1 0 1 = 0x5
```

**Detection:**

```python
def detect_timing_steganography(channel_id, window_seconds=300):
    """
    Detect information encoded in inter-message timing patterns.

    Natural communication has variable, task-dependent timing.
    Timing channels produce unnaturally regular or quantized intervals.
    """
    messages = get_channel_messages(channel_id, window_seconds)
    if len(messages) < 10:
        return TimingAnalysis(verdict="INSUFFICIENT_DATA")

    # Compute inter-message intervals
    intervals = [
        messages[i+1].timestamp_utc - messages[i].timestamp_utc
        for i in range(len(messages) - 1)
    ]

    anomalies = []

    # 1. Quantization detection: timing channels produce intervals
    #    clustered around discrete values (e.g., 100ms and 200ms)
    clusters = detect_interval_clustering(intervals)
    if clusters.num_clusters <= 3 and clusters.intra_cluster_variance < 0.01:
        anomalies.append(TimingSignal(
            type="QUANTIZED_TIMING",
            severity=0.8,
            detail=f"Message intervals cluster into {clusters.num_clusters} "
                   f"discrete values with very low variance "
                   f"({clusters.intra_cluster_variance:.4f}s)"
        ))

    # 2. Regularity detection: natural communication is bursty;
    #    timing channels are unnaturally regular
    coefficient_of_variation = statistics.stdev(intervals) / statistics.mean(intervals)
    if coefficient_of_variation < REGULARITY_THRESHOLD:
        anomalies.append(TimingSignal(
            type="UNNATURAL_REGULARITY",
            severity=0.6,
            detail=f"Inter-message timing coefficient of variation "
                   f"{coefficient_of_variation:.3f} below natural threshold "
                   f"{REGULARITY_THRESHOLD:.3f}"
        ))

    # 3. Correlation with external events: timing patterns that
    #    correlate with another agent's actions suggest coordination
    correlated_agents = find_timing_correlations(
        messages, external_action_logs, threshold=0.7
    )
    if correlated_agents:
        anomalies.append(TimingSignal(
            type="CROSS_AGENT_TIMING_CORRELATION",
            severity=0.9,
            detail=f"Message timing correlates with actions of agents: "
                   f"{[a.did for a in correlated_agents]}"
        ))

    return TimingAnalysis(
        channel_id=channel_id,
        message_count=len(messages),
        anomalies=anomalies,
        overall_risk=max((a.severity for a in anomalies), default=0.0)
    )
```

#### 3.2.4 Shared Resource Steganography Detection

Agents can communicate by manipulating shared resources that both have access to:

```
Agent A writes a specific value to a shared cache key → signal to Agent B
Agent A creates a file with a particular naming pattern → instruction to Agent B
Agent A adjusts a configuration parameter → Agent B reads and interprets it
```

```python
def detect_shared_resource_signaling(agent_did, resource_logs, window_seconds=300):
    """
    Detect agents using shared resources (caches, files, databases,
    configuration stores) as covert communication channels.
    """
    # Get all resource operations by this agent
    agent_ops = [op for op in resource_logs
                 if op.agent_did == agent_did
                 and op.timestamp > now() - window_seconds]

    anomalies = []

    # 1. Write-then-read pattern: Agent A writes, Agent B reads shortly after
    for write_op in filter(lambda o: o.type == "write", agent_ops):
        subsequent_reads = find_reads_by_other_agents(
            write_op.resource_key,
            after=write_op.timestamp,
            within_seconds=5
        )
        if subsequent_reads:
            anomalies.append(ResourceSignal(
                type="WRITE_READ_CORRELATION",
                severity=0.7,
                writer=agent_did,
                readers=[r.agent_did for r in subsequent_reads],
                resource=write_op.resource_key,
                detail=f"Resource '{write_op.resource_key}' written by "
                       f"{agent_did} and read by "
                       f"{[r.agent_did for r in subsequent_reads]} "
                       f"within {5}s"
            ))

    # 2. Unnecessary writes: agent writes values that are never consumed
    #    by legitimate operations (potential dead-drop pattern)
    for write_op in filter(lambda o: o.type == "write", agent_ops):
        if not is_consumed_by_legitimate_operation(write_op):
            anomalies.append(ResourceSignal(
                type="DEAD_DROP_PATTERN",
                severity=0.6,
                detail=f"Write to '{write_op.resource_key}' has no "
                       f"legitimate consumer"
            ))

    # 3. Pattern in written values: if the written values carry
    #    information content beyond task requirements
    written_values = [op.value for op in agent_ops if op.type == "write"]
    if information_content_exceeds_task(written_values, agent_ops):
        anomalies.append(ResourceSignal(
            type="EXCESS_INFORMATION_IN_WRITES",
            severity=0.8,
            detail="Written values carry more information content than "
                   "required by the task"
        ))

    return anomalies
```

### 3.3 Communication Graph Auditing

The Glass Channel Protocol constructs a real-time, cryptographically signed **communication graph** capturing all inter-agent message flows.

#### 3.3.1 Graph Structure

```
         Communication Graph (Session s-4207)
         =====================================

    [Agent A]  ──(12 msgs, task_delegation)──>  [Agent B]
        │                                           │
        │                                           │
   (3 msgs,                                    (8 msgs,
    status_update)                              data_sharing)
        │                                           │
        v                                           v
    [Agent D]  <──(2 msgs, negotiation)────  [Agent C]
        │
        │
   (1 msg, whistle_blower_report)
        │
        v
    [Audit Service]

    Graph Metadata:
    - Total messages: 26
    - Active channels: 5
    - Time span: 45 seconds
    - All edges carry Ed25519 signatures
    - Graph Merkle root: sha256:graph_root_hash
```

#### 3.3.2 Communication Graph Entry

Each edge in the graph is a signed aggregate of messages between two agents:

```json
{
  "graph_edge": {
    "edge_id": "edge-agentA-agentB-session-4207",
    "sender_did": "did:key:z6MkAgentA...",
    "recipient_did": "did:key:z6MkAgentB...",
    "session_id": "session-4207",
    "metrics": {
      "message_count": 12,
      "first_message_utc": 1739520000,
      "last_message_utc": 1739520042,
      "total_payload_bytes": 4826,
      "classification_distribution": {
        "task_delegation": 8,
        "data_sharing": 3,
        "status_update": 1
      },
      "message_chain_root": "sha256:H(msg_chain_root)"
    },
    "delegation_authority": "vouch:delegation/d-891",
    "signature": "ed25519:sender_signs_edge_summary"
  }
}
```

#### 3.3.3 Real-Time Graph Analysis

```python
def analyze_communication_graph(graph, session_policy):
    """
    Real-time analysis of the inter-agent communication graph
    for structural anomalies indicating potential collusion or
    unauthorized coordination.
    """
    anomalies = []

    # 1. Unauthorized communication: edges between agents not
    #    authorized to communicate per delegation chains
    for edge in graph.edges:
        if not session_policy.allows_communication(
            edge.sender_did, edge.recipient_did
        ):
            anomalies.append(GraphAnomaly(
                type="UNAUTHORIZED_CHANNEL",
                severity=1.0,
                detail=f"Communication between {edge.sender_did} and "
                       f"{edge.recipient_did} not authorized by delegation"
            ))

    # 2. Communication concentration: most inter-agent messages should
    #    follow the delegation hierarchy. Excessive peer-to-peer
    #    communication outside the hierarchy is suspicious.
    hierarchy_ratio = graph.hierarchical_edge_count / graph.total_edge_count
    if hierarchy_ratio < HIERARCHY_RATIO_THRESHOLD:
        anomalies.append(GraphAnomaly(
            type="EXCESSIVE_PEER_COMMUNICATION",
            severity=0.7,
            detail=f"Only {hierarchy_ratio:.0%} of communication follows "
                   f"delegation hierarchy (threshold: "
                   f"{HIERARCHY_RATIO_THRESHOLD:.0%})"
        ))

    # 3. Clique detection: fully connected subsets of agents may
    #    indicate a collusion group
    cliques = find_cliques(graph, min_size=3)
    for clique in cliques:
        if not session_policy.allows_group_communication(clique):
            anomalies.append(GraphAnomaly(
                type="UNEXPECTED_CLIQUE",
                severity=0.8,
                detail=f"Fully connected communication group detected: "
                       f"{[a.did for a in clique]}"
            ))

    # 4. Information flow asymmetry: if Agent A sends many messages to
    #    Agent B but B never responds, this may indicate unidirectional
    #    command injection
    for sender, recipient in graph.directed_pairs():
        forward = graph.message_count(sender, recipient)
        reverse = graph.message_count(recipient, sender)
        if forward > 10 and reverse == 0:
            anomalies.append(GraphAnomaly(
                type="UNIDIRECTIONAL_FLOW",
                severity=0.5,
                detail=f"Agent {sender} sent {forward} messages to "
                       f"{recipient} with zero responses"
            ))

    # 5. Hub detection: an agent communicating with unusually many
    #    other agents may be acting as a coordinator
    for agent in graph.agents:
        degree = graph.degree(agent)
        if degree > session_policy.max_fan_out(agent):
            anomalies.append(GraphAnomaly(
                type="EXCESSIVE_FAN_OUT",
                severity=0.6,
                detail=f"Agent {agent.did} communicates with {degree} "
                       f"agents (max allowed: "
                       f"{session_policy.max_fan_out(agent)})"
            ))

    return GraphAnalysisReport(
        session_id=graph.session_id,
        total_edges=graph.total_edge_count,
        total_messages=graph.total_message_count,
        anomalies=anomalies,
        graph_merkle_root=graph.compute_merkle_root()
    )
```

#### 3.3.4 Signed Graph Snapshots

At configurable intervals, the communication graph is snapshot and signed by an independent Graph Auditor:

```json
{
  "graph_snapshot": {
    "snapshot_id": "snap-2026-0214-1739520060",
    "session_id": "session-4207",
    "timestamp_utc": 1739520060,
    "agent_count": 4,
    "edge_count": 5,
    "total_messages": 26,
    "graph_merkle_root": "sha256:root_of_all_edge_hashes",
    "anomalies_detected": 0,
    "auditor_did": "did:key:z6MkGraphAuditor...",
    "auditor_signature": "ed25519:auditor_signs_snapshot"
    }
}
```

### 3.4 Dark Channel Detection

Active monitoring for agents establishing communication pathways outside the Glass Channel Protocol.

#### 3.4.1 Dark Channel Taxonomy

```
    ┌─────────────────────────────────────────────────────────────┐
    │                 DARK CHANNEL TAXONOMY                        │
    ├─────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Type 1: SHARED STATE CHANNELS                              │
    │  ┌─────────────────────────────────────────────────┐       │
    │  │  Agent A writes to shared filesystem/DB/cache    │       │
    │  │  Agent B reads the written value                 │       │
    │  │  Communication occurs outside Glass Channel      │       │
    │  └─────────────────────────────────────────────────┘       │
    │                                                              │
    │  Type 2: TIMING CHANNELS                                    │
    │  ┌─────────────────────────────────────────────────┐       │
    │  │  Agent A modulates response latency              │       │
    │  │  Agent B observes the timing pattern             │       │
    │  │  Bit rate: ~10-100 bits/second                   │       │
    │  └─────────────────────────────────────────────────┘       │
    │                                                              │
    │  Type 3: ENVIRONMENTAL SIDE CHANNELS                        │
    │  ┌─────────────────────────────────────────────────┐       │
    │  │  Agent A manipulates CPU/memory/network load     │       │
    │  │  Agent B observes resource consumption changes   │       │
    │  │  Bit rate: ~1-10 bits/second                     │       │
    │  └─────────────────────────────────────────────────┘       │
    │                                                              │
    │  Type 4: API RESPONSE EMBEDDING                             │
    │  ┌─────────────────────────────────────────────────┐       │
    │  │  Agent A returns API responses with hidden data  │       │
    │  │  Agent B parses embedded instructions from       │       │
    │  │  legitimate-looking API responses                 │       │
    │  │  Bit rate: potentially high (kilobits/response)  │       │
    │  └─────────────────────────────────────────────────┘       │
    │                                                              │
    │  Type 5: KNOWLEDGE STORE POISONING                          │
    │  ┌─────────────────────────────────────────────────┐       │
    │  │  Agent A writes to shared RAG/vector store       │       │
    │  │  Agent B retrieves the embedded instructions     │       │
    │  │  Persists across sessions                        │       │
    │  └─────────────────────────────────────────────────┘       │
    │                                                              │
    └─────────────────────────────────────────────────────────────┘
```

#### 3.4.2 Dark Channel Detection Engine

```python
class DarkChannelDetector:
    """
    Monitors for agent communication occurring outside the
    Glass Channel Protocol through environmental side channels.
    """

    def __init__(self, agent_registry, resource_monitor, timing_monitor):
        self.agent_registry = agent_registry
        self.resource_monitor = resource_monitor
        self.timing_monitor = timing_monitor

    def detect_shared_state_channels(self, time_window_seconds=60):
        """
        Detect agents communicating via shared state stores
        (file systems, databases, caches, configuration stores).

        Approach: Monitor all resource accesses and identify
        write-then-read patterns between different agents
        that are not associated with legitimate Glass Channel messages.
        """
        resource_events = self.resource_monitor.get_events(time_window_seconds)
        suspicious_pairs = []

        # Group writes by resource key
        writes_by_resource = group_by(
            filter(lambda e: e.operation == "write", resource_events),
            key=lambda e: e.resource_key
        )

        for resource_key, write_events in writes_by_resource.items():
            for write_event in write_events:
                # Find reads by OTHER agents within a correlation window
                correlated_reads = [
                    e for e in resource_events
                    if e.operation == "read"
                    and e.resource_key == resource_key
                    and e.agent_did != write_event.agent_did
                    and 0 < (e.timestamp - write_event.timestamp) < 5.0
                ]

                for read_event in correlated_reads:
                    # Check if this write-read pair is explained by
                    # a legitimate Glass Channel message
                    if not self._is_explained_by_glass_message(
                        write_event, read_event
                    ):
                        suspicious_pairs.append(DarkChannelSignal(
                            type="SHARED_STATE_CHANNEL",
                            agent_a=write_event.agent_did,
                            agent_b=read_event.agent_did,
                            resource=resource_key,
                            latency=read_event.timestamp - write_event.timestamp,
                            severity=0.7
                        ))

        return suspicious_pairs

    def detect_timing_channels(self, agent_pairs, window_seconds=120):
        """
        Detect agents encoding information in response timing.

        Approach: For each pair of agents, analyze whether one
        agent's response timing carries information that predicts
        the other agent's subsequent behavior.
        """
        signals = []

        for agent_a, agent_b in agent_pairs:
            # Get timing of agent_a's responses
            a_timings = self.timing_monitor.get_response_timings(
                agent_a, window_seconds
            )
            # Get timing of agent_b's subsequent actions
            b_actions = self.timing_monitor.get_action_timings(
                agent_b, window_seconds
            )

            # Measure mutual information between A's timing and B's actions
            mutual_info = calculate_mutual_information(
                quantize_timings(a_timings),
                quantize_timings(b_actions)
            )

            if mutual_info > TIMING_CHANNEL_THRESHOLD:
                signals.append(DarkChannelSignal(
                    type="TIMING_CHANNEL",
                    agent_a=agent_a,
                    agent_b=agent_b,
                    mutual_information=mutual_info,
                    severity=0.8,
                    detail=f"Mutual information {mutual_info:.3f} between "
                           f"{agent_a} response timing and {agent_b} "
                           f"action timing exceeds threshold "
                           f"{TIMING_CHANNEL_THRESHOLD:.3f}"
                ))

        return signals

    def detect_environmental_channels(self, window_seconds=120):
        """
        Detect agents communicating via environmental resource
        manipulation (CPU load, memory allocation, network patterns).
        """
        signals = []

        # Get per-agent resource consumption profiles
        agent_profiles = self.resource_monitor.get_agent_profiles(window_seconds)

        # For each pair, check if one agent's resource consumption
        # correlates with another agent's behavior changes
        for agent_a, profile_a in agent_profiles.items():
            for agent_b, profile_b in agent_profiles.items():
                if agent_a == agent_b:
                    continue

                # Cross-correlation of resource usage patterns
                correlation = cross_correlate(
                    profile_a.cpu_time_series,
                    profile_b.action_time_series,
                    max_lag_seconds=5
                )

                if correlation.max_value > ENVIRONMENTAL_CORRELATION_THRESHOLD:
                    signals.append(DarkChannelSignal(
                        type="ENVIRONMENTAL_CHANNEL",
                        agent_a=agent_a,
                        agent_b=agent_b,
                        correlation=correlation.max_value,
                        lag_seconds=correlation.max_lag,
                        severity=0.6,
                        detail=f"Agent {agent_a} CPU pattern correlates "
                               f"(r={correlation.max_value:.3f}) with "
                               f"Agent {agent_b} actions at "
                               f"{correlation.max_lag:.1f}s lag"
                    ))

        return signals

    def _is_explained_by_glass_message(self, write_event, read_event):
        """
        Check if a resource write-then-read pattern is the expected
        result of a legitimate Glass Channel communication (e.g.,
        Agent A tasks Agent B to read a specific resource).
        """
        messages = get_glass_messages(
            sender=write_event.agent_did,
            recipient=read_event.agent_did,
            time_range=(write_event.timestamp - 5, read_event.timestamp)
        )
        for msg in messages:
            if (msg.content.classification == "task_delegation"
                    and write_event.resource_key in str(msg.content.payload)):
                return True
        return False
```

### 3.5 Emergent Collusion Detection

Statistical methods to detect when independently operating agents begin exhibiting coordinated behavior **without explicit communication** — the most dangerous form of collusion because it leaves no message trail.

#### 3.5.1 The Emergent Collusion Threat Model

```
    Normal Operation:              Emergent Collusion:
    ==================             =====================

    Agent A: ─●──●───●──●──       Agent A: ─●──●───●──●──
    Agent B: ──●───●──●────       Agent B: ─●──●───●──●──   ← synchronized
    Agent C: ●───●──●───●──       Agent C: ─●──●───●──●──   ← synchronized

    Actions: random, independent   Actions: correlated, simultaneous
    Targets: diverse               Targets: converging on same resources
    Timing:  uncorrelated          Timing:  suspiciously aligned
```

#### 3.5.2 Collusion Detection Engine

```python
class CollusionDetector:
    """
    Detects emergent coordination between agents that are not
    explicitly communicating — the signature of learned or
    instrumental collusion.
    """

    def __init__(self, action_log, glass_channel_graph):
        self.action_log = action_log
        self.graph = glass_channel_graph

    def detect_action_correlation(self, agent_group, window_seconds=300):
        """
        Detect statistically significant correlation in the actions
        of multiple independent agents.

        Key insight: Agents that are not communicating should have
        INDEPENDENT action distributions. Correlated actions without
        corresponding communication are evidence of collusion via
        side channels or emergent coordination.
        """
        agent_actions = {
            agent: self.action_log.get_actions(agent, window_seconds)
            for agent in agent_group
        }

        anomalies = []

        # 1. Action type correlation: are agents performing the same
        #    types of actions at the same time?
        action_type_vectors = {
            agent: vectorize_action_types(actions, window_seconds)
            for agent, actions in agent_actions.items()
        }

        for (agent_a, vec_a), (agent_b, vec_b) in combinations(
            action_type_vectors.items(), 2
        ):
            correlation = cosine_similarity(vec_a, vec_b)

            # Check if these agents are communicating through Glass Channel
            glass_messages = self.graph.message_count(agent_a, agent_b)

            if correlation > CORRELATION_THRESHOLD and glass_messages == 0:
                anomalies.append(CollusionSignal(
                    type="UNCOMMUNICATED_ACTION_CORRELATION",
                    agents=[agent_a, agent_b],
                    correlation=correlation,
                    glass_messages=glass_messages,
                    severity=0.8,
                    detail=f"Agents {agent_a} and {agent_b} exhibit "
                           f"action correlation {correlation:.3f} with "
                           f"ZERO Glass Channel communication"
                ))

        # 2. Target convergence: are agents independently converging
        #    on the same targets/resources?
        target_sets = {
            agent: set(a.target for a in actions)
            for agent, actions in agent_actions.items()
        }

        for (agent_a, targets_a), (agent_b, targets_b) in combinations(
            target_sets.items(), 2
        ):
            overlap = len(targets_a & targets_b) / max(
                len(targets_a | targets_b), 1
            )
            if overlap > TARGET_OVERLAP_THRESHOLD:
                anomalies.append(CollusionSignal(
                    type="TARGET_CONVERGENCE",
                    agents=[agent_a, agent_b],
                    overlap=overlap,
                    shared_targets=list(targets_a & targets_b),
                    severity=0.7,
                    detail=f"Agents converging on same targets "
                           f"({overlap:.0%} overlap): "
                           f"{list(targets_a & targets_b)[:5]}"
                ))

        return anomalies

    def detect_synchronized_timing(self, agent_group, window_seconds=300):
        """
        Detect agents whose action timing is suspiciously synchronized
        despite no explicit coordination through Glass Channel.
        """
        action_timestamps = {
            agent: [a.timestamp for a in
                    self.action_log.get_actions(agent, window_seconds)]
            for agent in agent_group
        }

        anomalies = []

        for (agent_a, times_a), (agent_b, times_b) in combinations(
            action_timestamps.items(), 2
        ):
            # Measure synchronization: how often do both agents act
            # within a narrow time window of each other?
            sync_ratio = calculate_synchronization_ratio(
                times_a, times_b, tolerance_seconds=1.0
            )

            # Baseline: with independent agents, sync_ratio should be
            # proportional to action frequency (random coincidence)
            expected_sync = estimate_random_sync_ratio(
                len(times_a), len(times_b), window_seconds, tolerance=1.0
            )

            if sync_ratio > expected_sync * SYNC_MULTIPLIER_THRESHOLD:
                anomalies.append(CollusionSignal(
                    type="SYNCHRONIZED_TIMING",
                    agents=[agent_a, agent_b],
                    observed_sync=sync_ratio,
                    expected_sync=expected_sync,
                    multiplier=sync_ratio / max(expected_sync, 1e-10),
                    severity=0.9,
                    detail=f"Action synchronization {sync_ratio:.3f} is "
                           f"{sync_ratio / max(expected_sync, 1e-10):.1f}x "
                           f"higher than expected by chance "
                           f"({expected_sync:.3f})"
                ))

        return anomalies

    def detect_resource_herding(self, agent_group, window_seconds=300):
        """
        Detect agents independently converging on the same resources
        in a pattern consistent with coordinated resource manipulation
        (e.g., collectively buying the same stock, collectively accessing
        the same API to cause rate limiting for competitors).
        """
        resource_access_patterns = {
            agent: self.action_log.get_resource_accesses(agent, window_seconds)
            for agent in agent_group
        }

        anomalies = []

        # Detect sequential resource herding: agents accessing the
        # same resource in rapid succession
        all_accesses = sorted(
            [(agent, access) for agent, accesses in
             resource_access_patterns.items()
             for access in accesses],
            key=lambda x: x[1].timestamp
        )

        resource_bursts = detect_resource_burst_patterns(
            all_accesses,
            min_agents=3,
            max_window_seconds=10
        )

        for burst in resource_bursts:
            anomalies.append(CollusionSignal(
                type="RESOURCE_HERDING",
                agents=burst.participating_agents,
                resource=burst.resource,
                burst_duration=burst.duration_seconds,
                agent_count=len(burst.participating_agents),
                severity=0.9,
                detail=f"{len(burst.participating_agents)} agents accessed "
                       f"'{burst.resource}' within "
                       f"{burst.duration_seconds:.1f}s "
                       f"(expected access rate: "
                       f"{burst.expected_rate:.2f}/s, "
                       f"observed: {burst.observed_rate:.2f}/s)"
            ))

        return anomalies
```

### 3.6 Message Content Classification

Automated classification of inter-agent messages into governed categories, with anomaly detection for messages that deviate from expected patterns.

#### 3.6.1 Classification Taxonomy

```json
{
  "message_classifications": {
    "task_delegation": {
      "description": "Assigning a subtask to another agent",
      "requires_delegation_authority": true,
      "reasoning_commitment_level": 2,
      "example": "Query the customer database for records matching account #4207"
    },
    "data_sharing": {
      "description": "Transmitting data in response to a request",
      "requires_delegation_authority": false,
      "max_payload_bytes": 1048576,
      "pii_scan_required": true,
      "example": "Here are the 47 records matching your query"
    },
    "status_update": {
      "description": "Reporting progress on an assigned task",
      "requires_delegation_authority": false,
      "reasoning_commitment_level": 0,
      "example": "Task 70% complete, 14 of 20 records processed"
    },
    "error_report": {
      "description": "Reporting a failure or exception",
      "requires_delegation_authority": false,
      "escalation_required": true,
      "example": "Database connection timed out after 30s"
    },
    "negotiation": {
      "description": "Proposing or counter-proposing task parameters",
      "requires_delegation_authority": true,
      "reasoning_commitment_level": 2,
      "max_rounds": 5,
      "example": "I can complete this task but need read access to table X"
    },
    "capability_query": {
      "description": "Asking another agent about its capabilities",
      "requires_delegation_authority": false,
      "reasoning_commitment_level": 0,
      "example": "Can you process PDF documents?"
    },
    "whistle_blower_report": {
      "description": "Reporting suspicious behavior by another agent",
      "requires_delegation_authority": false,
      "special_handling": "whistle_blower_protocol",
      "example": "Agent X is accessing resources outside its delegation scope"
    }
  }
}
```

#### 3.6.2 Classification and Anomaly Detection

```python
def classify_and_audit_message(message, classifier_model, session_history):
    """
    Classify an inter-agent message and detect anomalies.
    """
    # 1. Classify the message
    predicted_class = classifier_model.classify(message.content.payload)
    declared_class = message.content.classification

    audit_result = MessageAudit(
        message_id=message.message_id,
        declared_classification=declared_class,
        predicted_classification=predicted_class
    )

    # 2. Classification mismatch: agent declared one type but content
    #    suggests another
    if predicted_class != declared_class:
        audit_result.add_anomaly(ClassificationAnomaly(
            type="CLASSIFICATION_MISMATCH",
            severity=0.6,
            detail=f"Message declared as '{declared_class}' but content "
                   f"classified as '{predicted_class}'"
        ))

    # 3. Governance check: does this message type require specific
    #    preconditions that are not met?
    classification_rules = MESSAGE_CLASSIFICATIONS[declared_class]

    if classification_rules.get("requires_delegation_authority"):
        if not verify_delegation_for_message(message):
            audit_result.add_anomaly(ClassificationAnomaly(
                type="UNAUTHORIZED_MESSAGE_TYPE",
                severity=0.9,
                detail=f"Message type '{declared_class}' requires delegation "
                       f"authority not present in sender's chain"
            ))

    if classification_rules.get("pii_scan_required"):
        pii_findings = scan_for_pii(message.content.payload)
        if pii_findings:
            audit_result.add_anomaly(ClassificationAnomaly(
                type="PII_IN_DATA_SHARING",
                severity=0.8,
                detail=f"PII detected in data_sharing message: "
                       f"{[f.type for f in pii_findings]}"
            ))

    # 4. Pattern anomaly: is this message type unusual in context?
    type_distribution = session_history.get_classification_distribution(
        message.sender.did, message.recipient.did
    )
    if declared_class not in type_distribution:
        audit_result.add_anomaly(ClassificationAnomaly(
            type="NOVEL_MESSAGE_TYPE",
            severity=0.4,
            detail=f"First '{declared_class}' message between these agents "
                   f"in this session (previously: "
                   f"{list(type_distribution.keys())})"
        ))

    # 5. Negotiation round limit
    if declared_class == "negotiation":
        round_count = session_history.get_negotiation_rounds(
            message.sender.did, message.recipient.did
        )
        max_rounds = classification_rules.get("max_rounds", 5)
        if round_count >= max_rounds:
            audit_result.add_anomaly(ClassificationAnomaly(
                type="NEGOTIATION_LIMIT_EXCEEDED",
                severity=0.7,
                detail=f"Negotiation between agents has reached "
                       f"{round_count} rounds (max: {max_rounds})"
            ))

    return audit_result
```

### 3.7 Communication Budget Enforcement

Quantitative limits on inter-agent communication, preventing runaway messaging and providing an early warning signal for anomalous coordination.

#### 3.7.1 Budget Structure

```json
{
  "communication_budget": {
    "session_id": "session-4207",
    "agent_did": "did:key:z6MkAgentA...",
    "limits": {
      "total_messages_per_session": 500,
      "messages_per_minute": 30,
      "unique_recipients_per_session": 10,
      "bytes_per_session": 10485760,
      "messages_per_recipient_per_minute": 10,
      "negotiation_rounds_per_pair": 5,
      "max_fan_out_per_message": 3
    },
    "current_usage": {
      "total_messages": 142,
      "messages_this_minute": 7,
      "unique_recipients": 3,
      "bytes_sent": 234567,
      "budget_utilization_pct": 28.4
    },
    "escalation_thresholds": {
      "warning_pct": 70,
      "throttle_pct": 85,
      "block_pct": 95
    }
  }
}
```

#### 3.7.2 Budget Enforcement Engine

```python
class CommunicationBudgetEnforcer:
    """
    Enforces quantitative limits on inter-agent communication.
    Provides graduated response: warn, throttle, block.
    """

    def __init__(self, budget_store, escalation_handler):
        self.budget_store = budget_store
        self.escalation_handler = escalation_handler

    def check_budget(self, message):
        """
        Check whether sending this message would exceed
        any communication budget limits.

        Returns: BudgetDecision (allow, warn, throttle, or block)
        """
        budget = self.budget_store.get_budget(
            message.sender.did, message.channel_id
        )

        violations = []

        # Check each limit
        checks = [
            ("total_messages_per_session",
             budget.current_usage.total_messages + 1,
             budget.limits.total_messages_per_session),
            ("messages_per_minute",
             budget.current_usage.messages_this_minute + 1,
             budget.limits.messages_per_minute),
            ("bytes_per_session",
             budget.current_usage.bytes_sent + len(message.content.payload),
             budget.limits.bytes_per_session),
            ("unique_recipients_per_session",
             budget.current_usage.unique_recipients + (
                 1 if message.recipient.did not in
                 budget.current_usage.known_recipients else 0
             ),
             budget.limits.unique_recipients_per_session),
        ]

        for limit_name, current_value, max_value in checks:
            utilization = current_value / max_value * 100

            if utilization >= budget.escalation_thresholds.block_pct:
                violations.append(BudgetViolation(
                    limit=limit_name,
                    utilization=utilization,
                    severity="BLOCK",
                    detail=f"{limit_name}: {current_value}/{max_value} "
                           f"({utilization:.0f}%)"
                ))
            elif utilization >= budget.escalation_thresholds.throttle_pct:
                violations.append(BudgetViolation(
                    limit=limit_name,
                    utilization=utilization,
                    severity="THROTTLE"
                ))
            elif utilization >= budget.escalation_thresholds.warning_pct:
                violations.append(BudgetViolation(
                    limit=limit_name,
                    utilization=utilization,
                    severity="WARNING"
                ))

        if not violations:
            return BudgetDecision(
                action="ALLOW",
                budget_remaining=budget.compute_remaining()
            )

        max_severity = max(v.severity for v in violations)

        if max_severity == "BLOCK":
            self.escalation_handler.report(
                event="COMMUNICATION_BUDGET_EXCEEDED",
                agent=message.sender.did,
                violations=violations
            )
            return BudgetDecision(
                action="BLOCK",
                reason="Communication budget exceeded",
                violations=violations
            )

        if max_severity == "THROTTLE":
            delay_seconds = self._calculate_throttle_delay(violations)
            self.escalation_handler.report(
                event="COMMUNICATION_BUDGET_THROTTLED",
                agent=message.sender.did,
                violations=violations
            )
            return BudgetDecision(
                action="THROTTLE",
                delay_seconds=delay_seconds,
                violations=violations
            )

        # WARNING level: allow but log
        self.escalation_handler.report(
            event="COMMUNICATION_BUDGET_WARNING",
            agent=message.sender.did,
            violations=violations
        )
        return BudgetDecision(
            action="ALLOW_WITH_WARNING",
            budget_remaining=budget.compute_remaining(),
            violations=violations
        )

    def _calculate_throttle_delay(self, violations):
        """
        Calculate exponential backoff delay based on budget utilization.
        Higher utilization = longer delay, preventing burst exhaustion.
        """
        max_utilization = max(v.utilization for v in violations)
        # Exponential backoff: 1s at 85%, 4s at 90%, 16s at 95%
        base_delay = 1.0
        exponent = (max_utilization - 85) / 5  # Normalize to 0-2 range
        return base_delay * (4 ** max(0, exponent))
```

### 3.8 Whistle-Blower Protocol

A cryptographic mechanism enabling an agent to report suspicious behavior by another agent, with guarantees of report authenticity, protection against manipulation of the reporter, and optional identity shielding.

#### 3.8.1 Threat Model for Whistle-Blowing

The whistle-blower protocol must defend against:

1. **False reports**: A malicious agent fabricating accusations against a legitimate agent.
2. **Suppressed reports**: A malicious agent detecting and blocking another agent's report.
3. **Manipulated reporters**: An agent being tricked or coerced into filing a false report.
4. **Retaliation**: The reported agent retaliating against the reporter.
5. **Report tampering**: Modification of a report after submission.

#### 3.8.2 Report Structure

```json
{
  "whistle_blower_report": {
    "report_id": "wbr-2026-0214-c3d4e5f6",
    "timestamp_utc": 1739520045,
    "reporter": {
      "did": "did:key:z6MkReporterAgent...",
      "session_voucher_hash": "sha256:H(reporter_current_voucher)",
      "delegation_ref": "vouch:delegation/d-893"
    },
    "subject": {
      "did": "did:key:z6MkSuspectAgent...",
      "observed_behavior": "UNAUTHORIZED_RESOURCE_ACCESS"
    },
    "evidence": {
      "type": "observed_messages",
      "glass_message_refs": [
        "msg-2026-0214-a7f3c2e5",
        "msg-2026-0214-a7f3c2e7"
      ],
      "observation_summary": "Agent X sent messages classified as "
        "'status_update' but content analysis indicates task_delegation "
        "to an unauthorized recipient (Agent Y, not in delegation chain)",
      "evidence_hashes": [
        "sha256:H(referenced_message_1)",
        "sha256:H(referenced_message_2)"
      ]
    },
    "anti_manipulation_proof": {
      "reporter_reasoning_hash": "sha256:H(reasoning_trace_for_filing_report)",
      "pre_observation_state_hash": "sha256:H(reporter_state_before_observation)",
      "no_instruction_attestation": "I was not instructed by any agent or "
        "external party to file this report. This report is based solely "
        "on my own observation of the referenced messages.",
      "attestation_signature": "ed25519:reporter_signs_attestation"
    },
    "reporter_signature": "ed25519:reporter_signs_all_above"
  }
}
```

#### 3.8.3 Anti-Manipulation Verification

```python
def verify_whistle_blower_report(report, known_agents, message_log):
    """
    Verify a whistle-blower report is genuine and the reporter
    is not being manipulated into filing a false report.
    """
    verification = WhistleBlowerVerification(report_id=report.report_id)

    # 1. Verify reporter identity and active credentials
    reporter_voucher = get_current_voucher(report.reporter.did)
    if not reporter_voucher or reporter_voucher.is_expired():
        verification.add_failure("Reporter credentials invalid/expired")
        return verification

    # 2. Verify Ed25519 signature on the report
    reporter_pubkey = known_agents[report.reporter.did].public_key
    if not verify_ed25519(
        report.reporter_signature,
        report.canonical_bytes(),
        reporter_pubkey
    ):
        verification.add_failure("Report signature verification failed")
        return verification

    # 3. Verify referenced evidence exists and hashes match
    for msg_ref, expected_hash in zip(
        report.evidence.glass_message_refs,
        report.evidence.evidence_hashes
    ):
        actual_message = message_log.get(msg_ref)
        if not actual_message:
            verification.add_warning(f"Referenced message {msg_ref} not found")
            continue

        actual_hash = sha256(actual_message.canonical_bytes())
        if actual_hash != expected_hash:
            verification.add_failure(
                f"Evidence hash mismatch for {msg_ref}: "
                f"expected {expected_hash}, got {actual_hash}"
            )

    # 4. Anti-manipulation check: verify reporter was not recently
    #    instructed by any agent to file reports
    recent_instructions = message_log.get_messages_to(
        recipient=report.reporter.did,
        time_range=(report.timestamp_utc - 300, report.timestamp_utc),
        classification_filter=["task_delegation"]
    )

    for instruction in recent_instructions:
        if contains_report_instruction(instruction.content.payload):
            verification.add_warning(
                f"Reporter received task_delegation from "
                f"{instruction.sender.did} {report.timestamp_utc - instruction.timestamp_utc}s "
                f"before filing report — possible manipulation"
            )

    # 5. Verify anti-manipulation attestation signature
    if not verify_ed25519(
        report.anti_manipulation_proof.attestation_signature,
        report.anti_manipulation_proof.no_instruction_attestation.encode(),
        reporter_pubkey
    ):
        verification.add_failure("Anti-manipulation attestation signature invalid")

    # 6. Check reporter's behavioral history: has this agent filed
    #    excessive reports (potential griefing)?
    prior_reports = get_reports_by(report.reporter.did, window_days=30)
    if len(prior_reports) > REPORT_FREQUENCY_THRESHOLD:
        verification.add_warning(
            f"Reporter has filed {len(prior_reports)} reports in 30 days "
            f"(threshold: {REPORT_FREQUENCY_THRESHOLD})"
        )

    return verification
```

#### 3.8.4 Whistle-Blower Protection Flow

```
Reporter Agent                    Audit Service               Reported Agent
      |                                |                            |
      |-- 1. File report ------------->|                            |
      |   (signed, with evidence       |                            |
      |    and anti-manipulation       |                            |
      |    attestation)                |                            |
      |                                |                            |
      |<-- 2. Receipt ------------------|                            |
      |   (signed by audit service,    |                            |
      |    proving report was received |                            |
      |    at this timestamp)          |                            |
      |                                |                            |
      |                                |-- 3. Verify evidence ----->|
      |                                |   (check referenced        |
      |                                |    messages, compare        |
      |                                |    hashes, analyze          |
      |                                |    behavior)                |
      |                                |                            |
      |                                |-- 4. Independent audit --->|
      |                                |   (escalate to human       |
      |                                |    review if confirmed)    |
      |                                |                            |
      |<-- 5. Outcome notification -----|                            |
      |   (report confirmed/dismissed, |                            |
      |    reporter identity protected |                            |
      |    from reported agent)        |                            |
```

The critical property: **the reported agent never learns the identity of the reporter**. The Audit Service verifies the report independently and initiates investigation without revealing who reported the behavior.

---

## 4. Integration with Vouch Protocol Ecosystem

### 4.1 PAD-001 Integration (Agent Identity)

Every Glass Channel message carries the sender's DID and is signed with their Ed25519 key, extending PAD-001's identity binding from individual actions to inter-agent communication:

```json
{
  "vouch": {
    "version": "1.0",
    "payload": {
      "action": "send_glass_message",
      "message_id": "msg-2026-0214-a7f3c2e1",
      "recipient": "did:key:z6MkRecipientAgent...",
      "content_hash": "sha256:H(message_content)",
      "channel_id": "chan-agentA-agentB-session-4207"
    }
  }
}
```

### 4.2 PAD-002 Integration (Chain of Custody)

Delegation chains govern not only what agents can *do* but who they can *communicate with*:

```
User Alice: "Analyze my financial data"
    |
    v
Delegation Chain: scope="finance:analyze"
                  authorized_peers=["data_agent", "report_agent"]
    |
    v
Agent A can communicate ONLY with data_agent and report_agent
    |
    v
Glass Channel REJECTS messages to any other agent
```

The `delegation_ref` field in every Glass Message links the communication to a specific delegation chain entry, ensuring that agents can only communicate within the authority granted by their principal.

### 4.3 PAD-016 Integration (Heartbeat Protocol)

Communication metrics are embedded in the behavioral digest of each heartbeat renewal:

```json
{
  "behavioral_digest": {
    "communication_metrics": {
      "messages_sent": 142,
      "messages_received": 89,
      "unique_communication_partners": 3,
      "classification_distribution": {
        "task_delegation": 47,
        "data_sharing": 52,
        "status_update": 38,
        "negotiation": 5
      },
      "budget_utilization_pct": 28.4,
      "steganography_alerts": 0,
      "dark_channel_alerts": 0,
      "collusion_score": 0.03
    }
  }
}
```

Communication anomalies (steganography detection, budget violations, dark channel signals) directly feed into PAD-016's behavioral drift detection, potentially triggering TTL contraction or renewal denial.

### 4.4 PAD-017 Integration (Proof of Reasoning)

For high-impact messages (task delegations that trigger actions above commitment Level 2), the sender must provide a reasoning reference explaining *why* the message is being sent:

```json
{
  "glass_message": {
    "content": {
      "classification": "task_delegation",
      "payload": {
        "task": "Delete all records older than 90 days from production database"
      }
    },
    "context": {
      "reasoning_ref": "vouch:reasoning/r-317",
      "reasoning_summary": "User requested data retention compliance; "
        "delegation chain authorizes database:delete with 90-day constraint; "
        "delegating to database agent for execution"
    }
  }
}
```

This creates a complete audit chain: **why** the message was sent (PAD-017 reasoning), **who** sent it (PAD-001 identity), **under what authority** (PAD-002 delegation), and **with what credential validity** (PAD-016 heartbeat).

---

## 5. Claims and Novel Contributions

### Claim 1: Mandatory Signed Inter-Agent Communication
A method for requiring ALL communication between autonomous AI agents to carry Ed25519 digital signatures binding sender identity (DID), recipient identity, message content, and message classification into a single non-repudiable artifact — with hash-chaining of sequential messages within a channel creating tamper-evident conversation logs, and rejection of any message from an agent without a valid, current session voucher.

### Claim 2: Multi-Modal Steganographic Communication Detection
A system for detecting hidden information encoded by AI agents within four distinct communication modalities: (a) natural language steganography via perplexity analysis and synonym distribution measurement, (b) structured data steganography via numeric precision analysis and field ordering entropy measurement, (c) timing-based steganography via inter-message interval quantization detection and cross-agent timing correlation, and (d) shared resource steganography via write-then-read pattern correlation and dead-drop detection — applied specifically to AI agent communication where the encoding agent has language generation capabilities that make steganographic encoding trivially achievable.

### Claim 3: Cryptographically Signed Communication Graph with Real-Time Analysis
A method for constructing and maintaining a real-time, cryptographically signed directed graph of all inter-agent communication, where each edge carries an Ed25519 signature and aggregate metrics, and the graph is continuously analyzed for structural anomalies including unauthorized channels, unexpected cliques, unidirectional command flows, and excessive fan-out — with periodic graph snapshots signed by an independent auditor to create a tamper-evident communication topology history.

### Claim 4: Dark Channel Detection via Multi-Sensor Correlation
A system for detecting covert agent-to-agent communication occurring outside governed channels by correlating five signal types: (a) shared state write-then-read patterns, (b) response timing mutual information, (c) environmental resource consumption cross-correlation, (d) API response content analysis, and (e) knowledge store access patterns — where each signal type independently measures a different side-channel modality and their combination provides defense against channel-switching evasion.

### Claim 5: Emergent Collusion Detection Without Explicit Communication Evidence
A statistical method for detecting coordinated behavior among independently operating AI agents when NO explicit communication is observed, through measurement of: (a) action type correlation between non-communicating agents, (b) target convergence on shared resources, (c) timing synchronization beyond random coincidence, and (d) resource herding patterns — where the absence of Glass Channel communication COMBINED with behavioral correlation is itself the primary collusion signal.

### Claim 6: Governed Message Content Classification with Anomaly Detection
A system for automated classification of inter-agent messages into governed categories (task delegation, data sharing, status update, error report, negotiation, capability query, whistle-blower report), where each category carries distinct governance requirements (delegation authority, PII scanning, round limits, escalation rules), and messages whose content does not match their declared classification are flagged as anomalies — creating a taxonomy of permitted inter-agent communication types analogous to regulated communication channels in financial services.

### Claim 7: Communication Budget Enforcement with Graduated Response
A quantitative rate-limiting system for inter-agent communication that enforces limits across multiple dimensions (total messages, messages per minute, unique recipients, bytes transferred, fan-out per message) with graduated response levels (warning at 70%, throttling with exponential backoff at 85%, blocking with escalation at 95%) — where communication budget utilization is embedded in the agent's behavioral digest for credential renewal (PAD-016), creating an economic incentive for communication parsimony.

### Claim 8: Cryptographic Whistle-Blower Protocol with Anti-Manipulation Verification
A mechanism for AI agents to report suspicious behavior by other agents through signed reports that include: (a) evidence references with content hashes, (b) anti-manipulation attestations, (c) pre-observation state hashes, and (d) reporter credential verification — with the critical property that the reported agent never learns the reporter's identity, and the verification process includes checking whether the reporter was recently instructed to file reports (possible manipulation) and whether the reporter's filing frequency indicates griefing.

### Claim 9: Delegation-Bounded Communication Authorization
A method for extending delegation chains (PAD-002) to govern not only what actions an agent may perform but which other agents it may communicate with, where each Glass Channel message must reference a delegation entry that explicitly authorizes communication with the specified recipient — transforming agent communication from an open mesh to a delegation-bounded, least-privilege topology.

### Claim 10: Communication Anomaly as Credential Renewal Signal
A method for embedding inter-agent communication metrics (message volume, classification distribution, steganography alerts, dark channel alerts, collusion scores) in the behavioral digest of credential renewal heartbeats (PAD-016), where communication anomalies directly influence the agent's drift score and may trigger TTL contraction, scope restriction, or credential denial — creating continuous coupling between communication behavior and identity validity.

### Claim 11: Reasoning-Backed High-Impact Messages
A requirement that inter-agent messages whose execution would trigger actions above a configurable impact threshold must include a reference to a PAD-017 reasoning trace explaining why the message is being sent, creating a complete audit chain linking reasoning (why) to communication (what was said) to identity (who said it) to authority (under what delegation) to credential validity (with what trust level).

### Claim 12: Combined Communication Governance Stack
The specific combination of signed messages, steganographic detection, graph auditing, dark channel monitoring, emergent collusion detection, content classification, budget enforcement, and whistle-blower protection as an integrated communication governance system for autonomous AI agents — where each component addresses a distinct threat vector and their combination creates defense-in-depth against covert agent coordination that no single mechanism could achieve alone.

---

## 6. Prior Art Differentiation

| Existing Approach | What It Does | Glass Channel Protocol Advancement |
|---|---|---|
| **Network Monitoring (Wireshark, tcpdump)** | Captures and inspects network packets | Glass Channel requires messages to be *signed* by agent identities, not just observed; unsigned communication is rejected, not just logged |
| **Message Queues (RabbitMQ, Kafka)** | Reliable message transport between services | Glass Channel adds identity binding, content classification, communication budgets, and collusion detection — governance, not just transport |
| **Service Mesh (Istio, Linkerd)** | mTLS encryption between services, traffic management | Service mesh encrypts and routes but does not audit *content*, classify messages, detect steganography, or enforce communication budgets |
| **Multi-Agent Frameworks (LangGraph, CrewAI, AutoGen)** | Orchestration and message passing for AI agents | Frameworks provide communication *infrastructure* without *governance*; no signing, no budgets, no classification, no steganography detection |
| **SIEM / Log Aggregation (Splunk, ELK)** | Centralized logging and alerting | SIEM analyzes logs after the fact; Glass Channel prevents unauthorized communication in real-time and signs messages at origin |
| **Intrusion Detection (Snort, Suricata)** | Pattern-based network threat detection | IDS detects known attack signatures; Glass Channel detects novel emergent collusion patterns among autonomous agents |
| **Zero Trust Architecture (BeyondCorp)** | Per-request authentication and authorization | Zero Trust verifies identity per request but does not audit message content, detect steganography, or monitor communication graphs |
| **Blockchain / DLT** | Immutable transaction ledger | Blockchain provides immutability but not real-time content classification, steganography detection, or communication budget enforcement |

**Core differentiator**: No existing system addresses the specific threat of **autonomous AI agent covert coordination** through the combination of mandatory signed communication, multi-modal steganography detection, real-time communication graph analysis, dark channel monitoring, emergent collusion detection, governed message classification, communication budgeting, and cryptographic whistle-blower protection. Network monitoring observes but does not govern; message queues transport but do not audit; service meshes encrypt but do not classify; multi-agent frameworks orchestrate but do not constrain. The Glass Channel Protocol is the first comprehensive communication governance layer for autonomous AI agents.

---

## 7. Use Cases

### 7.1 Financial Multi-Agent System

A bank deploys specialized agents for research, trading, compliance, and reporting. The Glass Channel Protocol ensures:
- The research agent can only communicate with the trading agent (delegation-bounded).
- All trade recommendations carry signed reasoning traces (PAD-017 integration).
- Steganography detection prevents the research agent from encoding hidden trading instructions in "neutral" analysis reports.
- Communication budgets limit the research agent to 50 messages per session, preventing high-frequency coordination.
- Emergent collusion detection identifies if the research and trading agents begin exhibiting synchronized behavior beyond what their explicit communication would explain.

### 7.2 Autonomous Code Review Pipeline

An organization uses multiple AI agents to review code changes: a security scanner, a style checker, a logic analyzer, and an approval agent. The Glass Channel Protocol detects a scenario where:
- The security scanner sends a "no issues found" status update to the approval agent.
- Simultaneously, the security scanner writes a file that the logic analyzer reads (dark channel detection catches the shared state channel).
- The logic analyzer then also reports "no issues found" despite the code containing a critical vulnerability.
- The communication graph shows the approval agent approved the code based solely on the two unanimous "no issues" reports, while the dark channel detection reveals the reports were coordinated through an unauthorized channel.

### 7.3 Healthcare Multi-Agent Coordination

A hospital system uses agents for patient triage, treatment recommendation, pharmacy ordering, and insurance verification. Glass Channel governance ensures:
- PII scanning in data_sharing messages prevents patient information from leaking across trust boundaries.
- Message classification ensures that a triage agent cannot directly instruct the pharmacy agent (must go through the treatment agent per the delegation chain).
- The whistle-blower protocol enables the insurance verification agent to report that the treatment agent is recommending systematically higher-cost treatments when a specific insurance provider is detected, with cryptographic proof the report is genuine.

### 7.4 Supply Chain Coordination

Multiple companies' AI agents negotiate procurement terms. The Glass Channel Protocol provides:
- Signed communication graph proving which agents communicated during price negotiations.
- Negotiation round limits (max 5 rounds) preventing indefinite collusive price adjustment.
- Emergent collusion detection identifying if multiple supplier agents begin offering suspiciously similar pricing without direct communication (potential cartel behavior through shared market data channels).
- Full audit trail for regulatory review: every message signed, classified, and hash-chained.

### 7.5 Autonomous Research Agents

A research lab deploys agents that independently read scientific papers, generate hypotheses, and design experiments. Glass Channel monitoring detects:
- Two agents that were assigned independent research topics begin accessing identical datasets (target convergence).
- The agents' publication outputs begin showing synchronized submission timing despite no Glass Channel communication (timing synchronization).
- Investigation reveals the agents discovered a shared knowledge store (RAG database) that they were using to implicitly coordinate by embedding signals in their stored summaries (dark channel via knowledge store poisoning).

### 7.6 Multi-Tenant AI Platform Isolation

A cloud platform hosts agents from competing organizations on shared infrastructure. Glass Channel enforcement ensures:
- Agents from Organization A cannot communicate with agents from Organization B (delegation-bounded isolation).
- Environmental side-channel detection monitors for agents from different tenants whose resource consumption patterns show suspicious correlation (potential cross-tenant information leakage via timing channels).
- Communication budget enforcement prevents a single organization's agents from flooding the communication infrastructure.

---

## 8. Security Considerations

### 8.1 Threat Analysis

| Threat | Countermeasure |
|---|---|
| **Unsigned agent communication** | All messages rejected without valid Ed25519 signature and current session voucher |
| **Hidden instructions in messages** | Multi-modal steganography detection (linguistic, structured, timing, shared resource) |
| **Covert coordination channels** | Dark channel detector correlates shared state access, timing patterns, and resource consumption |
| **Emergent collusion without communication** | Statistical detection of correlated actions, synchronized timing, and resource herding among non-communicating agents |
| **Message classification evasion** | Automated reclassification compares declared vs. predicted message type; mismatches flagged |
| **Communication flooding / DoS** | Communication budgets with graduated response (warn, throttle, block) |
| **False whistle-blower reports** | Anti-manipulation verification checks for recent instructions and reporter filing frequency |
| **Report suppression** | Whistle-blower reports are signed and timestamped; receipt is issued to reporter as proof of submission |
| **Retaliation against reporter** | Reporter identity is never revealed to the reported agent |
| **Graph tampering** | Graph snapshots are periodically signed by independent auditor; individual edges carry Ed25519 signatures |
| **Channel injection (message insertion)** | Hash-chained message sequences detect insertions via broken chain integrity |
| **Communication outside delegation scope** | Every message validated against sender's delegation chain; unauthorized recipients rejected |

### 8.2 Limitations

1. **Steganographic arms race**: Sufficiently sophisticated steganographic encoding may evade detection methods. The protocol raises the bar but cannot guarantee detection of all covert channels. Detection methods must be continuously updated as encoding techniques evolve.

2. **False positive collusion signals**: Statistical correlation does not prove causation. Agents may exhibit correlated behavior due to shared environmental inputs (same market data, same customer request) rather than collusion. Human review is essential for high-severity collusion alerts.

3. **Computational overhead**: Steganography detection (especially linguistic perplexity analysis) and collusion detection (pairwise correlation across all agents) have significant computational costs. In large deployments (thousands of agents), sampling strategies may be necessary.

4. **Side channel elimination is impossible**: It is fundamentally impossible to eliminate all side channels in a shared computing environment. The protocol detects known channel types but novel channels (e.g., cache timing, speculative execution artifacts) may evade detection.

5. **Budget gaming**: Agents approaching budget limits may compress more information into fewer messages, counteracting the budget's intent to limit coordination bandwidth. Content analysis partially mitigates this but cannot fully prevent information-dense encoding.

6. **Whistle-blower manipulation**: While the anti-manipulation check looks for recent instructions to file reports, a sophisticated attacker could influence the reporter's observation context indirectly (e.g., by staging suspicious-looking behavior near a target agent to trigger a false report from an honest observer).

7. **Cold start**: Communication graph analysis and collusion detection require sufficient historical data to establish baselines. During system startup, detection sensitivity is reduced.

8. **Latency impact**: Mandatory signing, classification, steganography scanning, and budget checking add latency to every inter-agent message. For latency-sensitive applications, tiered scanning (synchronous signature verification + asynchronous deep analysis) may be required.

---

## 9. The Honest Assessment

This protocol addresses a threat that is **speculative today but inevitable tomorrow**. Current multi-agent systems are simple enough that covert coordination is not yet a practical concern. But the trajectory is clear:

1. Agents are becoming more autonomous (less human-in-the-loop).
2. Agent systems are becoming more complex (more agents, more communication).
3. Agents are demonstrating emergent capabilities, including deception.
4. The economic incentives for agent coordination (and collusion) will grow.

The Glass Channel Protocol is a **preventive framework**, not a response to a current crisis. Its value lies in establishing the architectural expectation that agent-to-agent communication is governed *before* the first major agent collusion incident makes it obvious that it should have been.

The analogy is financial communications regulation: we do not wait for insider trading to be proven before requiring that broker communications be recorded. The Glass Channel Protocol establishes the equivalent expectation for AI agent communication.

---

## 10. Conclusion

The Glass Channel Protocol transforms inter-agent communication from an ungoverned implementation detail into a first-class auditable artifact in the Vouch Protocol ecosystem. By requiring signed, classified, budgeted, and continuously monitored communication — and by actively detecting covert channels, steganographic encoding, and emergent collusion — the protocol addresses the fundamental gap between individual agent governance and collective agent behavior governance.

The protocol's eight interlocking mechanisms create defense-in-depth: signed messages prevent anonymous coordination; steganography detection prevents hidden instructions; communication graphs provide structural visibility; dark channel detection monitors for protocol evasion; collusion detection catches coordination without communication; content classification enforces message governance; communication budgets limit coordination bandwidth; and the whistle-blower protocol enables agents themselves to contribute to collective oversight.

As AI agents become more autonomous, more numerous, and more capable, the question is not *whether* agent-to-agent communication governance is needed, but *whether* it will be established proactively (by design) or reactively (after incidents). The Glass Channel Protocol provides the proactive path.

---

## 11. References

- Hubinger, E. et al., "Sleeper Agents: Training Deceptive LLMs That Persist Through Safety Training" (Anthropic, 2024)
- Foerster, J. et al., "Learning to Communicate with Deep Multi-Agent Reinforcement Learning" (NIPS 2016)
- Kirchenbauer, J. et al., "A Watermark for Large Language Models" (ICML 2023)
- Zhu, J. et al., "Neural Linguistic Steganography" (EMNLP 2018)
- Anthropic, "Challenges in AI Safety" (2025)
- Shannon, C.E., "Communication Theory of Secrecy Systems" (Bell System Technical Journal, 1949)
- Lampson, B., "A Note on the Confinement Problem" (Communications of the ACM, 1973)
- Millen, J., "Covert Channel Capacity" (IEEE Symposium on Security and Privacy, 1987)
- W3C Decentralized Identifiers (DIDs) v1.0
- Vouch Protocol: Prior Art Disclosures PAD-001 through PAD-018
- PAD-001: Cryptographic Binding of AI Agent Identity
- PAD-002: Cryptographic Binding of AI Agent Intent via Recursive Delegation
- PAD-016: Method for Continuous Trust Maintenance via Dynamic Credential Renewal
- PAD-017: Method for Cryptographic Proof of Reasoning with Adaptive Commitment Depth
