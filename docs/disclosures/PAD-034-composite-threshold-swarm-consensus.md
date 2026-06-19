# PAD-034: Composite Threshold Aggregation for Multi-Agent Swarm Consensus

**Identifier:** PAD-034  
**Title:** Method for Bandwidth-Efficient Post-Quantum Multi-Agent Consensus via BLS Threshold Aggregation with Singular ML-DSA Representative Signatures  
**Publication Date:** April 22, 2026  
**Prior Art Effective Date:** April 22, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Post-Quantum Cryptography / Multi-Agent Systems / Threshold Signatures / Swarm Consensus / Distributed Identity  
**Author:** Ramprasad Anandam Gaddam  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-002 (Chain of Custody), PAD-022 (Swarm Limits Protocol), PAD-033 (ZK PQ Signature Compression)  

---

## 1. Abstract

A system and method for enabling autonomous multi-agent swarms to co-sign collective actions with both classical and post-quantum cryptographic assurance, while reducing the total cryptographic overhead from O(n) individual hybrid signatures to a constant-size composite token regardless of swarm size. The protocol solves the **exponential payload bloat problem** that makes naive post-quantum multi-party signing unviable over standard web protocols.

When N agents must co-authorize an action, the naive approach requires N independent ML-DSA signatures (N x 2,420-4,627 bytes). For a 100-agent swarm, this produces 242KB-462KB of signatures alone, far exceeding any practical HTTP transport limit. This disclosure introduces a two-layer aggregation architecture:

1. **Classical Layer (BLS12-381 Threshold Aggregation):** Each participating agent generates a BLS12-381 signature over the consensus payload. These N individual BLS signatures are aggregated into a single, constant-size threshold signature (96 bytes) that proves N-of-M agents participated. BLS aggregation is mathematically sound for this purpose because BLS signatures are additively homomorphic: the aggregate signature verifies against the aggregate public key.

2. **Post-Quantum Layer (Singular Representative ML-DSA):** Rather than every agent producing an individual ML-DSA signature, a single designated leader agent (or a decentralized multi-party computation protocol) generates one ML-DSA signature over the compound payload consisting of the consensus action plus the BLS aggregate. This single ML-DSA signature provides post-quantum security for the entire swarm action.

3. **Leader Election via Verifiable Random Function (VRF):** The leader is selected through a VRF-based election, ensuring the leader selection is unpredictable (preventing targeted attacks on a known leader), verifiable (any agent can confirm the election was fair), and non-manipulable (no agent can influence the outcome in their favor).

4. **Byzantine Fault Tolerance Integration:** The protocol incorporates a BFT-compatible consensus round where agents exchange signed intent commitments before generating their BLS signatures, ensuring that the aggregate signature represents genuine consensus rather than a leader fabricating participation claims.

5. **Post-Quantum Leader Rotation:** To prevent the leader's ML-DSA key from becoming a high-value target, the leader rotates every consensus round via the VRF. The ML-DSA signing burden is distributed across the swarm over time, and no single agent's compromise can provide a persistent quantum-safe signing capability.

Key innovations:
- **Total composite token size is constant regardless of swarm size:** one BLS aggregate (96 bytes) + one ML-DSA signature (2,420-4,627 bytes) + metadata. A 10-agent and a 10,000-agent swarm produce identical-size tokens.
- **No existing system** combines BLS threshold aggregation with singular ML-DSA representative signing for post-quantum swarm consensus.
- **VRF-based leader election distributes the post-quantum signing burden** across the swarm, preventing any single agent from becoming a permanent high-value target.
- **The protocol extends PAD-022 (Swarm Limits Protocol)** by adding cryptographic proof of consensus to population-governed swarm actions.

---

## 2. Problem Statement

### 2.1 Post-Quantum Signatures Scale Catastrophically in Multi-Agent Contexts

When N agents must co-sign an action with hybrid classical+PQ signatures:

| Swarm Size | Naive Hybrid Signatures (Ed25519 + ML-DSA-44) | Total Signature Payload |
|-----------|-----------------------------------------------|------------------------|
| 5 agents | 5 x (64 + 2,420) = 12,420 bytes | 12.4 KB |
| 20 agents | 20 x (64 + 2,420) = 49,680 bytes | 49.7 KB |
| 100 agents | 100 x (64 + 2,420) = 248,400 bytes | 248.4 KB |
| 1,000 agents | 1,000 x (64 + 2,420) = 2,484,000 bytes | 2.5 MB |
| 10,000 agents | 10,000 x (64 + 2,420) = 24,840,000 bytes | 24.8 MB |

A 100-agent swarm action produces nearly 250KB of signatures, making HTTP transport impractical. A 1,000-agent swarm produces 2.5MB of signatures for a single action.

### 2.2 Individual PQ Signing Is Computationally Redundant

Requiring every agent to generate an independent ML-DSA signature over the same consensus payload is computationally wasteful:

- ML-DSA-44 signing takes approximately 1.5ms per agent.
- For 1,000 agents, this is 1.5 seconds of aggregate signing time.
- The signatures are all over the same payload, proving the same thing N times with N different keys.

A single post-quantum signature proving that the consensus occurred is sufficient for quantum resistance, as long as the classical layer (BLS aggregation) cryptographically proves which specific agents participated.

### 2.3 BLS Alone Is Not Post-Quantum Secure

BLS12-381 signatures are based on elliptic curve pairings, which are vulnerable to Shor's algorithm. Using BLS aggregation alone for swarm consensus provides no post-quantum security. The classical aggregation must be paired with at least one post-quantum signature to achieve hybrid security.

### 2.4 No Existing System Addresses This

| System | Multi-Agent Signing | Signature Aggregation | Post-Quantum | Constant-Size Output |
|--------|-------------------|----------------------|-------------|---------------------|
| FROST (threshold Schnorr) | Yes | Classical only | No | Yes (single sig) |
| BLS multi-sig (Ethereum 2.0) | Yes | Classical only | No | Yes (aggregate) |
| NIST ML-DSA multi-sig | No standard | No aggregation | Yes | No |
| Dilithium threshold (research) | Research only | Not standardized | Yes | No |
| **This disclosure** | **Yes** | **BLS + singular ML-DSA** | **Yes (hybrid)** | **Yes (constant-size)** |

---

## 3. Solution (The Invention)

### 3.1 Protocol Overview

```
Phase 1: INTENT COMMITMENT (Byzantine Fault Tolerance)
  Each agent broadcasts:
    intent_commit = Sign_Ed25519(agent_did, SHA-256(consensus_payload))
  Agents collect >= 2f+1 intent commitments (BFT threshold)

Phase 2: BLS SIGNATURE GENERATION
  Each agent generates:
    bls_sig_i = Sign_BLS(agent_bls_sk, consensus_payload)
  Agent submits bls_sig_i to the swarm aggregator

Phase 3: BLS AGGREGATION
  Aggregator combines:
    bls_aggregate = bls_sig_1 * bls_sig_2 * ... * bls_sig_n
    (single 96-byte aggregate, constant-size regardless of n)

Phase 4: LEADER ELECTION (VRF)
  leader = agent whose VRF output maps to lowest hash:
    vrf_output_i = VRF_Eval(agent_vrf_sk, round_number || consensus_hash)
  All agents independently verify the election

Phase 5: POST-QUANTUM LEADER SIGNATURE
  Leader generates:
    compound_payload = consensus_payload || bls_aggregate || participation_bitmap
    ml_dsa_sig = Sign_ML-DSA(leader_mldsa_sk, compound_payload)

Phase 6: COMPOSITE TOKEN ASSEMBLY
  composite_token = {
    bls_aggregate,           // 96 bytes  (proves which agents participated)
    ml_dsa_sig,              // 2,420 bytes (provides post-quantum security)
    participation_bitmap,    // ceil(N/8) bytes (identifies participants)
    leader_did,              // ~50 bytes (identifies PQ signer)
    vrf_proof,               // ~80 bytes (proves fair leader election)
    consensus_payload_hash   // 32 bytes
  }
```

### 3.2 BLS12-381 Threshold Aggregation

**Why BLS:**
BLS (Boneh-Lynn-Shacham) signatures have a unique property: they are aggregatable. Given N individual signatures over the same message, they can be combined into a single signature that verifies against the aggregate of the corresponding public keys.

```
Individual signatures:
  sig_1 = sk_1 * H(m)
  sig_2 = sk_2 * H(m)
  ...
  sig_n = sk_n * H(m)

Aggregate signature:
  sig_agg = sig_1 + sig_2 + ... + sig_n
          = (sk_1 + sk_2 + ... + sk_n) * H(m)

Aggregate public key:
  pk_agg = pk_1 + pk_2 + ... + pk_n

Verification:
  e(sig_agg, G2) == e(H(m), pk_agg)
  where e() is the bilinear pairing on BLS12-381
```

**Properties:**
- **Constant-size output:** The aggregate signature is always 96 bytes (one G1 point), regardless of N.
- **Publicly verifiable:** Anyone with the individual public keys can compute pk_agg and verify.
- **Non-interactive:** Agents do not need to communicate with each other during signature generation; aggregation is a post-hoc operation.

### 3.3 Participation Bitmap

A compact bit vector indicating which agents contributed to the aggregate:

```
Swarm roster: [Agent_0, Agent_1, Agent_2, ..., Agent_{N-1}]
Bitmap:        [1,       1,       0,       ..., 1          ]
                ^participating     ^absent
```

Size: ceil(N/8) bytes. For a 1,000-agent swarm: 125 bytes.

The bitmap is included in the compound payload signed by the leader's ML-DSA key, binding the participation claim to the post-quantum signature. An attacker cannot alter the participation bitmap without invalidating the ML-DSA signature.

### 3.4 VRF-Based Leader Election

The leader for each consensus round is elected using a Verifiable Random Function:

```
For each agent i in the swarm:
  (vrf_output_i, vrf_proof_i) = VRF_Eval(agent_i_vrf_sk, round_nonce)

Leader = agent with the lexicographically smallest vrf_output

Verification by any party:
  VRF_Verify(agent_i_vrf_pk, round_nonce, vrf_output_i, vrf_proof_i) == true
```

**Properties:**
- **Unpredictable:** No agent can predict the leader before the round nonce is established (derived from the consensus payload hash).
- **Verifiable:** Any agent can independently verify the election by checking all VRF proofs.
- **Non-manipulable:** An agent cannot choose a favorable VRF output without possessing a different VRF secret key (which would require a different DID registration).
- **Leader rotation:** A different leader is selected for each round, distributing the ML-DSA signing burden and preventing any single agent from becoming a permanent high-value target.

### 3.5 Compound Payload Binding

The leader's ML-DSA signature covers the compound payload:

```
compound_payload = {
  consensus_action: SHA-256(original_payload),
  bls_aggregate: 96_byte_aggregate_signature,
  participation_bitmap: bitmap,
  participant_count: N,
  vrf_proof: leader_election_proof,
  round_number: monotonic_counter,
  timestamp: ISO_8601
}

ml_dsa_signature = ML-DSA.Sign(leader_mldsa_sk, compound_payload)
```

This binding ensures:
- The ML-DSA signature is over the specific consensus action (not reusable for different actions).
- The participation bitmap is cryptographically sealed (cannot be altered).
- The leader election proof is included (verifiers can confirm fair election).
- The round number prevents replay attacks (each round has a unique compound payload).

### 3.6 Composite Token Structure

```json
{
  "token_type": "vouch_swarm_consensus_v1",
  "consensus_payload_hash": "sha256:abc123...",
  "classical_layer": {
    "algorithm": "BLS12-381",
    "aggregate_signature": "base64url_96_bytes",
    "participation_bitmap": "base64url_bitmap",
    "participant_count": 47,
    "swarm_registry_hash": "sha256:def456..."
  },
  "pq_layer": {
    "algorithm": "ML-DSA-44",
    "leader_did": "did:vouch:z6MkLeader789",
    "leader_signature": "base64url_2420_bytes",
    "compound_payload_hash": "sha256:ghi789..."
  },
  "election": {
    "round_number": 1042,
    "vrf_output": "base64url_32_bytes",
    "vrf_proof": "base64url_80_bytes"
  },
  "timestamp": "2026-04-22T10:00:00Z"
}
```

**Size Analysis:**

| Component | Size |
|-----------|------|
| BLS aggregate signature | 96 bytes |
| ML-DSA-44 signature | 2,420 bytes |
| Participation bitmap (1,000 agents) | 125 bytes |
| VRF proof | 80 bytes |
| Metadata (hashes, DID, timestamp) | ~300 bytes |
| **Total** | **~3,021 bytes** |
| **Versus naive (1,000 x ML-DSA-44)** | **2,420,000 bytes** |
| **Compression factor** | **801x** |

### 3.7 Byzantine Fault Tolerance Integration

The intent commitment phase (Phase 1) ensures genuine consensus before BLS signature generation:

```
Byzantine Fault Tolerance Parameters:
  N = total swarm size
  f = maximum Byzantine agents tolerated
  Threshold = 2f + 1 (minimum honest participants for consensus)

BFT Round:
  1. Each agent broadcasts intent_commit = Sign(did, SHA-256(payload))
  2. Each agent collects intent_commits from other agents
  3. Agent proceeds to BLS signing only if >= 2f+1 intent_commits received
  4. Agent includes the set of intent_commits in its local consensus proof
```

This prevents a malicious leader from fabricating BLS aggregates without genuine swarm participation. The intent commitments serve as pre-authorization that the swarm actually agreed on the action.

### 3.8 Fallback: Leader Unavailability

If the elected leader fails to produce the ML-DSA signature within the timeout window:

```
1. Timeout expires (configurable, default 10 seconds)
2. Next VRF-ranked agent becomes the fallback leader
3. Fallback leader generates ML-DSA signature over the same compound payload
4. Process repeats through up to 3 fallback candidates
5. If all candidates fail, round is aborted and restarted with a new round nonce
```

---

## 4. Prior Art Differentiation

| System | BLS Aggregation | Post-Quantum | Hybrid Constant-Size | VRF Leader Election | BFT Integration |
|--------|----------------|-------------|---------------------|-------------------|-----------------|
| Ethereum 2.0 (beacon chain) | Yes | No | No | RANDAO (biasable) | Casper FFG |
| FROST (threshold Schnorr) | Schnorr (not BLS) | No | Yes (single sig) | No | No |
| Multi-party Dilithium (research) | No | Yes | No | No | No |
| HotStuff BFT | Ed25519 only | No | No | View-change | Yes |
| **This disclosure** | **Yes** | **Yes (ML-DSA)** | **Yes (BLS + 1 ML-DSA)** | **Yes (VRF)** | **Yes** |

Key differentiators:
1. **No existing system** combines BLS12-381 threshold aggregation with a singular ML-DSA representative signature for post-quantum hybrid swarm consensus.
2. **No existing system** uses VRF-based leader election specifically for distributing post-quantum signing burden across a multi-agent swarm.
3. **No existing system** achieves constant-size post-quantum swarm consensus tokens where the signature payload is independent of swarm size (O(1) vs. O(N)).
4. **No existing system** binds a participation bitmap to a post-quantum signature, cryptographically sealing which specific agents participated in the consensus while maintaining constant-size output.

---

## 5. Technical Implementation

### 5.1 Cryptographic Primitives

| Primitive | Purpose | Specification |
|-----------|---------|---------------|
| BLS12-381 | Threshold signature aggregation | draft-irtf-cfrg-bls-signature-05 |
| ML-DSA-44/65/87 | Post-quantum leader signature | FIPS 204 |
| Ed25519 | Intent commitment signatures | RFC 8032 |
| ECVRF (Ed25519-based) | Leader election | draft-irtf-cfrg-vrf-15 |
| SHA-256 | Payload and compound hashing | FIPS 180-4 |

### 5.2 Data Model

```
Key: swarm:{swarm_id}:roster - Set of agent DIDs in this swarm
Key: swarm:{swarm_id}:round:{n} - Hash (payload_hash, leader_did, status, timestamp)
Key: swarm:{swarm_id}:round:{n}:intents - Hash (did -> intent_commit signature)
Key: swarm:{swarm_id}:round:{n}:bls_sigs - Hash (did -> individual BLS signature)
Key: swarm:{swarm_id}:round:{n}:token - Composite consensus token JSON
Key: swarm:{swarm_id}:bls_pubkeys - Hash (did -> BLS12-381 public key)
Key: swarm:{swarm_id}:mldsa_pubkeys - Hash (did -> ML-DSA public key)
```

### 5.3 Verification Algorithm

```
Input: composite_token, swarm_roster (set of agent public keys)

Step 1: Verify participation bitmap consistency
  - Decode bitmap, count set bits, confirm == participant_count
  - Confirm all set-bit positions correspond to valid agents in swarm_roster

Step 2: Verify VRF leader election
  - VRF_Verify(leader_vrf_pk, round_nonce, vrf_output, vrf_proof)
  - Confirm leader has the lowest VRF output among roster

Step 3: Compute aggregate BLS public key
  - agg_pk = sum of BLS public keys for all agents with bit set in bitmap

Step 4: Verify BLS aggregate signature
  - BLS_Verify(agg_pk, consensus_payload_hash, bls_aggregate)

Step 5: Reconstruct compound payload
  - compound = consensus_payload_hash || bls_aggregate || bitmap || ...

Step 6: Verify ML-DSA signature
  - ML-DSA.Verify(leader_mldsa_pk, compound_payload, ml_dsa_signature)

Step 7: If all pass -> VALID swarm consensus with post-quantum assurance
```

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A composite signature scheme for multi-agent swarm consensus combining BLS12-381 threshold aggregation (proving which agents participated) with a singular ML-DSA representative signature (providing post-quantum security), where the total signature size is constant regardless of the number of participating agents.

2. A VRF-based leader election protocol for distributing post-quantum signing responsibility across swarm members, ensuring unpredictable and verifiable leader selection with automatic rotation per consensus round.

3. A compound payload binding mechanism where the leader's ML-DSA signature covers the BLS aggregate, participation bitmap, round number, and VRF proof, cryptographically sealing the complete consensus record under a single post-quantum signature.

4. A Byzantine fault tolerance integration where agents exchange Ed25519-signed intent commitments before BLS signature generation, ensuring that the BLS aggregate represents genuine consensus rather than fabricated participation.

5. A fallback leader protocol where successive VRF-ranked agents assume the ML-DSA signing role if the primary leader fails to produce a signature within a configurable timeout window.

6. A participation bitmap encoding that identifies specific swarm participants in ceil(N/8) bytes, bound to the post-quantum signature to prevent post-hoc participation claim manipulation.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch

---

## Update (April 27, 2026): JCS Canonicalization Strengthens Determinism

The Composite Threshold Swarm Consensus protocol described above pairs
threshold-aggregated classical signatures (BLS12-381) with a single
post-quantum ML-DSA signature for swarm-collective authorization. The
novel signature-aggregation mechanism is independent of the specific
serialization format of the payload being co-signed.

This update discloses that when the swarm-collective payload is
JCS-canonicalized (RFC 8785) prior to BLS aggregation and ML-DSA signing,
the threshold consensus property gains a determinism guarantee:

- Each swarm member contributing a BLS partial signature is signing a
  byte-identical canonical input. The aggregated BLS signature is
  therefore a true threshold signature over a single deterministic
  message, with no risk of serialization drift causing partial-signature
  rejection at aggregation time.
- The single ML-DSA signature produced by the swarm leader is computed
  over the same byte-identical canonical form that the BLS aggregation
  attests to, ensuring that classical and post-quantum proofs are bound
  to the same payload bytes (rather than to differently-serialized
  variants of the same logical payload).
- Independent verifiers can confirm both the BLS aggregate and the
  ML-DSA signature against the same JCS canonical form, eliminating
  serialization-mismatch failures that would otherwise undermine the
  composite property.

The originally-claimed Composite Threshold Swarm Consensus mechanism
remains the disclosed claim. JCS canonicalization is disclosed as a
strengthening implementation property that closes a serialization-drift
attack surface in multi-party threshold signature schemes for
post-quantum agent swarms.
