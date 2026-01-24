# PAD-002: Cryptographic Binding of AI Agent Intent via Recursive Delegation

**Publication Date:** January 03, 2026  
**Author:** Ramprasad Anandam Gaddam  
**Status:** Public Prior Art  
**License:** Apache 2.0

## 1. Abstract

This disclosure describes a method for establishing a cryptographically verifiable "Chain of Custody" for autonomous Artificial Intelligence (AI) agents. Unlike traditional authorization systems (e.g., OAuth 2.0, RBAC) which bind static *permissions* to an identity, this system binds dynamic *intent* (reasoning/logic) to a recursive delegation chain. This ensures that every action taken by a downstream sub-agent can be traced back to a specific root user intent, enabling forensic liability and automated policy enforcement in non-deterministic systems.

## 2. Problem Statement

In multi-agent systems, a "Root Agent" often spawns "Sub-Agents" to perform tasks. Standard authentication (e.g., passing a Bearer Token) suffers from:

1. **Context Loss:** The downstream service sees the Sub-Agent's identity but loses the context of *who* initiated the request and *why*.
2. **Permission Drift:** The Sub-Agent often inherits the full permissions of the Root Agent, violating the Principle of Least Privilege.
3. **Lack of Non-Repudiation:** If an agent acts erroneously (hallucination), there is no cryptographic proof that the action was consistent with the prompt provided by the user.

## 3. The Novel Solution: Intent-Bound Delegation Chains

We disclose a protocol mechanism where every delegation step requires a signed "Vouch" object containing:

1. **The Principal:** The identity of the delegator (User/Agent).
2. **The Delegate:** The identity of the sub-agent receiving authority.
3. **The Intent Payload:** A structured or natural language description of the *specific task* authorized (e.g., "Book flight < $500", not just "Scope: Travel").
4. **The Signature:** A cryptographic signature (e.g., Ed25519) binding the above fields.

### 3.1 Recursive Structure

The protocol enforces a recursive "Russian Doll" structure. To validate a request from `Agent_C`, the Verifier must validate:

```
Sign(User -> Agent_A) AND Sign(Agent_A -> Agent_B) AND Sign(Agent_B -> Agent_C)
```

If any link in the chain fails to validate, or if the *Intent Payload* at any step contradicts the final action (checked via semantic validation or logic policy), the request is rejected.

### 3.2 Visual Flow

```
User Alice --delegates--> Agent A --delegates--> Agent B --calls--> Database
    │                         │                      │
    └─ "Analyze my data"      └─ "Query tables"     └─ "SELECT * FROM users"
```

## 4. Prior Art Acknowledgement & Differentiation

We acknowledge foundational work in capability-based security:

* **Macaroons (2014):** Introduced "Cookies with Contextual Caveats" using chained HMACs.
* **Biscuits (2019):** Introduced public-key based offline delegation with Datalog caveats.
* **SPIFFE/SPIRE:** Workload identity for service-to-service authentication.

**Differentiation:**

This disclosure specifically applies these chaining mechanisms to **Non-Deterministic AI Workloads**. It introduces the concept of binding **Probabilistic Intent** (e.g., LLM prompts, embeddings, or confidence scores) into the cryptographic chain, allowing policy engines to make authorization decisions based on *semantic alignment* rather than just static claims.

## 5. Technical Implementation

### 5.1 Token Structure

```json
{
  "vouch_payload": "base64_encoded_canonical_json",
  "vouch_signature": "ed25519_signature",
  "delegation_chain": [
    {
      "sub": "did:web:alice.com",
      "aud": "did:web:travel_agent",
      "intent": "Plan a trip to Paris",
      "iat": 1704268800,
      "sig": "signature_1"
    },
    {
      "sub": "did:web:travel_agent",
      "aud": "did:web:flight_bot",
      "intent": "Find flights to CDG < $600",
      "iat": 1704268810,
      "parent_sig": "signature_1",
      "sig": "signature_2"
    }
  ]
}
```

### 5.2 Verification Algorithm

```python
def verify_chain(token, trusted_roots):
    # 1. Verify outermost signature
    if not verify_signature(token.vouch_signature, token.vouch_payload):
        return False
    
    # 2. Walk chain backwards
    for i in range(len(token.delegation_chain) - 1, 0, -1):
        current = token.delegation_chain[i]
        parent = token.delegation_chain[i - 1]
        
        # Verify current signed by parent
        if not verify_signature(current.sig, current, parent.public_key):
            return False
        
        # Optional: Check intent alignment
        if not is_intent_aligned(parent.intent, current.intent):
            return False
    
    # 3. Verify root is trusted
    root = token.delegation_chain[0]
    return root.sub in trusted_roots
```

## 6. Claims

This disclosure establishes prior art for:

1. Cryptographic binding of AI agent intent to delegation chains
2. Recursive signature verification for multi-hop agent systems
3. Semantic intent alignment checking in authorization decisions
4. Non-repudiation of AI agent actions through signed intent chains

## 7. Reference Implementation

- **Repository:** https://github.com/vouch-protocol/vouch
- **Related Discussion:** https://github.com/vouch-protocol/vouch/discussions/17
- **Implementation Issue:** https://github.com/vouch-protocol/vouch/issues/18

---

*This document is published as prior art to prevent patent assertion on the described concepts while allowing free use by the community under the Apache 2.0 license.*
