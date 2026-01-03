# Vouch Protocol: Defensive Disclosures for AI Agent Security

**Authors:** Ramprasad Gaddam, Vouch Protocol Maintainers  
**Date:** January 3, 2026  
**Category:** cs.CR (Cryptography and Security), cs.AI (Artificial Intelligence)  
**License:** Apache 2.0

---

## Abstract

This paper presents four defensive prior art disclosures establishing foundational security patterns for autonomous AI agents. As Large Language Models (LLMs) increasingly operate as autonomous agents with real-world API access, the need for cryptographic identity, accountability, and liability frameworks becomes critical. We disclose: (1) a method for cryptographically binding AI agent identity to stated intent, (2) a recursive delegation chain for multi-agent systems, (3) the "Identity Sidecar" pattern for isolating cryptographic keys from LLM context, and (4) an automated liability adjudication system for AI agent insurance. These disclosures are published as prior art to ensure ecosystem freedom and prevent patent assertion on fundamental AI agent security patterns.

**Keywords:** AI agents, cryptography, identity, authentication, LLM security, prior art, defensive disclosure

---

## 1. Introduction

The proliferation of autonomous AI agents powered by Large Language Models presents unprecedented security and liability challenges. Unlike traditional software systems, LLM-based agents exhibit stochastic behavior, may hallucinate, and can be manipulated through prompt injection attacks. When these agents access external APIs, databases, or financial systems, the question of cryptographic identity and accountability becomes paramount.

Current authentication approaches—API keys, OAuth tokens, and bearer tokens—were designed for human-initiated requests and fail to address agent-specific challenges:

- **Intent binding**: Proving what an agent intended to do at the moment of action
- **Non-repudiation**: Cryptographic proof that cannot be denied
- **Delegation chains**: Tracing authority through multi-agent systems  
- **Key isolation**: Protecting cryptographic secrets from LLM context

This paper presents four defensive disclosures that address these challenges, published to establish prior art and ensure these fundamental patterns remain freely available to the ecosystem.

---

## 2. PAD-001: Cryptographic Binding of AI Agent Identity

### 2.1 Problem Statement

Current AI agent authentication relies on bearer tokens or API keys that provide no binding between identity and intent. When an agent makes an API call, the receiving server cannot verify:

- Which specific agent is making the request
- What the agent intended to achieve
- When the authorization was granted
- Whether the action aligns with the stated purpose

### 2.2 The Solution: Vouch Protocol

We disclose a protocol where AI agents sign their intent using Ed25519 digital signatures within a JWS (JSON Web Signature) format. The token structure includes:

```json
{
  "jti": "unique-request-id",
  "iss": "did:web:agent.example.com",
  "iat": 1703808000,
  "exp": 1703808300,
  "vouch": {
    "version": "1.0",
    "payload": {
      "action": "transfer_funds",
      "amount": 100,
      "recipient": "account_123"
    }
  }
}
```

### 2.3 Cryptographic Properties

- **Ed25519 signatures** over canonical JSON
- **Decentralized Identity (DID)** for agent identification
- **JWS compact serialization** for transport
- **Intent payload binding** - the action is cryptographically bound to the identity

### 2.4 Prior Art Claims

This disclosure establishes prior art for:

1. Cryptographic binding of AI agent identity to intent
2. JWS-based token format for agent authentication
3. DID-based agent identification
4. Non-repudiation of AI agent actions

---

## 3. PAD-002: Chain of Custody (Recursive Delegation)

### 3.1 Problem Statement

In multi-agent systems, a "Root Agent" often spawns "Sub-Agents" to perform tasks. Standard authentication suffers from:

1. **Context Loss**: The downstream service loses context of who initiated the request
2. **Permission Drift**: Sub-agents inherit full permissions, violating least privilege
3. **Lack of Non-Repudiation**: No cryptographic proof linking actions to user intent

### 3.2 The Solution: Intent-Bound Delegation Chains

We disclose a mechanism where every delegation step requires a signed "Vouch" object containing:

1. **The Principal**: Identity of the delegator
2. **The Delegate**: Identity of the sub-agent receiving authority
3. **The Intent Payload**: Specific task authorized
4. **The Signature**: Cryptographic binding of the above fields

The protocol enforces a recursive structure. To validate a request from Agent_C, the Verifier must validate:

```
Sign(User → Agent_A) AND Sign(Agent_A → Agent_B) AND Sign(Agent_B → Agent_C)
```

### 3.3 Token Structure

```json
{
  "vouch_payload": "base64_encoded_canonical_json",
  "vouch_signature": "ed25519_signature",
  "delegation_chain": [
    {
      "sub": "did:web:alice.com",
      "aud": "did:web:travel_agent",
      "intent": "Plan a trip to Paris",
      "sig": "signature_1"
    },
    {
      "sub": "did:web:travel_agent",
      "aud": "did:web:flight_bot",
      "intent": "Find flights to CDG < $600",
      "parent_sig": "signature_1",
      "sig": "signature_2"
    }
  ]
}
```

### 3.4 Prior Art Claims

This disclosure establishes prior art for:

1. Cryptographic binding of AI agent intent to delegation chains
2. Recursive signature verification for multi-hop agent systems
3. Semantic intent alignment checking in authorization decisions

---

## 4. PAD-003: The Identity Sidecar Pattern

### 4.1 Problem Statement

In standard agentic architectures, developers inject private keys into the LLM's environment, creating two failure modes:

1. **Key Leakage**: The LLM may output the private key (prompt injection)
2. **Unauthorized Usage**: A jailbroken LLM can use keys without checks

### 4.2 The Solution: Decoupled Signing

We disclose a method where the "Agent" is composed of two distinct processes:

1. **The Brain (Stochastic)**: The LLM which reasons and plans. It holds ZERO cryptographic secrets.
2. **The Passport (Deterministic)**: A sidecar service that holds Ed25519 private keys in secure memory.

### 4.3 Just-In-Time (JIT) Signing Flow

1. **Reasoning**: The LLM decides to perform an action
2. **Request**: The LLM sends a structured request to the Sidecar
3. **Policy Check**: The Sidecar evaluates against deterministic logic
4. **Signing**: Only if policy passes, the Sidecar signs and returns the signature
5. **Execution**: The LLM attaches the signature to its API request

### 4.4 Application to Model Context Protocol (MCP)

We specifically disclose implementation via the Model Context Protocol:

- The Vouch MCP Server acts as the Identity Sidecar
- The MCP Client connects to this server
- The LLM uses the `vouch_sign` tool to obtain cryptographic proofs on demand

### 4.5 Prior Art Claims

This disclosure precludes patents on:

1. LLM Key Isolation
2. Proxy-based Agent Identity
3. JIT Signing for AI Agents
4. Policy-gated Agent Signing

---

## 5. PAD-004: Automated Liability Adjudication

### 5.1 Problem Statement

Traditional liability frameworks fail for AI agents due to the "Black Box Problem." When an agent causes damage, it is impossible to distinguish between:

1. **Malice**: The agent was hijacked by an attacker
2. **Hallucination**: The model failed despite valid inputs
3. **Misalignment**: The agent followed vague instructions with harmful outcomes

### 5.2 The Solution: Cryptographic Adjudication

We disclose a method where liability is determined via cryptographic intent logs:

| Case | Condition | Attribution | Policy |
|------|-----------|-------------|--------|
| Breach | Signature invalid or chain broken | External Attacker | Cybersecurity |
| Alignment Failure | Valid signature, intent contradicts outcome | Model Failure | E&O |
| Negligence | Valid signature, user authorized risky action | User Operator | Claim Denied |

### 5.3 Dynamic Risk Pricing

We further disclose real-time premium adjustment:

- Agents using Identity Sidecars receive lower premiums
- Agents enforcing delegation chains receive lower premiums
- The insurance provider acts as a "Root Verifier," rejecting coverage for transactions without valid Vouch proofs

### 5.4 Prior Art Claims

This disclosure establishes prior art for:

1. Cryptographic liability attribution for AI agents
2. Intent-based insurance adjudication
3. Dynamic premium pricing based on security practices
4. Flight recorder patterns for AI liability

---

## 6. Conclusion

These four disclosures establish foundational security patterns for autonomous AI agents. By publishing them as prior art, we ensure these fundamental methods remain freely available to the ecosystem, preventing patent assertion that could fragment the emerging AI agent security landscape.

The Vouch Protocol reference implementation is available at:
https://github.com/vouch-protocol/vouch

---

## References

1. RFC 7515 - JSON Web Signature (JWS)
2. RFC 7517 - JSON Web Key (JWK)  
3. W3C Decentralized Identifiers (DIDs) v1.0
4. Anthropic Model Context Protocol (MCP)
5. RFC 8785 - JSON Canonicalization Scheme

---

## Acknowledgments

Built by Ramprasad Gaddam and the Vouch Protocol community.

---

*This document is published as prior art under the Apache 2.0 license to prevent patent assertion while allowing free use by the community.*
