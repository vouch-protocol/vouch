# PAD-003: The "Identity Sidecar" Pattern & JIT Intent Signing for AI Agents

**Publication Date:** January 03, 2026  
**Author:** Ramprasad Anandam Gaddam  
**Subject:** Decoupled Cryptographic Signing for Stochastic AI Models  
**Status:** Public Prior Art  
**License:** Apache 2.0

## 1. Abstract

This disclosure places into the public domain a security architecture for Large Language Models (LLMs) known as the "Identity Sidecar." This pattern solves the critical security risk of entrusting non-deterministic, hallucinatory models with long-lived private keys. Instead, the cryptographic identity is isolated in a deterministic "Sidecar" process (e.g., an MCP Server) that performs Just-In-Time (JIT) signing only when explicitly requested and validated against a local policy.

## 2. Problem Description

In standard agentic architectures, developers often inject API keys or private keys directly into the LLM's system prompt or environment variables. This creates two failure modes:

1. **Key Leakage:** The LLM may accidentally output the private key in its response (Prompt Injection).
2. **Unauthorized Usage:** If the LLM enters a loop or is jailbroken, it can use the keys to perform unlimited actions without checks.

## 3. The Solution: The Identity Sidecar Pattern

We disclose a method where the "Agent" is composed of two distinct processes:

1. **The Brain (Stochastic):** The LLM (e.g., Claude, GPT-4) which reasons and plans. It holds **ZERO** cryptographic secrets.
2. **The Passport (Deterministic):** A local sidecar service (e.g., Vouch MCP Server) that holds the `Ed25519` private keys in secure memory.

### Architecture Diagram

![Vouch Identity Sidecar Pattern](./PAD-003-identity-sidecar-diagram.png)

### 3.1 The "Just-In-Time" (JIT) Signing Flow

The signing process is inverted. The Agent does not "login" at the start. Instead:

1. **Reasoning:** The LLM decides it needs to perform an action (e.g., "Book Flight").
2. **Request:** The LLM sends a structured request to the Sidecar: *"Please sign this specific intent payload: {'action': 'book', 'amount': 500}."*
3. **Policy Check (The Guardrail):** The Sidecar evaluates the payload against deterministic logic (e.g., "Is amount < $1000?").
4. **Signing:** Only if the policy passes, the Sidecar signs the payload and returns the signature to the LLM.
5. **Execution:** The LLM attaches the signature to its API request.

### 3.2 Security Properties

| Property | Traditional Approach | Identity Sidecar |
|----------|---------------------|------------------|
| Key exposure to LLM | Direct access | Zero access |
| Prompt injection risk | Critical | Mitigated |
| Rate limiting | Application-level | Cryptographic |
| Audit trail | Logs only | Signed intents |

## 4. Application to Model Context Protocol (MCP)

We specifically disclose the implementation of this pattern via the **Model Context Protocol (MCP)**.

* The **Vouch MCP Server** acts as the Identity Sidecar.
* The **MCP Client** (IDE/Chatbot) connects to this server.
* The LLM uses the `vouch_sign` tool exposed by the MCP server to obtain cryptographic proofs on demand.

### 4.1 Example MCP Tool Definition

```json
{
  "name": "vouch_sign",
  "description": "Sign an intent payload with the agent's cryptographic identity",
  "inputSchema": {
    "type": "object",
    "properties": {
      "intent": {
        "type": "object",
        "description": "The action and parameters to sign"
      }
    },
    "required": ["intent"]
  }
}
```

### 4.2 Example Usage

```python
# The LLM requests a signature through the MCP tool
result = await mcp_client.call_tool(
    "vouch_sign",
    {"intent": {"action": "book_flight", "amount": 450}}
)

# The sidecar returns a signed token (or error if policy fails)
vouch_token = result.content[0].text

# LLM uses the token in API call
response = await api_client.book_flight(
    headers={"Vouch-Token": vouch_token}
)
```

## 5. Prior Art Statement

This architecture combines "Hardware Security Module (HSM)" principles with "Agent Tool Use." By applying the HSM pattern specifically to the **context window limitations and non-deterministic nature of LLMs**, we establish this as a distinct architectural standard for the AI Agent era.

### 5.1 Related Work

| Concept | Source | Differentiation |
|---------|--------|-----------------|
| HSM/TPM | Industry standard | Applies pattern to LLM context |
| Sidecar pattern | Kubernetes/Service Mesh | Applies to AI agent identity |
| MCP Tools | Anthropic | Novel use for cryptographic signing |

### 5.2 Claims Established as Prior Art

This disclosure precludes patents on:

1. "LLM Key Isolation" - Separating cryptographic keys from LLM context
2. "Proxy-based Agent Identity" - Using a proxy service for agent authentication
3. "JIT Signing for AI Agents" - On-demand cryptographic signing for agent actions
4. "Policy-gated Agent Signing" - Applying deterministic policy checks before signing

## 6. Reference Implementation

- **Repository:** https://github.com/vouch-protocol/vouch
- **MCP Integration:** `vouch/integrations/mcp/`
- **Documentation:** https://github.com/vouch-protocol/vouch#mcp-integration

---

*This document is published as prior art to prevent patent assertion on the described concepts while allowing free use by the community under the Apache 2.0 license.*
