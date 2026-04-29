# PAD-051: Parallel Intent Extraction from LLM Prompts via a Local Shadow Small-Language-Model

**Identifier:** PAD-051
**Title:** Method for Out-of-Band Extraction of Operational Policy from Natural-Language Prompts to LLM Coding Assistants Using a Parallel Local Small Language Model with Zero Token Overhead on the Primary Assistant
**Publication Date:** April 30, 2026
**Prior Art Effective Date:** April 30, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / LLM Coding-Assistant Governance / Local-First AI / Out-of-Band Extraction / Token-Budget Engineering
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-017 (Cryptographic Proof of Reasoning), PAD-048 (Write-Only Asynchronous Context Ledger), PAD-049 (Decoupled Semantic Policy Extraction), PAD-052 (UI State Sniffing)

---

## 1. Abstract

A method for extracting operational policy declarations from natural-language prompts directed at a primary LLM coding assistant, by deploying a lightweight, local Small Language Model (SLM) that runs in parallel with the primary assistant. The SLM monitors the outbound prompt stream via a transparent local API proxy, performs Natural Language Processing (NLP) constraint extraction on the prompt text, translates extracted constraints into structured policy entries, and writes them to the ledger of PAD-048 entirely **out-of-band** with respect to the primary assistant.

The architectural keystone is **zero token overhead and zero context burden** on the primary coding assistant. The primary assistant receives the developer's prompt unmodified. It is not asked to extract rules, evaluate rules, or even acknowledge rule presence. The SLM's extraction is performed in parallel, in a separate process, on local hardware, and its output flows only to the local policy ledger, never back into the primary assistant's context window.

Key innovations:

- **Token economy: zero overhead on the primary.** Inline rule tags (as in PAD-048) and instruction-laden system prompts (as in PAD-049) consume primary-context tokens. The SLM-based extraction consumes none.
- **Local-only execution.** The SLM runs entirely on the developer's machine. No cloud round-trip, no third-party data exposure, no extra latency observable to the developer.
- **Strict translator role.** The SLM is constrained to a single function: convert free-form natural language to a structured policy schema. It does not generate code, evaluate code, or reason about the developer's task. This narrow role allows a small (sub-3B parameter) model to perform reliably.
- **Transparent proxy architecture.** The SLM sits inline on the local network path between the assistant client and its API endpoint. The primary assistant operates exactly as it would without Amnesia present.

---

## 2. Problem Statement

### 2.1 Inline tag formalism creates user-experience friction

PAD-048 requires developers to type `<r>...</r>` around any rule they want recorded. This works but introduces ceremony. Developers in flow state forget the tags, type rules in plain language ("hey, keep the algorithm name out of any push"), and lose the policy capture.

### 2.2 Asking the primary LLM to extract rules from natural language couples policy capture to LLM probability

A naive solution is to instruct the primary LLM, via a system prompt, to "watch for any policy-like instructions in user prompts and record them to the ledger." This works inconsistently for the same reasons all LLM-enforcement approaches fail under context dilution: the instruction itself decays from attention as the session grows. By turn 200, the primary LLM no longer reliably notices when the developer asserts a rule.

It also burdens every prompt in the primary's context with this meta-instruction, and uses primary-context tokens to discuss extraction at every turn.

### 2.3 Cloud-based extraction services are privacy-hostile

A third option is to send every prompt to an external policy-extraction service (a separate cloud API). This:

- Exposes the developer's prompts to a third party.
- Adds round-trip latency.
- Requires network availability.
- Introduces a new trust dependency.

For a tool whose entire purpose is to keep proprietary information local, sending all prompts to a remote service is a non-starter.

### 2.4 No prior system uses a local SLM as a parallel passive translator for policy extraction in LLM coding workflows

The combination, local SLM + transparent proxy + strict translator role + ledger output + zero primary overhead, is not deployed by any prior system.

---

## 3. Solution (The Invention)

### 3.1 Local proxy architecture

A small local HTTP proxy listens on `127.0.0.1:<port>` and forwards traffic to the configured LLM API endpoint (Anthropic Messages API, OpenAI Chat Completions API, etc.). The user configures their assistant client to point at the local proxy:

```
ANTHROPIC_API_URL=http://127.0.0.1:11434/v1
```

The proxy is a pass-through for the assistant traffic. It does not modify the request, the response, or the streaming behavior. From the assistant's perspective, the proxy is invisible.

### 3.2 Extraction tap

For each outbound request, the proxy makes a copy of the prompt content (the developer's user message, plus any new system additions) and dispatches it asynchronously to the local SLM. The forward path to the primary API is not blocked by the SLM call; the developer's interaction proceeds at full speed.

### 3.3 SLM-as-translator role

The SLM runs locally via `ollama`, `llamafile`, or similar local-inference runtime. Recommended models in the 1B to 3B parameter range (Phi-3-mini, Llama-3.2-3B, Qwen2.5-3B, Gemma-2-2B) are sufficient for the narrow task. The SLM is invoked with a fixed extraction prompt:

```
You are a constraint-extraction assistant. Read the following developer
prompt and extract any operational rules, security constraints, or
policy declarations the developer is stating. Return strict JSON only,
no prose, in this schema:

{
  "rules": [
    {
      "body": "<verbatim or paraphrased rule>",
      "scope": "workspace|file:<path>|function:<name>|global",
      "severity": "advisory|block|attest",
      "confidence": 0.0-1.0
    }
  ]
}

If no rules are stated, return {"rules": []}.

Developer prompt:
"""
<the prompt text>
"""
```

The SLM's structured output is parsed. Rules with `confidence` above a configured threshold are written to the ledger.

### 3.4 Out-of-band ledger writing

The SLM's output flows only to `.vouch/ledger/`. It does not flow back into the primary assistant's context. The primary assistant continues to perform the developer's coding task; the policy extraction happens entirely beside it, and the primary assistant remains "blissfully unaware" that policy extraction is occurring.

### 3.5 Confirmation loop (optional)

When the SLM extracts a rule with low confidence, or with a high-stakes severity (`block` or `attest`), the system can optionally surface the extracted rule to the developer via a side channel (system tray notification, a brief CLI confirmation: `Capture rule: "Never include AWS keys in pushes" [y/n]?`). The developer's confirmation flows directly to the ledger; it does not pass through the primary assistant.

This pattern preserves the zero-overhead property for the primary assistant while still giving the developer veto power over imprecise extractions.

---

## 4. Prior Art Differentiation

| System | Local execution | Parallel to primary | Strict-translator role | Token overhead on primary | Domain |
|---|---|---|---|---|---|
| Cloud LLM-based policy extractors (custom) | No | Sequential | Variable | High | Generic |
| LangChain output parsers | Yes (in-process) | No (same model invocation) | N/A | High | LLM apps |
| `ollama` + custom scripts | Yes | Possible but ad-hoc | No standard schema | Variable | Generic |
| Speech-to-intent SLMs (Rasa, Snips) | Yes | Yes | Yes | N/A | Voice assistants |
| Local DLP scanners (Symantec, Forcepoint) | Yes | Yes | No (rule-based, not NLP) | None | Enterprise data egress |
| **This disclosure** | **Yes** | **Yes** | **Yes (single function)** | **Zero** | **LLM coding assistants** |

Differentiating claims:

1. The combination of a local SLM, a transparent local proxy, a strict translator role, and an out-of-band ledger output, applied specifically to LLM coding assistant workflows for the purpose of extracting operational policy without burdening the primary assistant's context, is novel.
2. The use of a small (sub-3B) local model in a strictly narrowed translator role to compensate for the model's generic limitations, is a specific architectural choice that distinguishes this disclosure from generic cloud-LLM-based extraction.
3. The zero-overhead property on the primary assistant is achieved by the parallel-not-sequential structural placement of the SLM and is not present in prior LLM-app architectures (LangChain, Semantic Kernel, etc.) that invoke extraction sequentially within the primary's context.

---

## 5. Technical Implementation

### 5.1 Proxy reference architecture

```
Developer types in:    [Cursor / Claude Code / Aider / etc.]
                                       |
                                       v
                              [Local proxy 127.0.0.1:11434]
                              /                          \
              forward as-is /                            \ async tap
                          /                              \
                         v                                v
              [Anthropic / OpenAI API]              [Local SLM via ollama]
                                                              |
                                                              v
                                                      [.vouch/ledger/]
```

The proxy is a few hundred lines of TypeScript or Go. Streaming responses are forwarded byte-for-byte. The async tap does not block the forward path.

### 5.2 SLM selection criteria

| Property | Requirement |
|---|---|
| Parameter count | 1B-3B for low memory footprint |
| Quantization | INT4 or INT8 to fit in 4-8 GB RAM |
| Inference latency | Sub-second on a developer laptop with no GPU |
| Output format | Reliable JSON when prompted |
| License | Permissive (Apache 2.0, MIT, Llama 3.x community) |

Phi-3-mini-4k-instruct, Qwen2.5-3B-Instruct, and Llama-3.2-3B-Instruct all meet these criteria.

### 5.3 Schema validation

The SLM's output JSON is validated against a JSON Schema before any ledger write. Malformed output is logged and discarded. The system does not retry against the SLM (a malformed output is a signal that the prompt did not contain a clear rule, not a model failure).

### 5.4 Privacy properties

- All prompt content stays on the developer's machine.
- The proxy does not log prompts to disk by default.
- The SLM's invocation context is the prompt only; no project files, no environment variables, no shell history.

### 5.5 Integration with chat-tag and source-comment paths

The SLM-based extraction (this disclosure), the chat-tag declaration (PAD-048), and the source-comment declaration (PAD-049) are independent and complementary. A workspace may use any subset. Rules from all three sources land in the same `.vouch/ledger/` and are reduced by the same Compactor.

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A method for extracting operational policy from natural-language prompts to an LLM coding assistant by routing the assistant's API traffic through a local transparent proxy that asynchronously dispatches a copy of each outbound prompt to a parallel local Small Language Model performing constraint extraction.

2. A strict translator role for the local SLM, in which the SLM's output is constrained to structured JSON conforming to a fixed policy schema, and in which the SLM is not invoked for code generation, code evaluation, or any task other than constraint extraction.

3. An out-of-band ledger output path in which extracted rules flow only to a local policy ledger and never re-enter the primary LLM's context window, preserving zero token overhead and zero attention burden on the primary assistant.

4. A local-only execution model in which the SLM, the proxy, and the ledger all reside on the developer's machine, with no cloud dependency and no exposure of developer prompts to any external service.

5. A confidence-thresholded confirmation loop in which low-confidence or high-severity extractions are surfaced to the developer via a side channel for explicit confirmation, without the confirmation flowing through the primary LLM session.

6. The combination of (1) through (5), composed with the chat-tag and source-comment extraction paths of PAD-048 and PAD-049, into a unified policy capture architecture.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch
