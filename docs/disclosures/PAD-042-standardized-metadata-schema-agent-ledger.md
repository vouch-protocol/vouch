# PAD-042: Standardized Metadata Schema for AI Agent Ledger Signatures

**Identifier:** PAD-042  
**Title:** Open Specification for Verifiable AI Agent Execution Payloads and Cryptographic Attestations  
**Publication Date:** April 29, 2026  
**Prior Art Effective Date:** April 29, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Verifiable Credentials / Agent Logging / Audit / Interoperability / Forensic Reconstruction  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-016 (Dynamic Credential Renewal), PAD-017 (Cryptographic Proof of Reasoning), PAD-018 (Model Lineage Provenance), PAD-039 (JCS Multi-Party Trust State)  

---

## 1. Abstract

This publication defines an open, standardized JSON / W3C Verifiable
Credential data schema for recording autonomous Artificial Intelligence
(AI) agent actions onto immutable cryptographic ledgers. The schema
establishes mandatory and optional metadata fields required to maintain
a forensic, auditable chain-of-thought for machine-executed
transactions. The schema is intended to be cryptographically signed via
a Data Integrity proof (`eddsa-jcs-2022` or
`hybrid-eddsa-mldsa44-jcs-2026`) prior to ledger submission, producing a
machine-verifiable record that any independent auditor can reconstruct.

## 2. Background

The proliferation of autonomous agents has created fragmentation in how
machine actions are logged. Different developer frameworks (LangChain,
CrewAI, AutoGPT, AutoGen, the Model Context Protocol, Vertex AI, Google
ADK, custom orchestrators) each emit logs in their own structure. A
log entry from one framework cannot be cross-referenced with a log
entry from another without ad-hoc translation. This makes
cross-platform auditing impossible, prevents cross-platform compliance
tracing, and makes liability assignment ambiguous in incident
investigations.

An open standard schema is required to ensure interoperability across
the "Agentic Web." The schema must be cryptographically verifiable so
that auditors examining a ledger entry can confirm:

- Which specific agent performed the action.
- Which model and configuration generated the action.
- Which prompt was governing the agent at the time.
- Which human authorization permitted the action.
- Which tools or APIs the agent invoked.
- Exactly when the action was committed.

Without this standard, organizations operating agents in regulated
environments (banking, healthcare, insurance, capital markets) cannot
meet auditability obligations imposed by SR 11-7, FFIEC AI guidance,
HIPAA, NAIC AI Bulletin, MiFID II, EU AI Act, or 21 CFR Part 11.

## 3. Detailed Description: The Schema

### 3.1 Mandatory Fields

To achieve verifiable machine execution, an agent's signed payload
MUST adhere to the following schema structure prior to ledger
submission. The fields are encoded as a JSON object that becomes the
`credentialSubject.execution` field of a Verifiable Credential, or
equivalently the JWS payload `vouch.execution` field for the legacy
v0.x form.

| Field | Type | Description |
|---|---|---|
| `agent_did` | DID URI | The Decentralized Identifier of the executing machine (e.g., `did:web:agent.example.com`). Resolves to a DID Document containing the verification method that signed this execution record. |
| `model_version` | String | The specific LLM or model utilized, including its version identifier (e.g., `gpt-4-0613`, `claude-3-5-sonnet-20241022`, `gemini-1.5-pro-002`). MUST identify the exact model build, not just a family name. |
| `system_prompt_hash` | Hex string | A SHA-256 hash of the governing system prompt guiding the agent during this execution step. The hash binds the prompt at signing time without disclosing its contents on the ledger. |
| `temperature_setting` | Float [0.0, 2.0] | The algorithmic randomness setting used during generation. Required for deterministic-vs-stochastic behavior reconstruction. |
| `delegation_reference` | URI / hash | A pointer to the human-signed token authorizing the action. Either a URN identifying a delegation credential in the chain, or a SHA-256 hash of the parent credential. |
| `tool_call_array` | Array of objects | An ordered array detailing specific APIs or tools invoked during this execution step. Each entry MUST include `tool_id`, `arguments_hash`, and `result_hash`. |
| `execution_timestamp` | Unix epoch (integer, milliseconds) | The precise timestamp of the cryptographic signature. Required for temporal ordering and replay detection. |

### 3.2 Optional Fields

The following fields strengthen the audit record and SHOULD be
included where applicable:

| Field | Type | Description |
|---|---|---|
| `model_provider` | String | The vendor or hosting environment (e.g., `openai`, `anthropic`, `google-vertex`, `local-llamafile`). |
| `inference_runtime_version` | String | The version of the inference runtime (e.g., `vllm-0.6.2`, `tgi-2.4.0`, `local-ollama-0.4.0`). |
| `top_p` | Float | Nucleus sampling parameter, when applicable. |
| `seed` | Integer | The random seed if the run was seeded for reproducibility. |
| `reasoning_steps_hash` | Hex string | SHA-256 of the chain-of-thought reasoning trace, when available (PAD-017). |
| `policy_check_passed` | Boolean | Whether the agent's local policy engine accepted the action prior to signing (Identity Sidecar pattern, PAD-003). |
| `parent_execution_id` | URN | The credential ID of the immediately preceding execution step in a multi-step workflow. |
| `swarm_consensus_root` | Hex string | When the action requires multi-agent consensus, the Merkle root of the swarm's BLS aggregate (PAD-034). |

### 3.3 Example Encoded as a Vouch Credential

```json
{
 "@context": [
  "https://www.w3.org/ns/credentials/v2",
  "https://vouch-protocol.com/contexts/v1"
 ],
 "id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
 "type": ["VerifiableCredential", "VouchCredential", "AgentExecutionCredential"],
 "issuer": "did:web:agent.example.com",
 "validFrom": "2026-04-29T10:00:00Z",
 "validUntil": "2026-04-29T10:05:00Z",
 "credentialSubject": {
  "id": "did:web:agent.example.com",
  "vouchVersion": "1.0",
  "intent": {
   "action": "submit_clinical_finding",
   "target": "trial:NCT00000001",
   "resource": "https://fda-submissions.example.com/api/findings"
  },
  "execution": {
   "agent_did": "did:web:agent.example.com",
   "model_version": "claude-3-5-sonnet-20241022",
   "system_prompt_hash": "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
   "temperature_setting": 0.2,
   "delegation_reference": "urn:uuid:8a7e4f2c-1234-4abc-9def-0123456789ab",
   "tool_call_array": [
    {
     "tool_id": "fda-api.submit_finding",
     "arguments_hash": "0x4c8e1f3d...",
     "result_hash": "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
   ],
   "execution_timestamp": 1746090000000,
   "policy_check_passed": true
  }
 },
 "proof": {
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-jcs-2022",
  "created": "2026-04-29T10:00:00Z",
  "verificationMethod": "did:web:agent.example.com#key-1",
  "proofPurpose": "assertionMethod",
  "proofValue": "z3FXQjecWufY46..."
 }
}
```

### 3.4 Forensic Reconstruction Property

By standardizing these fields, auditors can perfectly reconstruct the
state of the agent at the exact moment a transaction occurred:

- The `agent_did` resolves to the DID Document, which yields the
 agent's public verification method and the controller of the agent.
- The `model_version` identifies the exact model and build, allowing
 auditors to consult model documentation for known capabilities,
 failure modes, and CVE history.
- The `system_prompt_hash` binds the operating instructions
 cryptographically. If the auditor has access to the prompt under
 legal process, they can confirm it matches the hash.
- The `temperature_setting` and optional `seed` jointly indicate
 whether the run was reproducible.
- The `delegation_reference` chains to the authorizing principal.
- The `tool_call_array` enumerates side effects with hashed inputs and
 outputs, enabling tamper detection on tool inputs and outputs.
- The `execution_timestamp` orders this record relative to other
 records on the ledger and against external evidence.

When the record is committed to an immutable cryptographic ledger
(content-addressed object store, blockchain, transparency log, or
write-once audit database), the combination of the schema and the
Data Integrity proof yields a record that any independent party
can verify without trusting the agent's operator.

## 4. The Novel Mechanism

The non-obvious element is the deliberate selection of these specific
seven mandatory fields as the minimum sufficient set for forensic
reconstruction of an AI agent action. Prior agent logging schemes
typically include either:

- Less (just identity + action), losing model, prompt, and tool
 context.
- More (full prompts, full responses, full reasoning traces),
 defeating compactness and creating privacy risk.

The seven mandatory fields are chosen to be:

1. **Sufficient**: every regulatory question about an agent action is
  answerable from the seven fields plus the corresponding DID
  Document, the original system prompt (held under access control),
  and the parent delegation credential.

2. **Privacy-preserving by hash**: prompt content and tool I/O are
  bound by hash, not transcribed verbatim, so the ledger entry does
  not leak proprietary prompts or PII.

3. **Hashable into a fixed-size canonical form** via JCS (PAD-039),
  enabling deterministic ledger anchoring and Merkle inclusion.

4. **Cross-framework**: the same seven fields apply to LangChain
  agents, MCP agents, AutoGPT agents, and custom orchestrators,
  enabling a common audit substrate.

## 5. Embodiments

**Embodiment 1: VC + Data Integrity ledger entry.** The schema
appears as `credentialSubject.execution` in a Vouch Credential signed
with `eddsa-jcs-2022`. Implementations in Python, TypeScript, and Go
(per PAD-039 cross-implementation interop) all canonicalize identically
and produce byte-identical SHA-256 anchors.

**Embodiment 2: JWS Compact ledger entry (legacy).** The schema appears
as the `vouch.execution` field of a JWT, signed Ed25519. Provided for
backward compatibility with v0.x deployments.

**Embodiment 3: Hybrid post-quantum ledger entry.** The schema is
signed under `hybrid-eddsa-mldsa44-jcs-2026` for regulated long-term
records (insurance contracts, clinical trial submissions, capital
markets transactions) where the ledger must remain verifiable through
post-quantum migration.

**Embodiment 4: Streaming append-only audit log.** Each agent action
emits a schema-conforming credential. A daemon batches credentials
into a Merkle tree, anchors the root onto a transparency log
(Sigstore Rekor, OpenTimestamps, or a private append-only store), and
publishes the inclusion proofs alongside the credentials. Auditors
verify both the Data Integrity proof on each entry and the Merkle
inclusion against the published root.

**Embodiment 5: Cross-framework adapter.** A LangChain callback
handler, a MCP server intercept, an AutoGPT command hook, and an
AutoGen tool wrapper all emit schema-conforming credentials regardless
of the underlying agent framework. Auditors using a single tool can
verify records produced by any of the frameworks.

## 6. Non-Obviousness

Existing agent logging conventions are framework-specific (each
framework emits its own structure) and either too sparse or too
verbose for forensic use. The non-obvious element is the deliberate
seven-field minimum that provides forensic completeness while
remaining hash-anchorable on a public ledger without privacy leakage.
Combined with the Data Integrity proof attached to the schema and
the JCS canonicalization that allows the schema to be rendered to
byte-identical canonical form across implementations, the combination
is non-obvious relative to either:

- Plain JSON logs (no cryptographic guarantees).
- Verbose audit transcripts (too large for ledger anchoring, leak
 prompt and PII content).
- Framework-specific schemas (no cross-framework interop).

The seven-field specification is itself the novel claim, the
cryptographic envelope and the canonicalization are disclosed
separately in PAD-001, PAD-039, and PAD-040.

## 7. Disclaimer

This disclosure is published as defensive prior art under the Apache
2.0 License. It is intended to prevent assertion of patents covering
the disclosed mechanism. The author claims no exclusive rights to the
described invention.

---

*Published as prior art to ensure ecosystem freedom for cross-framework
AI agent action logging and ledger anchoring.*
