# PAD-045: Proof of Non-Hallucination via Cryptographic Retrieval Anchoring

**Identifier:** PAD-045
**Title:** Method for Cryptographically Proving an AI Agent's Output Was Grounded in Specific Retrieved Context, Not Hallucinated
**Publication Date:** April 29, 2026
**Prior Art Effective Date:** April 29, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / Hallucination Mitigation / Retrieval-Augmented Generation / Agent Trust / Inference-Time Provenance
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-017 (Cryptographic Proof of Reasoning), PAD-018 (Model Lineage Provenance), PAD-042 (Metadata Schema), PAD-043 (Cryptographic Weight Binding)

---

## 1. Abstract

A method for an AI agent to produce a cryptographic proof that its
output was **grounded in specific retrieved context** at inference
time, distinguishing genuinely retrieved information from
**confabulation** (hallucinated content the model invents and presents
as factual). The agent commits to the cryptographic hash of its
retrieved context **before** generation begins, signs the binding of
"retrieval root + output" together under its Vouch identity, and
submits this Retrieval-Anchored Credential alongside its action
credential.

A verifier receiving the agent's output can confirm:

1. The agent claims to have retrieved a specific corpus of source
   material (identified by its Merkle root).
2. The agent's output is bound to that corpus, not to other data the
   agent might have invented.
3. The retrieval root is reproducible: a verifier can re-fetch the
   sources and confirm the agent did not silently substitute or
   fabricate them.

The mechanism does not prevent hallucination at the model level. It
provides **cryptographic accountability** for hallucination: an agent
that hallucinates produces a credential where the output cannot be
reconciled with the retrieved context, which is detectable as a
post-fact discrepancy by any auditor.

## 2. Problem Statement

Retrieval-Augmented Generation (RAG) is the dominant pattern for
grounding AI agent outputs in factual sources. The agent is supposed
to:

1. Retrieve relevant context from a vector store, knowledge base, or
   document corpus.
2. Pass the retrieved context to the language model as part of the
   prompt.
3. Generate an output that synthesizes the retrieved context.

In practice, three failure modes arise:

- **Silent confabulation**: the model ignores the retrieval and
  invents content. Output looks factual but is fabricated.
- **Cherry-picked retrieval**: the agent retrieves results, then
  selectively cites only the supporting subset, hiding contradictory
  evidence in the corpus.
- **Substituted retrieval**: a malicious or compromised agent retrieves
  trustworthy sources but generates output as if it had retrieved
  different (forged) sources.

None of these failure modes is detectable from the output alone.
Auditors cannot distinguish a faithful RAG output from a
hallucinated one without access to the retrieval system's logs, and
even then logs can be tampered with.

What is needed is a cryptographic mechanism that binds the agent's
output to the **exact** retrieved context, makes the retrieval
content-addressed and reproducible, and lets any third party
independently verify that an agent's claim of "I retrieved X and
generated Y from X" is consistent.

## 3. The Novel Mechanism

### 3.1 Retrieval Commit Phase

Before the language model is invoked, the agent's Identity Sidecar
(PAD-003) performs a **retrieval commit**:

1. The agent's retrieval subsystem returns a list of source
   documents/chunks `[D_1, D_2, ..., D_n]`, each with a stable
   identifier (URL, document ID, or content hash) and content.
2. The Sidecar JCS-canonicalizes each `D_i` into the canonical form
   `(source_id, content_hash, retrieval_score)`.
3. The Sidecar computes a **Retrieval Merkle Root** over the
   canonical sequence: each leaf is `SHA-256(canonical(D_i))`,
   internal nodes are standard Merkle composition, the root is a
   single 32-byte digest.
4. The Sidecar emits a **Retrieval Commit Credential**: a Vouch
   Credential with `credentialSubject.retrieval_root` set to the
   Merkle root, plus `credentialSubject.source_count`,
   `credentialSubject.retrieval_query_hash`, and
   `credentialSubject.retrieval_timestamp`.

This credential is signed *before* the language model is called. The
retrieval is now cryptographically committed: any subsequent
generation must be reconcilable with the corpus committed in this
credential.

### 3.2 Generation and Output Binding

After the retrieval commit, the language model generates the agent's
output `O`. The Sidecar then issues an **Output Binding Credential**:

```json
{
  "@context": [...],
  "type": ["VerifiableCredential", "VouchCredential", "RetrievalAnchoredOutput"],
  "issuer": "did:web:agent.example.com",
  "credentialSubject": {
    "retrieval_root": "0x4c8e1f3d... (from Retrieval Commit Credential)",
    "retrieval_credential_id": "urn:uuid:...",
    "model_did": "did:weight:zM<...>",
    "output_hash": "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "output": "...the agent's actual output text or structured response...",
    "claimed_source_inclusion_proofs": [
      { "source_id": "doc:legal-precedent-1991", "merkle_path": [...], "leaf_index": 3 }
    ]
  },
  "proof": { "...eddsa-jcs-2022..." }
}
```

The Output Binding Credential cryptographically asserts:

- The output `O` was generated *after* the retrieval commit.
- The output is hash-bound to the retrieval root.
- For each claimed citation, the Merkle inclusion proof shows that
  source was actually in the retrieved corpus.
- The model that generated `O` is identified by its Weight Hash
  (PAD-043), so the output cannot be later attributed to a different
  model.

### 3.3 Verifier-Side Reconciliation

A verifier receiving the Output Binding Credential can perform
graduated checks:

**Level 1 (cryptographic, instant):**
- Verify both the Retrieval Commit and Output Binding credentials'
  Data Integrity proofs.
- Verify the Merkle inclusion proofs for claimed citations.
- Verify the agent's Vouch identity and (if PAD-043 is in use) the
  model's Weight Hash.

**Level 2 (factual, requires re-fetch):**
- Re-fetch the source documents using the published `source_id` list.
- Recompute each `SHA-256(canonical(D_i))`.
- Recompute the Merkle root.
- Confirm the recomputed root matches the credential's
  `retrieval_root`.

If Level 2 fails, the agent has fabricated retrieval (failure mode
"substituted retrieval"). Even if the agent's signatures are
cryptographically valid, the output is not grounded in the claimed
sources.

**Level 3 (semantic, requires LLM-as-judge or human review):**
- For each claim in the agent's output, verify the claim is
  consistent with the content of the cited sources.
- This is the only check that catches fully internal confabulation
  (output fabricated despite valid retrieval).

The combination produces a cryptographic accountability surface for
hallucination. An auditor armed with the Output Binding Credential
and the retrieval corpus can either confirm grounding or
mathematically prove the agent's claim of grounding is false.

### 3.4 Non-Repudiation Property

Once the Retrieval Commit Credential is signed, the agent **cannot
later claim** to have retrieved different sources. The Merkle root
in the commit cryptographically constrains every subsequent Output
Binding Credential under the same retrieval. An agent caught
hallucinating cannot retroactively swap its corpus to match its
output, because the commit is signed and timestamped.

### 3.5 Integration with Existing PADs

- **PAD-017 (Cryptographic Proof of Reasoning)**: extends naturally.
  The reasoning trace can include retrieval steps, each anchored by
  a Retrieval Commit.
- **PAD-018 (Model Lineage Provenance)**: the Output Binding
  Credential references the model's birth certificate.
- **PAD-042 (Metadata Schema)**: the retrieval root and output hash
  fit naturally into the standardized seven-field schema as optional
  fields.
- **PAD-043 (Weight Binding)**: the model_did in the output binding
  is the Weight Hash, mechanically constraining which model
  produced the output.

## 4. Embodiments

**Embodiment 1: Healthcare clinical decision support.** A clinical
RAG agent retrieves treatment guidelines and patient history,
commits, then generates a recommendation. The hospital's compliance
team can audit by re-fetching the cited guidelines, recomputing the
Merkle root, and confirming the recommendation is grounded in
verifiable sources rather than hallucinated.

**Embodiment 2: Legal research agent.** An agent retrieves case law,
commits to the Merkle root, and produces a legal memo with citation
proofs. Opposing counsel verifying the agent's work can both
cryptographically check that the cited cases existed in the
retrieval and re-read the cases to confirm semantic grounding.

**Embodiment 3: Regulatory submission preparation.** An FDA
submission agent retrieves trial data, commits, generates the
submission document. FDA reviewers receive both the document and
the Output Binding Credential, allowing post-hoc verification that
the submission is grounded in the trial data the agent claimed to
use.

**Embodiment 4: Fraud detection in fintech.** A loan-underwriting
agent retrieves credit reports and bank transactions, commits, and
generates a decision. Regulators reviewing decisions can confirm the
agent did not hallucinate financial data to justify a decision.

**Embodiment 5: Verifiable open-source security advisories.** An
automated vulnerability-research agent retrieves CVE database
entries and source code, commits, and produces an advisory. Other
security researchers can verify the advisory is grounded in real
CVE data rather than fabricated.

## 5. Non-Obviousness

Existing RAG implementations either:

- Do not record the retrieved corpus at all (no accountability).
- Log the retrieved corpus to an internal database (not externally
  verifiable, log can be tampered).
- Cite sources in the output (citations can be fabricated alongside
  the output).

The non-obvious elements are:

1. **Pre-generation cryptographic commit.** The Retrieval Commit
   Credential is signed *before* the language model is invoked,
   establishing an immutable record of what the agent claims to
   have retrieved. No prior RAG protocol does this.

2. **Merkle-rooted retrieval corpus.** The retrieval is committed
   as a Merkle root rather than a flat list, enabling per-source
   inclusion proofs in the output without requiring the verifier to
   re-fetch the entire corpus.

3. **Hash-binding of output to retrieval root.** The Output Binding
   Credential cryptographically links the generated output to the
   retrieval root, eliminating the failure mode where an agent
   retrieves source A but generates as if it had retrieved source B.

4. **Compatible with arbitrary retrieval backends.** The mechanism
   works with vector stores, full-text search, knowledge graphs, or
   any retrieval system that can produce a stable list of source
   documents.

The combination is non-obvious relative to:

- Standard RAG (no cryptographic accountability).
- LLM citation prompts (citations are model output, can be
  fabricated alongside).
- Confidence scores (probabilistic, not cryptographic).
- Watermarking output (does not bind to retrieved context).
- Reasoning chain logs (PAD-017, doesn't require retrieval-corpus
  Merkle commitment).

## 6. Disclaimer

This disclosure is published as defensive prior art under the Apache
2.0 License. It is intended to prevent assertion of patents covering
the disclosed mechanism. The author claims no exclusive rights to the
described invention. The mechanism is published openly because
hallucination accountability is foundational to AI agent trust and
must be available as a public good rather than a vendor-locked
feature.

---

*Published as prior art to ensure that retrieval-anchored
non-hallucination accountability is freely available to every AI
agent deployment, regardless of vendor.*
