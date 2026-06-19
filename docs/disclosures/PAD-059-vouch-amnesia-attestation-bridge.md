# PAD-059: Vouch-Amnesia Attestation Bridge for Deterministic Pre-Push Policy Decisions

**Identifier:** PAD-059  
**Title:** Method for Cryptographically Anchoring Deterministic Pre-Push Policy Decisions of an AI Coding Assistant Workspace to W3C Verifiable Credentials with Optional Hybrid Post-Quantum Signatures  
**Publication Date:** May 14, 2026  
**Prior Art Effective Date:** May 14, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Safety / LLM Coding-Assistant Governance / Cryptographic Audit Trail / Cross-Project Composition / Post-Quantum-Ready Audit Logs  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-039 (JCS Deterministic Multi-Party Trust State), PAD-040 (Hybrid Composite Signature Same Canonical Bytes), PAD-041 (Multikey Algorithm-Agnostic Verification), PAD-048 (Write-Only Asynchronous Context Ledger), PAD-049 (Decoupled Semantic Policy Extraction), PAD-050 (Zero-Context Deterministic Egress Interception), PAD-053 (Time-Bounded Ephemeral Rules), PAD-055 (Cross-Session Policy Re-Anchoring)  

---

## 1. Abstract

A method for cryptographically anchoring the policy decisions of a deterministic egress-time policy evaluator, of the kind described in PAD-048 through PAD-055 for AI coding assistant workspaces, to W3C Verifiable Credentials secured with W3C Data Integrity proofs. The bridge composes two independently-novel systems:

- **The deterministic policy side:** a workspace ledger, a compactor daemon, a consolidated `.vouchpolicy` artifact, and a pre-push git hook that produces a structured `EgressDecision` object (block / attest / allow) at the moment of code egress.
- **The cryptographic identity side:** a Decentralized Identifier (DID) controlled by the developer's machine or organization, used to sign a W3C Verifiable Credential whose `credentialSubject.intent` field binds the egress decision to the specific commit range, the active policy snapshot, the resource being pushed, and (optionally) the chain of human delegators who authorized the developer.

The resulting Verifiable Credential is a non-repudiable, byte-deterministic, third-party-verifiable record that the developer machine performed a specific deterministic policy evaluation against a specific code diff at a specific moment, and that the result was the recorded one. The bridge supports the dual-proof post-quantum profile (one `eddsa-jcs-2022` proof plus one `mldsa44-jcs-2026` proof, both over the same JCS-canonicalized credential bytes; see PAD-040 §3.3a) so that audit credentials produced today remain verifiable against future post-quantum adversaries without re-signing or re-issuance.

Key innovations of the bridge:

- **Composition pattern: sign the policy engine's decisions, not just events.** Existing systems sign source events (commits, build artifacts, deployment events). The bridge signs the *decision* of a deterministic evaluator over those events, which captures both the input (commit range + policy snapshot) and the conclusion (block / attest / allow) in a single cryptographic envelope.
- **Policy-snapshot binding.** The Verifiable Credential includes a content-addressed hash of the active `.vouchpolicy` file at decision time. Later attempts to argue that the rule set was different at the moment of decision are cryptographically refuted by the hash.
- **Asynchronous attestation.** The pre-push git hook need not wait for signing to complete. The hook produces the decision synchronously (block / attest / allow), and the signing process produces the credential asynchronously, posting it to a local or remote audit log. The push is not delayed.
- **Post-quantum-ready audit logs.** The hybrid cryptosuite ensures that audit credentials produced today remain verifiable even after large-scale quantum computers exist. This is uniquely important for audit credentials, which may be retained for years (regulatory record-retention periods of 7+ years are common).
- **Optional, non-invasive integration.** Amnesia operates fully without Vouch. Vouch operates fully without Amnesia. The bridge is opt-in via configuration. Disabling the bridge does not change Amnesia's enforcement behavior.

---

## 2. Problem Statement

### 2.1 Plain-text policy logs are inadmissible as cryptographic evidence

Existing egress-time policy enforcers (pre-commit hooks, pre-push hooks, secret scanners, license compliance checkers, custom CI gates) produce plain-text logs of their decisions. In a regulatory or litigation context where the question is "did the developer's machine actually enforce the documented policy at the moment of egress, or was the log fabricated later?", a plain-text log is weak evidence:

- The log file is editable after the fact by the same actor whose behavior is in question.
- The log does not bind to the specific commit range that was being evaluated.
- The log does not bind to the specific policy snapshot that was active.
- The log has no signature by any identifiable entity.
- The log cannot be independently verified by a third party without trusting the integrity of the developer's local filesystem.

For internal-only deployments this is acceptable. For deployments in regulated industries (finance, healthcare, government contracting) where audit trails must withstand adversarial scrutiny, plain-text logs do not meet the evidentiary bar.

### 2.2 Cryptographic signing of source events does not capture the policy decision

The well-known practice of signing source events (signed git commits, signed build artifacts, signed deployment manifests) proves "this commit was authored by this key" or "this build was produced by this key." It does not prove "the developer machine ran a deterministic policy evaluator over this commit range and the evaluator's decision was X." A signed commit is consistent with any policy decision having been reached, including one that violates the documented rules.

The gap is structural: signing the *input* to a policy engine does not encode anything about the engine's *output*. An auditor receiving a signed commit cannot tell whether the developer's pre-push policy passed cleanly or whether the developer bypassed the policy and pushed anyway.

### 2.3 Signing the policy engine's output binds the input, the engine, and the conclusion together

What is required is a single cryptographic envelope that says:

> At time T, against policy snapshot P (identified by content hash), the deterministic evaluator E (identified by version and content hash of the evaluator binary) evaluated commit range C (identified by the SHAs of the pushed commits) and reached decision D (one of block / attest / allow). This envelope is signed by DID K (the developer's identity).

The envelope must be:

- Byte-deterministic (so an auditor regenerating it from the same inputs gets identical bytes).
- Third-party verifiable (no shared infrastructure required between the developer and the auditor).
- Cryptographically agile (so the signature scheme can be migrated as the post-quantum landscape evolves, without re-issuing or re-signing prior credentials).
- Standards-aligned (so existing W3C VC tooling can consume the audit trail).

No prior system combines these properties for the specific case of deterministic pre-push policy decisions in AI coding assistant workspaces.

### 2.4 Existing W3C VC and Data Integrity tooling does not, by itself, solve the problem

W3C Verifiable Credentials and Data Integrity proofs are general-purpose primitives. They define how to sign a JSON document and how to verify it. They do not define:

- What the `credentialSubject` should look like for a policy-engine-decision attestation.
- How to bind the policy snapshot deterministically to the credential.
- How to compose with a pre-push git hook in a way that does not slow the developer's workflow.
- How to handle the post-quantum migration without invalidating existing audit credentials.

The novelty of this disclosure is not in the W3C primitives. The novelty is in their specific composition with the deterministic policy evaluator of PAD-048 through PAD-055, producing an audit credential with the four properties above.

### 2.5 Hybrid post-quantum signatures matter especially for audit credentials

Many use cases for cryptographic signatures (ephemeral session tokens, short-lived API authentication) tolerate near-term cryptographic agility because the signed artifact has a short validity window. Audit credentials are different. Audit credentials are retained for years (sometimes a decade or more) and must remain verifiable for the entire retention period.

A classical Ed25519 signature produced today is at risk of being broken by a sufficiently large quantum computer within the retention window. An audit credential whose signature can be retroactively forged is worse than no audit credential: it produces a false sense of evidentiary strength while the underlying record is repudiable.

The dual-proof post-quantum profile (Ed25519 alongside ML-DSA-44, expressed as two independent W3C Data Integrity proofs over the same JCS-canonicalized credential bytes; PAD-040 §3.3a) addresses this directly: each proof can be verified independently, and as classical Ed25519 weakens over time, the ML-DSA-44 proof remains valid and the credential continues to verify under any verifier policy that admits the post-quantum proof.

---

## 3. Solution (The Invention)

### 3.1 The bridge architecture

```
   Developer machine
   ─────────────────────────────────────────────────────────────
   <r>...</r>  ──▶  .vouch/ledger/rule_*.json    (PAD-048)
                          │
                          ▼
                    Synapse Compactor
                          │
                          ▼
                  .vouchpolicy  (deterministic)
                          │
   git push  ──▶  pre-push hook  ──▶  Cortex Evaluator
                                          │
                                          ▼
                                  EgressDecision
                                  { decision, commits, policy_hash,
                                    evaluator_version, ledger_rule_ids,
                                    timestamp }
                                          │
                                          ▼                ◄─── DID key
                              Vouch Signer (this PAD)
                                          │
                                          ▼
                          W3C Verifiable Credential
                          { @context, type, issuer (DID),
                            credentialSubject (EgressDecision),
                            proof: [ eddsa-jcs-2022 proof,
                                    (optional) mldsa44-jcs-2026 proof ] }
                                          │
                                          ▼
                              local audit log  ─▶  optional remote sink
```

### 3.2 The `EgressDecision` object

The deterministic evaluator produces a JSON object with the following fields:

```json
{
  "type": "AmnesiaEgressDecision",
  "decision": "block" | "attest" | "allow",
  "evaluated_at": "<ISO-8601 UTC>",
  "evaluator_version": "<semver>",
  "evaluator_binary_hash": "sha256-<hex>",
  "policy_snapshot_hash": "sha256-<hex of canonical .vouchpolicy bytes>",
  "active_rule_ids": ["rule_1714400111000_a8f3d1b2", ...],
  "commit_range": {
    "remote": "origin",
    "branch": "main",
    "from": "<sha of remote HEAD>",
    "to": "<sha of local HEAD>",
    "commits": ["<sha1>", "<sha2>", ...]
  },
  "matched_rules": [
    { "rule_id": "...", "severity": "block" | "attest" | "advisory",
      "matched_files": ["..."], "matched_evidence": "<short string>" }
  ],
  "human_override": null | {
    "override_id": "<uuid>",
    "approved_by_did": "<DID of human approver>",
    "approved_at": "<ISO-8601 UTC>",
    "approval_signature_credential_id": "<URN of the override credential>"
  }
}
```

The object is canonicalized via RFC 8785 JCS (PAD-039) to produce a byte-deterministic representation.

### 3.3 Embedding the decision into a Verifiable Credential

The signer wraps the `EgressDecision` as the `credentialSubject.intent` field of a W3C Verifiable Credential with the standard VC 2.0 shape:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://vouch-protocol.com/contexts/v1"
  ],
  "type": ["VerifiableCredential", "AmnesiaEgressDecisionCredential"],
  "issuer": "did:web:dev-machine-alice.example.com",
  "validFrom": "2026-05-14T03:42:11Z",
  "validUntil": "2036-05-14T03:42:11Z",
  "credentialSubject": {
    "id": "did:web:dev-machine-alice.example.com",
    "intent": { /* the EgressDecision object above */ }
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2026-05-14T03:42:11Z",
      "verificationMethod": "did:web:dev-machine-alice.example.com#key-ed25519",
      "proofPurpose": "assertionMethod",
      "proofValue": "z<base58btc(ed25519_sig)>"
    },
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "mldsa44-jcs-2026",
      "created": "2026-05-14T03:42:11Z",
      "verificationMethod": "did:web:dev-machine-alice.example.com#key-mldsa44",
      "proofPurpose": "assertionMethod",
      "proofValue": "z<base58btc(mldsa44_sig)>"
    }
  ]
}
```

The credential is signed using one of two profiles:

- **Classical only:** one `eddsa-jcs-2022` proof. Smaller credential, ~700 bytes total. Appropriate when post-quantum retention is not a constraint.
- **Dual-proof post-quantum profile:** one `eddsa-jcs-2022` proof and one `mldsa44-jcs-2026` proof, both over the same JCS-canonicalized credential bytes (PAD-040 §3.3a). Post-quantum-ready, ~3.2 KB total.

The choice is per-deployment. Regulated industries with multi-year retention windows are advised to emit the dual-proof profile.

### 3.4 Asynchronous attestation flow

The pre-push git hook does **not** wait for the signature to complete. The flow is:

1. The hook runs the Cortex evaluator. The evaluator produces an `EgressDecision` in milliseconds.
2. The hook decides synchronously: if `decision == "block"`, the hook exits non-zero and the push is aborted. If `decision == "attest"` or `"allow"`, the hook exits zero and the push proceeds.
3. **In parallel**, the hook enqueues the `EgressDecision` to a background signer process (the Vouch sidecar; see also PAD-003 for the broader Identity Sidecar pattern).
4. The signer produces the Verifiable Credential asynchronously, writes it to a local audit log file at `.vouch/audit/credentials/<credential-id>.json`, and optionally forwards it to a remote audit sink (an HTTP endpoint, an S3 bucket, a logging pipeline) via a configurable transport.

The asynchronous design ensures that the developer's `git push` is not slowed by signing. For Ed25519, signing latency is ~50 microseconds and the synchronous case would also work fine. For the hybrid profile, signing takes ~3 milliseconds and the asynchronous design becomes more valuable.

### 3.5 Policy-snapshot binding

The `policy_snapshot_hash` field in the `EgressDecision` is the SHA-256 of the canonical bytes of the `.vouchpolicy` file as it existed at the moment of decision. The Vouch signer **must** independently re-hash the `.vouchpolicy` file at signing time and verify that the hash matches the one in the `EgressDecision` before producing the credential. If they do not match (which would indicate that the policy file was modified between decision and signing), the signer **must** abort and log an integrity warning.

This binding is what gives the credential its evidentiary strength. An auditor receiving the credential can fetch the policy snapshot from the developer's machine or from a separate snapshot log, hash it themselves, and confirm that the policy in effect at decision time is the one referenced in the credential.

### 3.6 Optional human-override binding

If the developer invoked `amnesia approve-once` to override a block (see PAD-060 for the override pattern itself), the `human_override` field in the `EgressDecision` is populated with the override identifier. The override is itself a separately-signed Verifiable Credential. The bridge embeds the override credential's URN by reference and includes its hash in the egress decision, providing a chain of two credentials: the override and the egress decision that consumed it.

### 3.7 Verification flow

A third-party auditor verifies a stored `AmnesiaEgressDecisionCredential` as follows:

1. Resolve the issuer DID to obtain the verification method (public key).
2. Verify the Data Integrity proof against the credential body. If hybrid, verify both Ed25519 and ML-DSA-44 signatures (or whichever is preferred for the auditor's threat model).
3. Fetch the `.vouchpolicy` snapshot referenced by `policy_snapshot_hash` (from a separately-archived snapshot log or from the developer's repository at the corresponding commit).
4. Re-hash the snapshot and verify that the hash matches.
5. Optionally re-run the Cortex evaluator with the snapshot policy and the commit range and confirm that the evaluator's deterministic output matches the `decision` field in the credential.

Step 5 is the strongest form of verification because it independently reproduces the policy decision from first principles. The evaluator is deterministic (PAD-050), so the same policy + same commit range MUST produce the same decision, regardless of when or where the re-evaluation is run.

---

## 4. Prior Art Differentiation

### 4.1 Signed git commits and signed tags (GPG, S/MIME, SSH signatures, Sigstore)

Existing systems sign source events. They do not sign policy decisions. A signed commit proves authorship; it does not prove that any policy evaluator was run, that any policy was enforced, or that a specific block / attest / allow decision was reached.

### 4.2 Signed build artifacts (SLSA, in-toto, Sigstore)

SLSA and in-toto define attestation formats for build pipelines. The artifacts being attested are *outputs* (built binaries, container images). The attestation says "this binary was built from this source by this builder." It does not say "the developer machine ran a deterministic policy evaluator at the moment of egress and the evaluator's decision was X." The phase is different (build vs. egress), the input is different (source tree vs. commit range), and the conclusion being attested is different (build provenance vs. policy decision).

### 4.3 Generic W3C VC tooling

W3C Verifiable Credentials and Data Integrity proofs are general-purpose primitives. They define how to sign and verify a JSON document. They do not specify the shape of an `EgressDecision` credential, do not specify policy-snapshot binding, and do not specify asynchronous-attestation composition with a pre-push hook. The novelty here is the *application* of these primitives to deterministic policy decisions of an AI coding assistant workspace.

### 4.4 Policy-as-code engines with logging (Open Policy Agent, Cedar, others)

Policy-as-code engines produce decisions and log them. The logs are typically plain-text or structured JSON without cryptographic signatures. Some deployments retrofit signing on top (signing the OPA decision log line with a hardware security module). These retrofits target a different threat model (centralized policy server enforcing API access) and do not address the specific case of a developer's local machine producing an egress-time decision over a git commit range with policy-snapshot binding.

### 4.5 Post-quantum digital signature schemes (FIPS 204 ML-DSA, others)

FIPS 204 standardized ML-DSA in August 2024. The post-quantum primitives themselves are publicly available. What is novel here is the **composition** of ML-DSA with W3C Data Integrity, expressed as a dual-proof attachment on the same credential (one `eddsa-jcs-2022` proof plus one `mldsa44-jcs-2026` proof, the latter aligning with the Digital Bazaar [`mldsa44-rdfc-2024-cryptosuite`](https://github.com/digitalbazaar/mldsa44-rdfc-2024-cryptosuite) family's forthcoming JCS variant), **applied to the specific use case of egress-time policy decisions for AI coding assistant workspaces**, with multi-year retention as the explicit design constraint.

### 4.6 The combination is novel

No prior system combines (a) a deterministic egress-time policy evaluator for an AI coding assistant workspace, (b) W3C Verifiable Credentials as the attestation format, (c) policy-snapshot binding via content-addressed hashing, (d) asynchronous post-decision signing that does not delay the developer's push, (e) an optional dual-proof post-quantum profile (one classical Data Integrity proof plus one ML-DSA-44 Data Integrity proof, both over the same JCS-canonicalized credential) for multi-year retention, and (f) deterministic re-verification by re-running the evaluator against the bound snapshot. This disclosure establishes prior art on the composition.

---

## 5. Technical Implementation

### 5.1 Reference implementation locations

- **Python:** `vouch-protocol/vouch/integrations/amnesia.py`. Function `build_egress_attestation(decision: EgressDecision, signer: Signer) -> dict` produces the credential. Function `verify_egress_attestation(credential: dict, policy_snapshot: bytes) -> VerificationResult` verifies.
- **TypeScript:** `vouch-protocol/packages/sdk-ts/src/integrations/amnesia.ts`. Equivalent API: `buildEgressAttestation()`, `verifyEgressAttestation()`.
- **Bridge documentation:** `vouch-protocol/docs/integrations/amnesia.md`.
- **Test vectors:** Cross-language test vectors for the bridge are at `test-vectors/amnesia-egress-decision/` (planned, see Action items in `docs/specs/strategy-amnesia-website-and-pads.md`).

### 5.2 Wire format

The credential is W3C VC 2.0 JSON with a Vouch-specific context. The minimum required fields are listed in §3.3. Additional fields may be present (delegation chains per PAD-002, behavioral metadata per PAD-042, etc.) but are not required for the bridge to function.

### 5.3 Cryptosuite selection

The bridge supports the `eddsa-jcs-2022` cryptosuite alone (single classical proof) or in combination with `mldsa44-jcs-2026` (dual-proof post-quantum profile). The cryptosuite of each proof is encoded in its own `proof.cryptosuite` field; verifiers iterate over the `proof` array and apply local policy (e.g., a long-term-archive verifier might require the credential to carry an `mldsa44-jcs-2026` proof and refuse credentials that carry only the classical proof).

### 5.4 Audit log storage

Credentials are written to `.vouch/audit/credentials/<credential-id>.json` on the developer machine by default. The `<credential-id>` is a UUID generated at signing time. Larger deployments will forward credentials to a remote audit sink (S3, Splunk, an enterprise audit log) via a configurable transport. The local file remains as a tamper-evident local cache.

### 5.5 Re-verification by re-running the evaluator

The deterministic evaluator (Cortex) is deterministic by design (PAD-050). Given the same `.vouchpolicy` snapshot and the same commit range, it MUST produce the same `decision`. The strongest verification of an egress credential is to re-run the evaluator against the bound snapshot and the bound commit range and confirm that the output matches. Tooling for this verification mode is straightforward: invoke `cortex evaluate --policy <snapshot> --commits <range>` and compare to the credential's `decision` field.

---

## 6. Claims Summary

This defensive publication establishes prior art on the following methods, alone or in combination:

1. **Attestation of a deterministic egress-time policy decision** as a W3C Verifiable Credential with Data Integrity proofs, applied specifically to AI coding assistant workspaces.

2. **Policy-snapshot binding** within the credential subject via content-addressed hash of the policy file, with mandatory re-hash verification at signing time before the credential is emitted.

3. **Asynchronous-attestation composition with a pre-push git hook** in which the hook decides synchronously and the cryptographic signing occurs in parallel without delaying the developer's push.

4. **Hybrid post-quantum signatures applied to egress-decision audit credentials** specifically, with the explicit design constraint of multi-year retention windows.

5. **Deterministic re-verification of egress decisions** by independently re-running the deterministic policy evaluator against the bound policy snapshot and the bound commit range.

6. **Composition of a write-only ledger (PAD-048) with W3C Verifiable Credentials** such that the rules that contributed to a decision are individually addressable (`active_rule_ids`) inside the signed credential.

7. **Embedded human-override binding** by referencing a separately-signed override credential within the egress decision credential, creating a verifiable chain of two credentials when a block is overridden.

---

## Prior Art Declaration

This disclosure is published under the Apache License 2.0 to establish prior art and prevent the patenting of these methods by any party. The methods described are intended for free, open use. The author retains no proprietary claim and explicitly waives any future patent rights arising from the disclosed methods.

The disclosure is timestamped at the publication date in the document header. It is published to the public Git repository at [github.com/vouch-protocol/vouch](https://github.com/vouch-protocol/vouch) and accessible to any third party performing prior-art search.

## Notes on companion disclosures

PAD-059 sits at the intersection of two disclosure clusters:

- **The AI coding assistant governance cluster** (PAD-048 through PAD-058) describes the deterministic-policy side of the bridge.
- **The cryptographic identity cluster** (PAD-001 through PAD-047) describes the W3C-VC-and-Data-Integrity side of the bridge.

This disclosure documents the composition. A subsequent disclosure (PAD-060) covers the single-use audited override pattern referenced in §3.6, which is itself a separately patentable method.
