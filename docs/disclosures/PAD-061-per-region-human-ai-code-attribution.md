# PAD-061: Per-Region Authorship Attribution for Mixed Human and AI Source Code via Edit-Channel Capture and Independently-Keyed Signatures

**Identifier:** PAD-061  
**Title:** Method and System for Cryptographically Attributing Individual Regions of a Source File to Human or AI Authors by Capturing Authorship at the Edit Channel and Signing Each Party's Regions with an Independently-Held Key  
**Publication Date:** June 10, 2026  
**Prior Art Effective Date:** June 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Software Provenance / AI Coding Governance / Accountability / Decentralized Identifiers / DevSecOps  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-002 (Chain of Custody Delegation), PAD-003 (Identity Sidecar), PAD-007 (Automated Provenance via Input Telemetry), PAD-039 (JCS Deterministic Multi-Party Trust State), PAD-042 (Standardized Metadata Schema for AI Agent Ledger Signatures), PAD-056 (Capability-Bounded AI Assistant Output), PAD-059 (Vouch-Amnesia Attestation Bridge)

---

## 1. Abstract

A method that records, at the moment of editing and from the actual edit
channel, which regions of a source file were produced by an AI coding
assistant and which by a human, and then attests each party's regions with a
signing key that party holds independently of the other. The output is a signed
Attribution Manifest that binds, per file, exact line ranges to an author
Decentralized Identifier (DID) over the exact bytes, secured by a JSON
Canonicalization Scheme (JCS) Data Integrity proof.

The novel contribution is making the attribution legitimate rather than a
self-serving label. Two properties enforce this:

1. **Edit-channel capture.** Regions attributed to the AI are derived only from
   the assistant's actual edit operations (its Edit / Write / MultiEdit tool
   calls), captured as they occur by a hook on the assistant's edit pipeline.
   They are never reconstructed after the fact or asserted by hand. Regions
   attributed to the human are the residual: any change to the file on disk
   that did not arrive through the assistant's edit channel. Lines unchanged
   since the session began are marked preexisting.

2. **Independently-held keys.** AI-authored regions are attested with an
   AI-session key that the human's editor does not wield, optionally held in an
   Identity Sidecar (PAD-003) or delegated from the AI vendor's root identity
   (PAD-002). The human signs the assembled manifest with the human's own key.
   Because the two keys are distinct and separately held, neither party can
   mint the other's attribution.

The manifest enforces completeness (the union of attributed regions must cover
every line of the file, so a defective region cannot hide as unattributed) and
backing (every AI region in the manifest must be covered by a signed AI
attestation, so an AI region cannot be invented without the AI signature). A
verifier can therefore confirm, for any line that later causes an incident,
whether a human or a machine wrote it, who specifically, and that the bytes
have not changed since signing.

---

## 2. Problem Statement

### 2.1 git blame Launders AI Authorship Through the Human Committer

When an AI coding assistant and a human jointly edit a file, the version
control system credits every line to the identity that committed it, which is
almost always the human. The assistant's contribution is invisible. `git
blame`, the commit author field, and signed-commit mechanisms (GPG, SSH, even
the cryptographic commit signing of the Vouch git integration) all attribute
the whole commit to one committing identity. They operate at commit
granularity, not authorship granularity, and they have no concept of a
non-human author of a subset of lines.

### 2.2 Accountability Requires Sub-File Authorship, Not Commit Authorship

As autonomous and semi-autonomous coding assistants write a growing fraction of
production code, the operational question after a defect, a security
regression, or a compliance failure is no longer only "who committed this" but
"who authored this specific line, a human or a model, and which one." Liability
frameworks, incident response, regulated-industry audit obligations (including
emerging AI-accountability regimes), and internal engineering governance all
need authorship at the region level. No deployed mechanism provides it with
cryptographic assurance.

### 2.3 Naive Authorship Tagging Is Worthless

The obvious approach, having the editor or the assistant stamp regions with an
"AI wrote this" or "human wrote this" label, fails on legitimacy. If a single
party's tooling applies both labels, that party controls both, so a human can
attribute their own defective line to the AI, or an assistant's wrapper can
claim human lines as its own. A label that the labeller can set arbitrarily
proves nothing. Equally, a label captured after the fact (by diffing a final
file against some baseline and guessing) cannot distinguish a human edit from
an AI edit, because the final bytes carry no record of which channel produced
them.

### 2.4 Existing Provenance Mechanisms Operate at the Wrong Granularity or Trust Boundary

- Commit signing (GPG / SSH / Vouch git) proves who committed, at commit
  granularity, with one signer.
- Content provenance standards for media (C2PA) attest the origin of a whole
  asset, not regions of a text file authored by different parties.
- AI-output watermarking marks that text was machine-generated but does not
  identify which model instance, does not separate interleaved human edits, and
  is not cryptographically bound to a committing identity.
- Telemetry-based provenance (PAD-007) records that input occurred but does not
  separate concurrent human and AI authorship within one file with independent
  per-party signatures.

None of these answers "which lines did the human write and which did the AI,
provably, with each party's own key."

---

## 3. Disclosed Method

### 3.1 Architecture

```
+---------------------------+        +-----------------------------+
| AI coding assistant       |        | Human editor / typing       |
| (Edit / Write / MultiEdit)|        | (changes on disk)           |
+-------------+-------------+        +--------------+--------------+
              | edit-channel hook                   | (no hook: residual)
              v                                      |
   +----------+-----------+                          |
   | Attribution Session  |<-------------------------+
   | - AI-session key     |   reconciles human drift at each AI event
   |   (held separately)  |   and at finalize (snapshot -> final = human)
   | - per-file authorship|
   |   map (ai/human/pre) |
   +----------+-----------+
              | finalize(files, human_signer)
              v
   +----------+--------------------------------------------------+
   | Attribution Manifest                                        |
   |  files[]: { path, sha256, lineCount, regions[] }            |
   |  regions[]: { startLine, endLine, source, author, model }   |
   |  aiAttestations[]: signed by AI-session key                 |
   |  proof: Data Integrity proof signed by the human key        |
   +----------+--------------------------------------------------+
              v
   +----------+-----------+
   | Verifier             |  human proof + AI attestations +
   | who-wrote-this?      |  region completeness + byte hashes
   +----------------------+
```

### 3.2 Edit-Channel Capture

A hook is installed on the AI assistant's edit pipeline. For an assistant that
exposes tool events (for example a coding agent firing a post-tool event on its
Edit / Write / MultiEdit operations), the hook fires after each edit is applied
and reports the affected file. The capturing process reads the file's current
content (the post-edit state) and, for an in-place edit, the assistant's own
before-and-after fragments, so the inserted or replaced lines can be diffed as
AI-authored.

Each captured edit updates a per-file authorship map: a structure aligned to
the file's current lines, where each line carries a source tag (`ai-assistant`,
`human`, or `preexisting`) and, for AI lines, the model identifier. The map is
updated by a line-level diff:

- Equal lines carry their prior tag forward.
- Inserted or replaced lines produced by the assistant take the `ai-assistant`
  tag and the model identifier.

### 3.3 Human Drift Reconciliation

A human may edit the file between two AI edits, or after the last AI edit,
without passing through the assistant's edit channel. These edits are detected
as drift:

- **At each AI edit:** before applying the AI tag, the captured pre-edit state
  is compared against the session's last stored snapshot. Any line that differs
  is attributed to the human, because it changed without an AI edit event.
- **At finalize:** the final committed content of each file is compared against
  the session's last snapshot. Any line that changed is attributed to the
  human.

This two-point reconciliation is what makes the human attribution legitimate
without a human-side hook: the human's lines are precisely the changes the
assistant did not make. The assistant cannot claim them, because it never
produced them through its channel; the human cannot disclaim them, because they
are the residual of the AI capture.

### 3.4 Independently-Held Keys

The Attribution Session holds an AI-session identity with its own DID and
keypair, distinct from the human's signing identity. Three embodiments, in
increasing strength:

1. **Local session key (baseline).** The session generates a fresh did:key
   keypair, stored with owner-only file permissions. This is the reference
   embodiment and is sufficient when the goal is to separate, within one
   workstation, which channel produced which lines.
2. **Sidecar-held key (stronger).** The AI-session private key is held by an
   Identity Sidecar (PAD-003), so a prompt-injected assistant cannot exfiltrate
   it and the human's editor cannot sign with it directly.
3. **Vendor-delegated key (strongest).** The AI-session identity is a
   capability-attenuated delegation (PAD-002) from the AI vendor's root
   identity, so the AI's signature chains to the actual model provider rather
   than to a key the local user minted.

In all three, the human signs the final manifest with the human key only. The
separation of keys is the trust boundary that distinguishes this method from
naive labelling.

### 3.5 Signed AI Attestation

Each captured edit, and the per-file AI view at finalize, produces an
authorship attestation signed by the AI-session key:

```json
{
  "@context": "https://vouch-protocol.com/attribution/v1",
  "type": "VouchAuthorshipAttestation",
  "session": "did:key:z6Mk...",
  "path": "src/app.py",
  "model": "claude-opus-4-8",
  "sha256": "9f2b...e1",
  "aiLines": [[1, 2], [6, 7]],
  "recordedAt": "2026-06-10T12:00:00Z",
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6Mk...#attribution",
    "proofPurpose": "assertionMethod",
    "proofValue": "z..."
  }
}
```

The `aiLines` ranges are bound to the file content by `sha256`, and the whole
attestation is bound by the Data Integrity proof over its canonical JCS bytes.

### 3.6 The Attribution Manifest

At finalize, the human signer assembles the manifest:

```json
{
  "@context": "https://vouch-protocol.com/attribution/v1",
  "type": "VouchAttributionManifest",
  "commit": "working-tree",
  "createdBy": "did:web:dev.acme.com",
  "aiSession": {
    "did": "did:key:z6Mk...",
    "model": "claude-opus-4-8",
    "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." }
  },
  "files": [
    {
      "path": "src/app.py",
      "sha256": "9f2b...e1",
      "lineCount": 7,
      "regions": [
        { "startLine": 1, "endLine": 2, "source": "ai-assistant",
          "author": "did:key:z6Mk...", "model": "claude-opus-4-8" },
        { "startLine": 3, "endLine": 5, "source": "human",
          "author": "did:web:dev.acme.com", "model": null },
        { "startLine": 6, "endLine": 7, "source": "ai-assistant",
          "author": "did:key:z6Mk...", "model": "claude-opus-4-8" }
      ]
    }
  ],
  "aiAttestations": [ /* the signed attestations of 3.5 */ ],
  "proof": { /* Data Integrity proof signed by the human key */ }
}
```

The human proof covers the entire manifest, including the embedded AI
attestations, so altering an attestation breaks the human proof as well as the
attestation's own proof.

### 3.7 Verification

A verifier checks, in order:

1. **Human proof.** The Data Integrity proof over the whole manifest verifies
   against the human public key.
2. **AI attestations.** Every embedded AI attestation verifies against the
   AI-session public key.
3. **Backing.** Every region whose source is `ai-assistant` is covered by the
   `aiLines` of a verified AI attestation. An AI region with no signed backing
   is rejected. This is what prevents relabelling a human line as AI.
4. **Completeness.** The regions of each file cover every line from 1 to
   `lineCount` with no gap and no overlap. A file whose regions leave lines
   unattributed is rejected, so a defective line cannot hide as unattributed.
5. **Byte binding.** When the files are available, the SHA-256 of each file's
   current bytes matches the manifest. A single altered byte fails this check.

### 3.8 Blame and Summary

Given a verified manifest, a `blame` operation returns, for each line of a
file, the source, the author DID, and the model. A `summarize` operation
aggregates line counts and percentages by source. These present the proven
authorship in the same shape developers already expect from `git blame`, but
with a non-human author as a first-class possibility and with cryptographic
backing.

### 3.9 Honest Degradation

If the edit-channel hook never recorded anything (the assistant was not
instrumented), finalize attributes the whole file to the human committer and
emits no AI regions. The method never fabricates AI attribution it did not
observe. The presence of an AI region is therefore always evidence of a
captured, signed AI edit.

---

## 4. Distinction from Prior Art

### 4.1 vs. Version-Control Blame and Commit Signing

`git blame`, commit author metadata, and commit signing (GPG, SSH, Vouch git)
operate at commit granularity with one committing identity. PAD-061 operates at
line-region granularity with two independently-keyed authors per file and a
non-human author as a first-class case. Commit signing answers "who committed";
PAD-061 answers "who authored this region."

### 4.2 vs. AI-Output Watermarking

Statistical or token-level watermarking marks that text is machine-generated.
It does not separate interleaved human edits, does not identify the specific
model instance via a verifiable key, and is not bound to a committing human
identity. PAD-061 binds named regions to specific author DIDs with
per-party signatures and content hashes.

### 4.3 vs. Naive Authorship Labels

A label applied by a single party's tooling is controllable by that party and
proves nothing (Section 2.3). PAD-061's legitimacy rests on edit-channel
capture plus independently-held keys, so neither party can produce the other's
attribution. This is the central distinction.

### 4.4 vs. PAD-007 (Automated Provenance via Input Telemetry)

PAD-007 records that input events occurred to establish provenance
automatically. PAD-061 additionally separates concurrent human and AI
authorship within a single file and signs each party's regions with that
party's own key, enforcing region completeness and AI-region backing at
verification. PAD-061 may use PAD-007-style telemetry as one capture source but
adds the dual-keyed, region-complete manifest.

### 4.5 vs. PAD-042 (Standardized Metadata Schema for Agent Ledger Signatures)

PAD-042 standardizes the metadata schema for agent ledger signatures. PAD-061
defines a specific authorship-attribution object (regions, sources, per-region
authors, AI attestations) and the verification rules (backing, completeness,
byte binding) over it. PAD-061 may serialize within a PAD-042-compatible schema
but claims the per-region human-or-AI attribution method, not the general
metadata schema.

### 4.6 vs. PAD-059 (Vouch-Amnesia Attestation Bridge)

PAD-059 anchors an AI coding assistant's deterministic pre-push policy decisions
(block / attest / allow) to Verifiable Credentials. That is governance of the
egress decision. PAD-061 is governance of authorship: which party wrote which
lines. The two compose. A PAD-059 egress credential may reference a PAD-061
manifest so that an attested push also carries proven per-region authorship.

### 4.7 vs. Pair-Programming and IDE Authorship Plugins

Collaborative editors and some IDE plugins track which connected user typed
which characters for live presence or attribution within a trusted session.
They attribute among mutually-trusted human participants over a shared
transport, without independent cryptographic keys per author, without a
non-human author class, and without a verifiable, content-bound, signed
manifest that survives outside the editing session. PAD-061 produces a portable
signed artifact verifiable by any third party against the parties' public keys.

---

## 5. Claims

The defensive disclosure asserts public prior art for:

1. A method for attributing individual regions of a source file to a human
   author or to an AI coding assistant by capturing authorship from the
   assistant's actual edit channel as edits occur, and treating as human-
   authored the residual changes to the file that did not arrive through that
   channel.
2. The two-point human-drift reconciliation that attributes to the human any
   change detected between the last AI edit and the next AI edit (pre-edit
   state versus stored snapshot) and any change detected between the last AI
   edit and finalization (final content versus stored snapshot), without a
   human-side capture hook.
3. The attestation of AI-authored regions with an AI-session key held
   independently of the human's signing key, in embodiments where the
   AI-session key is a local session key, a key held by an Identity Sidecar, or
   a capability-attenuated delegation from the AI vendor's root identity.
4. The Attribution Manifest binding, per file, line ranges to author DIDs over
   the exact file bytes via a content hash and a JCS Data Integrity proof
   signed by the human key, embedding AI attestations signed by the AI-session
   key.
5. The verification rule requiring that every AI-attributed region be covered
   by a signed AI attestation, so an AI region cannot exist without the AI
   signature, preventing relabelling of human lines as AI-authored.
6. The verification rule requiring that the attributed regions of each file
   cover every line with no gap and no overlap, so a region cannot hide as
   unattributed.
7. The honest-degradation property whereby, absent any captured AI edit, the
   method attributes the whole file to the human committer and emits no AI
   regions, so the presence of an AI region is always evidence of a captured,
   signed AI edit.
8. A blame operation returning, for each line, the source (human, AI, or
   preexisting), the author DID, and the model identifier, derived from the
   verified manifest, presenting non-human authorship as a first-class result.

---

## 6. Reference Implementation

The reference implementation ships in the Vouch Protocol Python SDK under
Apache 2.0:

- `vouch/attribution.py`: the Attribution Session (edit capture, drift
  reconciliation, AI-session key handling), manifest assembly and signing, and
  the verification, blame, and summary functions.
- `vouch attribute` CLI: `record` and `hook` (the latter consumes a coding
  assistant's post-tool event from standard input), `finalize`, `blame`, and
  `verify`.
- `vouch/integrations/claude-code/`: a post-tool hook configuration that wires
  the assistant's Edit / Write / MultiEdit operations to `vouch attribute
  hook`, plus setup documentation.
- `examples/who_wrote_this.py`: a self-contained demonstration that an honest
  manifest verifies, a relabelled AI region is rejected, and a single altered
  byte is rejected.

Stronger key custody (Sidecar-held and vendor-delegated AI-session keys) and a
hosted attribution registry are operational layers on top of these open
primitives. This disclosure does not claim any specific commercial feature; it
claims the per-region attribution method and its verification rules.

---

## 7. Security Considerations

### 7.1 Trust in the Edit-Channel Hook

The legitimacy of AI attribution depends on the hook reporting only genuine
assistant edits. If an adversary can feed fabricated edit events to the
capture process, they can mint AI attribution for human-written lines. The hook
SHOULD therefore run inside the assistant's trust boundary, and in the stronger
embodiments the AI-session key is held by the Sidecar or delegated from the
vendor, so a fabricated local event cannot produce a vendor-chained signature.

### 7.2 Custody of the AI-Session Key

In the baseline embodiment the AI-session key is local and owner-readable. A
local adversary with that key can sign arbitrary AI attestations. Deployments
needing assurance against the local user SHOULD use the Sidecar or
vendor-delegated embodiments of Section 3.4, where the human user does not hold
the AI-session key.

### 7.3 Completeness Against Hidden Regions

The completeness rule (Section 3.7) prevents a defective line from being left
unattributed. It does not prevent a party from attributing a line to the
correct author who nonetheless disclaims responsibility through other means;
attribution establishes authorship, not intent or correctness.

### 7.4 Binding to Bytes, Not to Semantics

The content hash binds attribution to exact bytes. A semantically equivalent
reformatting (whitespace, comment changes) produces different bytes and
requires re-attribution. This is intentional: the manifest attests the bytes
that existed at signing, not an abstract semantic unit.

### 7.5 Privacy

The manifest records authorship metadata (which DID wrote which lines) and
content hashes, not the prompt history or the assistant's reasoning. It does not
collect third-party data. Where the AI-session DID is a fresh per-session
did:key, it does not link sessions to each other unless the operator chooses a
stable AI identity.

---

## 8. Conclusion

This disclosure establishes public prior art for **per-region authorship
attribution of mixed human and AI source code**, made legitimate by capturing
authorship at the assistant's edit channel and signing each party's regions
with an independently-held key, and made verifiable by a content-bound,
region-complete, dual-keyed Attribution Manifest. It answers, for any line that
later matters, whether a human or a machine wrote it, which one, and that the
bytes have not changed, without allowing either party to wear the other's name.

The author publishes this disclosure under Apache 2.0 (the reference
implementation) and CC0 (this disclosure document) to keep the method freely
available to the open developer and decentralized-identity communities and to
prevent its appropriation by patent claims from any third party.

---

## 9. References

- [PAD-001] Cryptographic Agent Identity (Gaddam, December 2025)
- [PAD-002] Chain of Custody Delegation (Gaddam, January 2026)
- [PAD-003] Identity Sidecar Pattern (Gaddam, January 2026)
- [PAD-007] Automated Provenance via Input Telemetry (Gaddam, January 2026)
- [PAD-039] Cross-Implementation Deterministic Multi-Party Trust State via JCS-Canonicalized Verifiable Credentials (Gaddam, April 2026)
- [PAD-042] Standardized Metadata Schema for AI Agent Ledger Signatures (Gaddam, April 2026)
- [PAD-056] Capability-Bounded AI Assistant Output via Intent Allow-List at the Identity Sidecar (Gaddam, May 2026)
- [PAD-059] Vouch-Amnesia Attestation Bridge (Gaddam, May 2026)
- [W3C-VC-2.0] Verifiable Credentials Data Model 2.0
- [W3C-DID-CORE] Decentralized Identifiers (DIDs) v1.0
- [VC-DI-EDDSA] Data Integrity EdDSA Cryptosuites v1.0 (eddsa-jcs-2022)
- [RFC 8785] JSON Canonicalization Scheme
