# PAD-085: Two-Phase Deliberated Execution of Irreversible Agent Actions with Signed Veto Window

**Identifier:** PAD-085
**Title:** Method for Two-Phase Deliberated Execution of Consequential Autonomous Agent Actions, in Which an Intent Is Committed and Broadcast Before Execution, a Challenge Window Must Provably Elapse, and Any Authorized Party May Block Execution With a Separately-Signed Veto Bound to the Committed Intent
**Publication Date:** July 5, 2026
**Prior Art Effective Date:** July 5, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / Agent Governance / Irreversible-Action Containment / Human Oversight / Verifiable Credentials
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-016 (Heartbeat), PAD-017 (Proof of Reasoning), PAD-020 (Ratchet Lock), PAD-021 (Graduated Autonomy), PAD-047 (VDF Rate-Limiting), PAD-071 (Commit-Before-Outcome), PAD-086 (Executable Caveats)

---

## 1. Abstract

A method for gating an autonomous agent's consequential and irreversible
actions behind a mandatory two-phase, deliberated execution sequence. In the
first phase the agent issues and broadcasts a signed **Intent Credential** that
names the proposed action, its reversibility class, a challenge window, and the
set of parties authorized to object. Execution is structurally impossible until
the challenge window has provably elapsed. In the second phase the agent issues
an **Execute Credential** that references the prior intent and carries evidence
that the window elapsed and no valid veto was recorded; a verifier rejects any
Execute Credential minted before the window closes or in the presence of a valid
veto. During the window any authorized party may issue a separately-signed
**Veto Credential** bound to the committed intent's digest, which any verifier
treats as a hard block.

The protected property is prevention rather than detection: unlike audit
logging, reasoning capture, or post-hoc reputation, this mechanism interposes a
deliberation delay and a third-party objection channel before an irreversible
effect occurs, while imposing zero delay on actions classified as reversible.

Key elements:

- **Reversibility-graded execution.** The required deliberation latency is a
  function of a declared reversibility class, not a flat policy. Reversible
  actions execute immediately; only irreversible or high-blast-radius classes
  enter the two-phase sequence.
- **Commit-before-execute ordering.** The intent is fixed by a signed credential
  whose `created` time and action digest are bound together, so the executed
  action cannot differ from the announced one and cannot be executed earlier
  than the window permits.
- **Provable window elapse without a trusted clock (optional).** The window may
  be evidenced by signed wall-clock timestamps or, where no clock authority is
  trusted, by a Verifiable Delay Function output (PAD-047) proving the minimum
  time could not have been skipped.
- **Separated veto authority.** The parties who may block execution are named in
  the intent and are structurally distinct from the acting agent, so the actor
  cannot both propose and unilaterally clear its own irreversible act.

---

## 2. Problem Statement

### 2.1 Authorization does not bound harm inside the envelope

An agent operating strictly within a valid, attenuated delegation may still take
an authorized action that is catastrophic and irreversible: wiring funds,
deleting a production dataset, publishing to an external channel, or actuating a
physical effector. Identity, delegation, reasoning capture, and reputation all
answer questions after the effect. None interposes a controllable pause before
an effect that cannot be undone.

### 2.2 Detection is inadequate for irreversible effects

For reversible actions, detect-and-remediate suffices: the effect can be rolled
back. For irreversible actions it does not: by the time an audit log, reasoning
trace, or reputation update is examined, the funds are gone and the data is
destroyed. The one class of action where a control must act before the effect is
exactly the class no existing agent-trust mechanism gates.

### 2.3 Human-oversight mandates need a machine-checkable hook

Regulatory regimes increasingly require that a human be able to intervene before
a consequential automated decision takes effect (for example, EU AI Act Article
14 human oversight). A blanket human-in-the-loop on every action is impractical
at machine speed and scale. What is needed is a mechanism that applies the pause
only to the actions that warrant it, makes the pause and the intervention
cryptographically verifiable after the fact, and works across vendors and
services rather than inside one platform.

### 2.4 Self-cleared delays are not delays

A pause the acting agent can shorten, skip, or clear by itself is not a control.
Any deliberation mechanism must make the elapse of the window and the absence of
an objection verifiable by an independent party, and must place the objection
authority in different hands than the actor.

---

## 3. The Novel Mechanism

### 3.1 Reversibility classification

Each action is assigned a reversibility class, derived from verifier-side policy
and from caveats in the delegation chain (PAD-086), never self-asserted by the
acting agent. Classes map to a minimum deliberation window:

| Class | Example | Minimum window |
|---|---|---|
| `reversible` | read, idempotent write to a versioned store | 0 (immediate) |
| `reversible-costly` | send an internal message, mutate a cache | short, policy-set |
| `irreversible-financial` | transfer funds, place an order | policy-set, typically minutes to hours |
| `irreversible-destructive` | delete without backup, revoke access | policy-set |
| `irreversible-external` | publish, email an outside party, actuate | policy-set |

### 3.2 Phase one: Intent Credential

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "VouchIntentCredential"],
  "issuer": "did:web:agent.example",
  "credentialSubject": {
    "intent": { "action": "transfer_funds", "target": "acct:vendor-1", "resource": "usd:5000" },
    "actionDigest": { "algorithm": "sha-256-jcs", "digest": "u<multibase>" },
    "reversibilityClass": "irreversible-financial",
    "challengeWindow": {
      "minSeconds": 900,
      "opensAt": "2026-07-05T10:00:00Z",
      "vetoAuthorities": ["did:web:controller.example", "did:web:risk.example"],
      "broadcast": ["log://transparency.example/agent-actions", "mcp://controller.example/inbox"]
    }
  },
  "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "...": "..." }
}
```

The `actionDigest` is the JCS-canonical SHA-256 of the exact action object, so
the later executed action must be byte-identical to the announced one. The
credential is broadcast to the named channels at issuance.

### 3.3 Phase two: Execute Credential

After the window closes, and if no valid veto exists, the agent issues:

```json
{
  "type": ["VerifiableCredential", "VouchExecuteCredential"],
  "credentialSubject": {
    "intentRef": "urn:vouch:intent:...",
    "intentDigest": { "algorithm": "sha-256-jcs", "digest": "u<multibase>" },
    "windowEvidence": {
      "mode": "timestamp",
      "closedAt": "2026-07-05T10:15:00Z",
      "vdfProof": null
    },
    "vetoStatus": "none"
  },
  "proof": { "...eddsa-jcs-2022 or dual-proof...": "..." }
}
```

### 3.4 Phase (any time in window): Veto Credential

```json
{
  "type": ["VerifiableCredential", "VouchVetoCredential"],
  "issuer": "did:web:controller.example",
  "credentialSubject": {
    "intentDigest": { "algorithm": "sha-256-jcs", "digest": "u<multibase>" },
    "decision": "block",
    "reason": "amount exceeds unattended threshold pending review"
  },
  "proof": { "...": "..." }
}
```

### 3.5 Verifier algorithm

A verifier presented with an Execute Credential accepts the action only if all
of the following hold, and otherwise emits the named structured reason:

1. The referenced Intent Credential verifies and its `actionDigest` equals the
   digest of the action now being executed. (`intent_mismatch`)
2. The issuer of the Execute Credential is the issuer of the intent, under a
   still-valid delegation. (`unauthorized_executor`)
3. The window evidence proves at least `minSeconds` elapsed after `opensAt`:
   either signed `closedAt` minus `opensAt` is at least `minSeconds`, or a valid
   VDF proof of the target duration. An execute time inside the window is
   rejected. (`challenge_window_not_elapsed`)
4. No Veto Credential signed by any listed `vetoAuthority` and bound to this
   `intentDigest` has been observed on the broadcast channels. (`vetoed`)

### 3.6 Structured reasons

`challenge_window_not_elapsed`, `vetoed`, `intent_mismatch`,
`unauthorized_executor`, `reversibility_class_understated`. These compose with
the delegation verifier's reasons and the caveat reasons of PAD-086.

---

## 4. Prior Art Differentiation

Two-phase commit, maker-checker approval, time-locks, and change-control windows
are all established. This disclosure does not claim those general ideas. What is
differentiated is their composition into a credential-native, cross-verifier,
reversibility-graded deliberation control for autonomous agents:

- **Versus PAD-047 (VDF rate-limiting).** PAD-047 enforces a minimum interval
  between an agent's own successive high-stakes actions to stop runaway loops.
  PAD-085 enforces a deliberation delay and third-party objection channel before
  a single irreversible action, with a signed veto path. PAD-085 may use a VDF as
  one way to evidence its window, but its subject is deliberation and veto, not
  self-rate-limiting.
- **Versus PAD-017 (Proof of Reasoning).** PAD-017 escalates audit depth by
  impact and captures why an action was taken; it is detective. PAD-085 withholds
  execution for a window and admits a blocking veto; it is preventive. They
  compose: the intent can carry PAD-017 justification, and the window is when a
  reviewer reads it.
- **Versus PAD-020 and PAD-021 (Ratchet Lock, Graduated Autonomy).** Those bound
  what capabilities an agent may acquire or hold. PAD-085 gates the timing and
  clearance of exercising a capability the agent already holds.
- **Versus PAD-071 (Commit-Before-Outcome).** PAD-071 commits a verdict before
  its outcome is known, for track-record integrity. PAD-085 commits an intent
  before its execution, for pre-effect intervention. Same commit-before
  discipline, different protected event.
- **Versus platform maker-checker and cloud change windows.** Those are siloed
  inside one service or IAM system and gate human or service-account actions.
  PAD-085 is a portable credential any counterparty verifier can check before
  transacting, spans services, and binds the veto authority cryptographically
  rather than by platform role.
- **Versus a plain signed timestamp delay.** A self-signed delay the agent can
  backdate is not a control. PAD-085 requires independently-verifiable window
  evidence (signed third-party close or VDF) and a separated veto authority.

---

## 5. Technical Implementation

The method is realized using the protocol's shared `eddsa-jcs-2022` Data
Integrity proofs (with the hybrid Ed25519 + ML-DSA-44 dual-proof profile
available for long-retention deployments) and RFC 8785 JCS canonicalization, so
the Intent, Execute, and Veto credentials verify byte-identically across the
language SDKs. The action and intent digests are SHA-256 over the JCS canonical
form. The optional VDF window mode reuses the Verifiable Delay Function primitive
of PAD-047; the broadcast transport is caller-selected and vendor-neutral. The
verifier evaluates the four-step algorithm of section 3.5 offline against the
presented credentials.

---

## 6. Claims Summary

1. A method for gating an autonomous agent's action behind a two-phase sequence
   in which a signed intent credential naming the action, its reversibility
   class, a challenge window, and authorized objectors is committed and
   broadcast, and a signed execute credential referencing that intent is
   required before the action takes effect.
2. The method of claim 1 wherein a verifier rejects the execute credential
   unless evidence proves the challenge window elapsed, so execution cannot be
   performed earlier than the deliberation delay permits.
3. The method of claim 2 wherein the window elapse is evidenced by a Verifiable
   Delay Function output, so the delay is enforceable without trust in any clock
   authority.
4. The method of claim 1 wherein any party named as an objector may issue a
   separately-signed veto credential bound to the committed intent digest, which
   a verifier treats as a hard block, and wherein the objector set is
   structurally distinct from the acting agent.
5. The method of claim 1 wherein the required deliberation delay is a function of
   a reversibility class derived from verifier policy and delegation-chain
   caveats rather than self-asserted by the agent, so a reversible action incurs
   no delay and an understated class is a detectable violation.
6. The method of claim 1 wherein the executed action must be byte-identical to
   the committed action digest, so an agent cannot announce one action and
   execute another.
7. The method of claim 1 wherein the credentials use canonicalization and
   signature primitives shared across language SDKs, so the intent, veto, and
   execution verify cross-language and compose with delegation, reasoning, and
   accountability credentials of the same protocol.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem.
