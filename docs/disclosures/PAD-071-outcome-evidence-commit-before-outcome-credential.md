# PAD-071: Commit-Before-Outcome Verdict Credential with Neutral-Settler Outcome Attestation

**Identifier:** PAD-071  
**Title:** Method for an Outcome-Evidence Credential in Which a Verdict, Prediction, or Recommendation Is Cryptographically Committed and Signed Before Its Outcome Is Known, and a Separately-Signed Settlement Attestation Binds the Observed Outcome Back to That Prior Commitment, So an Agent's Track Record Cannot Be Backdated, Cherry-Picked, or Unilaterally Edited  
**Publication Date:** June 17, 2026  
**Prior Art Effective Date:** June 17, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Agent Accountability / Reputation / Verifiable Credentials / Commit-Reveal  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-016 (Heartbeat), PAD-030 (ZK Reputation Portability), PAD-036 (Aggregated Reputation Scoring via Verifiable State Receipts), PAD-031 (Canary Identities)  

---

## 1. Abstract

A method for recording an autonomous agent's track record as tamper-evident
cryptographic evidence rather than as a mutable score. An issuer commits a
verdict, prediction, or recommendation as a signed Verifiable Credential whose
subject carries a salted SHA-256 digest of the canonical claim, fixed **before**
the outcome is known. After the outcome is observable, a separately-signed
settlement attestation reveals the claim and salt, lets any verifier recompute
the committed digest, and binds the observed outcome to that prior commitment. A
verifier rejects any settlement whose timestamp precedes the commitment, so a
winning verdict cannot be minted with hindsight.

Key innovations:

- **Commit-before-outcome binding.** The verdict is fixed by a signed digest at
  commit time. The signed `created` time and the digest together make backdating
  detectable: a claim revealed at settlement must recompute to a digest that was
  already signed earlier, so no party can substitute a different verdict after
  seeing the result.
- **Private commitment with later reveal.** A salt over the JCS-canonical claim
  lets the issuer publish only the digest, so the verdict cannot be read or
  front-run before settlement, yet is provably unalterable. The salt and claim
  are disclosed at settlement and checked against the published digest.
- **Neutral settler distinct from the committer.** The settlement attestation is
  signed by whoever observes the outcome, who may differ from the committer. It
  binds to the committed digest, not to trust in the committer, so the party
  whose record is at stake is not the party who certifies the result.
- **Anti-cherry-pick by construction.** Because each verdict is an independently
  signed, externally referenceable artifact committed before its result, a
  selectively-omitted loss is a visible gap against a settlement record rather
  than a silent absence in a self-reported score.

---

## 2. Problem Statement

### 2.1 Authenticity is not soundness

A protocol that proves an action authentically came from agent X, under valid
authority, with a non-revoked key, still says nothing about whether X is usually
right. A correctly-signed credential can carry a wrong prediction. Identity and
provenance answer "who did this," not "does this agent have a proven record of
being correct."

### 2.2 A score the agent can move is not evidence

A reputation value maintained by the party that benefits from it, or by an
engine that party operates, can be set, reset, or selectively updated. Whoever
controls the write path controls the number. A record that can be edited by its
own subject is an assertion, not evidence.

### 2.3 Self-reported track records permit hindsight and omission

Without a commitment fixed before the outcome, a track record can be assembled
after results are known: a verdict can be backdated to look prescient, and a
losing verdict can simply be left out. Aggregating such reports, however
rigorously, inherits the bias of the inputs.

---

## 3. Solution (The Invention)

`commit_outcome(...)` issues an `OutcomeCommitmentCredential`: an
`eddsa-jcs-2022` Verifiable Credential whose subject carries a `claimType`, a
vendor-neutral `settlement` descriptor (`method`, `locator`, `resolutionCriteria`,
optional `resolveBy`), and a `commitment` block holding `algorithm`
(`sha-256-jcs`), the multibase `digest`, and a `salted` flag. In private mode the
cleartext claim is withheld and only the digest is published; the function
returns the salt and claim as a secret the committer keeps for settlement.

`attest_outcome(...)` issues an `OutcomeAttestationCredential`, signed by the
settler. Its subject reveals the claim and salt, reproduces the committed digest
and commitment timestamp, and records the observed `outcome` with an optional
`matchesCommitment` verdict. Before signing, the function recomputes the digest
from the revealed claim and salt and refuses to issue if it does not match the
commitment, so a settler cannot attach a reveal that disagrees with what was
committed.

`verify_attestation(...)` checks the settler's Data Integrity proof, recomputes
the digest from the revealed claim and salt, and confirms it equals the cited
commitment digest. When the original commitment is supplied, it further confirms
the two digests agree, the subject is the same, and the settlement timestamp does
not precede the commitment; when the committer's key is supplied, the
commitment's own proof is verified too. `accountability_pointer(...)` builds a
small `AccountabilityRecord` object that any other credential can embed in its
subject to reference such a record, so an identity credential can point at an
agent's settled track record.

Because both credentials use the shared JCS and `eddsa-jcs-2022` primitives, the
same commitment and attestation verify across the language SDKs, and the outcome
evidence can feed, but is independent of, any scoring engine.

---

## 4. Prior Art Differentiation

Commit-reveal hashing, prediction markets, and encoding reputation as Verifiable
Credentials are each established prior art. This disclosure does **not** claim
those general mechanisms. What is differentiated here is their composition into a
verdict-accountability primitive for autonomous agents:

- **Commit-before-outcome applied to a verdict's correctness.** A salted digest
  fixes the claim before its result, and verification rejects a settlement that
  predates the commitment. The protected property is the soundness of a
  prediction or recommendation over time, not liveness. This differs from
  commit-reveal used for canary liveness or heartbeat freshness (PAD-016,
  PAD-031), where the revealed value proves presence rather than a pre-committed
  judgment whose correctness is later settled.
- **Evidence versus aggregated or portable scores.** PAD-036 aggregates
  verifiable state receipts into a reputation value; PAD-030 carries a reputation
  attestation between contexts in zero knowledge. Both operate on reputation
  values already assigned. The present method produces the upstream, per-verdict,
  commit-before-outcome evidence that such systems would consume, and is what
  prevents the inputs themselves from being backdated or cherry-picked.
- **Neutral settler binding rather than self-report.** The outcome attestation is
  signed by the observer of the result and binds to the committed digest, so the
  subject of the record is structurally separated from the certifier of the
  result. A self-maintained score has no such separation.
- **Private verdict with provable fixity.** The salted commitment lets a verdict
  stay confidential until settlement while remaining unalterable, so it can be
  published before the outcome without being front-run. A plain signed claim
  discloses its content at commit time.
- **Transport-neutral settlement descriptor.** The record of ground truth is
  named by `method` and `locator` and is deliberately not bound to any one
  chain, feed, notary, or payment rail, so the primitive composes with the open
  protocol rather than a specific external service.

---

## 5. Technical Implementation

A reference implementation ships in the Python SDK as `vouch.accountability`,
exposing `commit_outcome`, `verify_commitment`, `attest_outcome`,
`verify_attestation`, `commitment_digest`, and `accountability_pointer`, with the
`OutcomeCommitmentCredential` and `OutcomeAttestationCredential` types and the
`sha-256-jcs` commitment algorithm. The commitment digest is SHA-256 over the
RFC 8785 JCS canonical form of the claim with an optional appended salt, the same
canonicalization the rest of the SDK uses, so the digest is reproducible across
languages. Signing uses the shared `eddsa-jcs-2022` Data Integrity path; the
choice of public ledger or notary for the settlement record is left to the
caller.

---

## 6. Claims Summary

1. A method for recording an agent's track record in which a verdict, prediction,
   or recommendation is committed as a signed credential carrying a digest of the
   canonical claim fixed before the outcome is known, and a separately-signed
   attestation later binds the observed outcome to that commitment.
2. The method of claim 1 wherein the commitment carries a salted digest and
   withholds the cleartext claim, and the claim and salt are revealed at
   settlement and checked against the committed digest, so the verdict is
   confidential before settlement yet provably unalterable.
3. The method of claim 1 wherein verification rejects any settlement whose
   timestamp precedes the commitment, so a verdict cannot be minted with
   hindsight.
4. The method of claim 1 wherein the settlement attestation is signed by a party
   distinct from the committer and binds to the committed digest rather than to
   trust in the committer.
5. The method of claim 1 wherein the settlement record of ground truth is named
   by a transport-neutral descriptor of method and locator, so the primitive is
   not bound to any single ledger, feed, notary, or payment rail.
6. The method of claim 1 wherein the commitment and attestation are
   Verifiable Credentials using canonicalization and signature primitives shared
   across language SDKs, so the same evidence verifies cross-language and can be
   referenced from another credential by a pointer object.

---

## Update (2026-06-27): Third-party timestamp anchoring

The original disclosure relied on the signed `created` time to fix the commitment
before its outcome. On its own that timestamp is asserted by the committer, so the
pre-outcome timing is only as trustworthy as the committer's clock. This update
adds an optional `anchor` to the commitment: one entry or a tier list, each
carrying a `method` (a third-party timestamping service such as OpenTimestamps,
an RFC 3161 timestamp authority, a transparency log, or an on-chain method), a
`reference` to the proof at that service, and a `recomputeCmd` a verifier runs to
check it. The anchor is carried inside the signed credential, so it is
tamper-evident, and the anchor itself is checked out of band by the consumer
against the named method.

A precision the first update glossed: an anchor proves the commitment existed by
the stamped time, which is existence, not ordering. It does not by itself prove
that time is before the outcome, because an anchor can be a post-hoc existence
backfill, stamped after the outcome was known. So each anchor entry carries an
`establishes` affordance: `existence-only` (the default, asserting only existence
by the stamped time) or `pre-outcome-ordering` (asserting a forward commitment
made before the outcome). A consumer concludes commit-before-outcome only when an
anchor establishes `pre-outcome-ordering` and the consumer independently confirms,
via the `recomputeCmd`, that the stamped time precedes the settlement time. This
is the difference between anchored and anchored before the outcome. The original
claims are unchanged; the anchor with its precedence affordance is a disclosed
strengthening of the pre-outcome timing property, released under Apache 2.0.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem.
