# The Pacing Profile

**Status:** Draft specification (design)
**Applies to:** `vouch.pacing` (`census`, `restraint`, `recursion`, `prereg`, `custody`, `pace`, `fuse`, `redline`, `oversight`, `load_auth`, `dissent`, `disclosure`)
**Disclosures:** PAD-125 to PAD-135

## 1. Problem

A commitment to move at a particular pace is, today, a sentence in a document.
There is no artifact behind it. A party that slowed down cannot demonstrate it,
a party that did not cannot be shown to have carried on, and so every
participant's restraint is conditional on believing everyone else's. That is the
shape of a coordination problem that verification solves and rhetoric does not.

The technical question underneath it is narrow and stateable: how does a
mutually distrustful party prove it held to a limit, to another party that
cannot be allowed to see inside? Arms control answered a version of this with
safeguards and remote monitoring, which made restraint observable and therefore
survivable. There is no equivalent instrument for compute or for autonomous
development, and the absence is what keeps the conversation at the level of
declarations.

The second observation is what makes this a Vouch Protocol problem rather than
an adjacent one. Recursive self-improvement is not a single opaque event. It
runs through agents that read, write code, launch jobs, score results, and feed
the outcome back. Every step in that loop is an action taken under some
authority, which is the exact unit this protocol already signs, delegates,
budgets, and logs. The weights cannot be inspected. The loop can.

## 2. What each module answers

Each module answers one question that a coordinated pace requires and that no
party can settle on its own word.

**`census` and `restraint` (PAD-125): did anyone exceed a ceiling?** Accelerators
are enrolled with hardware-rooted device credentials, and the enrolled set is
committed as a census with published cardinality. Every device emits a signed
per-period record carrying an additively homomorphic commitment to its magnitude,
and the operator publishes an attestation of two predicates: no single workload
above the ceiling, and the period total within quota.

The property that matters is completeness rather than integrity. A signed report
over the workloads a party chose to disclose says nothing about the ones it
omitted. Here every enrolled device must contribute a record or be covered by a
signed decommission record, so omitting work requires omitting a device, and a
missing device fails the period. Absence becomes a dated event with an author.

Three disclosure modes verify through one entry point: open the aggregates, open
a sample the operator cannot choose because it is derived from a published log
root, or hand a range proof to a registered backend. The homomorphic commitments
are Pedersen commitments over a 2048-bit MODP group, so per-workload aggregates
combine without opening the individual records.

**`recursion` (PAD-126): how far is this artifact from a human decision?** Every
artifact entering a pipeline carries a signed authorship credential. Human
distance is the minimum number of authorization hops to a credential signed by a
key of an attested human presence class. Derivation is non-decreasing, so an
artifact derived from another inherits at least its parent's distance plus one,
and repackaging does not reset it. A step runs only when the maximum distance
across its inputs is at or below a declared bound.

The bound is the control. Lowering it forces more human authorization edges into
the loop, and since each edge is a real signature over an exact digest by a key
under human custody, lowering it lengthens the loop by construction rather than
by policy.

**`prereg` (PAD-127): what was this step meant to do, and how was it going to be
judged?** One commitment fixes the configuration and the evaluation plan
together, before the step runs. A mandatory challenge window follows,
externally named authorities may object, and the scheduler recomputes the
configuration digest from the workload actually submitted before admitting it.
Fixing the evaluation plan before results exist is pre-registration, borrowed
from experimental practice and enforced by a digest rather than by convention.

**`custody` (PAD-128): does the operator's account agree with the provider's?** A
workload is admitted only against a signed mandate, and the provider that admits
it countersigns an allocation receipt. Two books kept by parties with different
interests are then reconciled into typed divergences: an unbacked declaration, an
undeclared allocation, a magnitude mismatch, an envelope breach. Each names both
entries and both signers, so it is attributable on its face.

**`pace` (PAD-129): how does a multilateral body slow things without stopping
them?** A quorum drawn from distinct governance domains endorses a pace epoch
carrying a continuous decay rate. Verifiers already evaluate authority as a
decaying function of time since anchoring; the epoch sets the rate. Raising it
shortens the half-life of every outstanding grant at once, so contraction reaches
grants the signer has never seen and needs no delivery to any of them. Thresholds
by consequence class mean the highest-consequence operations stop first.

The quorum endorses a state record with no subject, so its authority is confined
to modifying evaluation and does not extend to issuing or withholding identity.
Epochs are monotonic, and a verifier that has not seen a current epoch applies
the more conservative of the last known rate and a declared default, so silence
contracts authority instead of preserving it.

**`fuse` (PAD-130): how long must the world have to look at a capability step?**
The required interval is a monotone function of the measured increment over a
committed reference point, evidenced by a sequential delay function. Evaluation
is serial, so more parallel compute does not shorten it, which makes this the one
rate limit that does not get cheaper as the constrained party grows. The seed
combines the shared log root with the step's own registration digest, so it does
not exist before registration and cannot be precomputed, and every participant
seeds from the same log.

The shipped function is a checkpointed hash chain: strictly serial to evaluate,
segment-wise independent to verify. The `SequentialFunction` protocol is the
substitution point for a succinct verifiable delay function.

**`redline` (PAD-131): were the thresholds fixed before the results?** Each
threshold is committed under its own blinding value into a counted tree, and the
root is appended to a log before measurement. Priority rests on log index rather
than on a timestamp anyone controls. Amendment stays possible through a
superseding commitment that names the prior one, so a threshold relaxed after a
result is visible as a dated amendment ordered after that result. Selective
reveal opens one threshold while the rest stay closed and the count stays
published.

**`oversight` (PAD-132): did oversight scale with capability?** Oversight work is
recorded as signed receipts naming the digests of the artifacts examined, weighted
by work class and by the performer's independence, and accumulated per period. A
step is authorized only when that measure stands in at least a committed ratio to
the step's compute measure. Receipts are consumed by nonce with partial
consumption, so the same work cannot support two steps, and per-class floors stop
the predicate being satisfied entirely from the cheapest class.

**`load_auth` (PAD-133): may these exact parameters still be run?** An identifier
is derived from the canonical tensor digest, so the parameters name themselves. A
quorum authorizes that identifier within an envelope, from an anchor time, at a
decay rate. A conforming runtime derives the identifier from what it is about to
load and re-checks while the parameters stay resident, attenuating the envelope
under the non-expansion rule as standing falls. A modified checkpoint yields a
different identifier, so authorizations do not transfer to it.

**`dissent` (PAD-134): can someone establish that they raised a concern without
paying the cost of raising it today?** The concern is canonicalized, sealed to an
escrow with X25519 and AES-GCM, and registered as a blinded commitment whose log
entry discloses neither content, subject, nor author. Release happens on a
declared condition, including a lapse in the author's own liveness chain. A
separately blinded subject tag lets independent registrations over the same
subject be counted, and that count can itself be a release condition, so
corroboration becomes available without any author going first.

**`disclosure` (PAD-135): how do rivals compare measurements when neither will go
first?** A signed round descriptor fixes the participants, schema, predicate, and
a closing log index. Commitments land before the index, the round closes when the
log passes it, and only then does the reveal phase begin. Closure is a fact every
participant observes identically, so no coordinator is needed and no clock enters
the trust base. A named participant with no in-round commitment is enumerated in
a signed closure record, so declining to take part carries information. The
ordinal variant commits differences against a descriptor-fixed reference, so
standing is established without levels.

## 3. Composition

The modules compose, and the composition is where the profile earns its keep. A
step registers its configuration and evaluation plan; the recursion ceiling bounds
how far its inputs stand from a human decision; the oversight ratio couples its
compute to attested review of those same artifacts; the red line policy that
judges its results was committed before the results existed; the sequential fuse
sets how long the world has before the result may be acted on; the census and the
provider ledger independently account for what it consumed; and the pace epoch in
force decides how much standing any of it still has by the time it runs.

`tests/test_pacing.py` exercises that whole path in one scenario, and each
mechanism separately against the attack its disclosure says it must resist.

## 4. What this does not do

Cryptography cannot verify a party that never enrols, so the first-mover problem
stays a political one. Device-level accounting depends on a hardware attestation
supply chain that no protocol controls. The range-proof mode is an extension
point with a registry, not a shipped proving system, and the two shipped modes
disclose aggregates rather than nothing. The sequential function shipped here is
a hash chain, whose verification cost is proportional to its evaluation cost even
though the segments are independent; a succinct verifiable delay function belongs
in that slot for large intervals. And completeness, meaning that the disclosed
population really is the whole population, is the hard part of the whole design:
everything else is comparatively easy.

## 5. Reference

```python
from vouch.pacing import (
    build_census, work_record, attest_restraint, verify_restraint,
    AuthorshipGraph, step_credential, check_step,
    register_step, issue_execution, check_admission,
    compute_mandate, AdmissionController, reconcile,
    pace_epoch, endorse_epoch, verify_epoch, effective_standing, permitted_classes,
    advancement_credential, check_advancement,
    commit_policy, publish_policy, open_threshold, verify_open,
    oversight_receipt, accumulate, check_ratio,
    identifier_for, load_authorization, check_load,
    concern_object, register_concern, evaluate_release,
    open_round, commit_measurement, collect_round, evaluate_predicate,
)
```
