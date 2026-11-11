# Pacing Profile Reference

The Pacing Profile is a set of verification primitives for proving that a party held to an agreed pace of autonomous system development, to another party that cannot see inside. It lives in `vouch.pacing` (Python only). The design document is `docs/pacing-profile.md` in the repository; the disclosures are PAD-125 to PAD-135.

Every record is an ordinary Vouch Protocol credential with an `eddsa-jcs-2022` Data Integrity proof over JCS-canonicalized JSON. A pacing artifact verifies through the same path as any other credential and needs no new proof type.

Import from the package: `from vouch.pacing import ...`. Shared names: `PacingError`, `PACING_CONTEXT_V1`.

## What each module answers

Each module answers one question that a coordinated pace needs and that no party can settle on its own word.

| Module | PAD | Question | Main names |
|---|---|---|---|
| `census`, `restraint` | 125 | Did anyone exceed a compute ceiling? | `build_census`, `enroll_device`, `decommission_device`, `chain_census`, `work_record`, `workload_commitment`, `attest_restraint`, `verify_restraint`, `sample_workloads`, `build_openings`, `register_proof_backend`, `Census`, `PeriodAccounting` |
| `recursion` | 126 | How many autonomous steps sit between this artifact and a human decision? | `AuthorshipGraph`, `authorship_credential`, `human_review`, `step_credential`, `check_step`, `max_human_distance` |
| `prereg` | 127 | What was this step meant to do, and how will it be judged? | `register_step`, `registration_digest`, `object_to_step`, `issue_execution`, `check_admission`, `publish_results`, `check_results` |
| `custody` | 128 | Does the operator's compute account agree with the provider's? | `compute_mandate`, `allocation_receipt`, `declared_ledger`, `provider_aggregate`, `reconcile`, `AdmissionController`, `Divergence` |
| `pace` | 129 | How does a multilateral body slow things down without stopping them? | `pace_epoch`, `endorse_epoch`, `verify_epoch`, `select_epoch`, `effective_lambda`, `effective_standing`, `half_life_seconds`, `permits`, `permitted_classes`, `QuorumPolicy` |
| `fuse` | 130 | How long must the world have to look at a capability step? | `required_steps`, `derive_seed`, `advancement_credential`, `check_advancement`, `stage_unlock`, `CheckpointedHashChain`, `SequentialFunction` |
| `redline` | 131 | Were the safety thresholds fixed before the results were known? | `Threshold`, `commit_policy`, `publish_policy`, `measurement_record`, `open_threshold`, `verify_open`, `check_ordering`, `verify_amendment_chain`, `PolicyCommitment` |
| `oversight` | 132 | Did oversight scale with capability? | `oversight_receipt`, `accumulate`, `authorize_step`, `check_ratio`, `verify_authorization`, `NonceLedger`, `Accumulation` |
| `load_auth` | 133 | May these exact parameters still be run? | `canonical_tensor_digest`, `derive_weight_identifier`, `identifier_for`, `load_authorization`, `endorse_authorization`, `runtime_attestation`, `check_load`, `attenuate_envelope`, `is_attenuation`, `LoadDecision` |
| `dissent` | 134 | Can someone establish they raised a concern without paying the cost today? | `concern_object`, `seal_concern`, `unseal_concern`, `escrow_keypair`, `register_concern`, `subject_tag`, `evaluate_release`, `verify_release`, `LivenessChain`, `Registration` |
| `disclosure` | 135 | How do rivals compare measurements when neither goes first? | `open_round`, `commit_measurement`, `reveal_measurement`, `collect_round`, `closure_record`, `evaluate_predicate`, `RoundState` |

## How each one works

**census and restraint.** Accelerators are enrolled with hardware-rooted device credentials, and the enrolled set is committed as a census with a published cardinality. Each device emits a signed per-period record carrying an additively homomorphic commitment (Pedersen, over a 2048-bit MODP group) to its magnitude. The operator publishes an attestation of two predicates: no single workload above the ceiling, and the period total within quota. Every enrolled device must contribute a record or be covered by a signed decommission record, so leaving work out means leaving a device out, and a missing device fails the period. `verify_restraint` is one entry point for three disclosure modes: open the aggregates, open a sample derived from a published log root (so the operator cannot choose it), or hand a range proof to a backend registered with `register_proof_backend`.

**recursion.** Each artifact entering a pipeline carries a signed authorship credential. Human distance is the minimum number of authorization hops to a credential signed by a key of an attested human presence class. It never decreases down a derivation: a derived artifact has at least its parent's distance plus one. A step runs only when the maximum distance across its inputs is at or below a declared bound. Lowering the bound forces more human signatures into the loop.

**prereg.** One commitment fixes the step's configuration and its evaluation plan together, before the step runs. A mandatory challenge window follows, named authorities may object, and the scheduler recomputes the configuration digest from the workload actually submitted before admitting it.

**custody.** A workload is admitted only against a signed mandate, and the provider countersigns an allocation receipt. The operator's declared ledger and the provider's aggregate are reconciled into typed divergences (an unbacked declaration, an undeclared allocation, a magnitude mismatch, an envelope breach). Each names both entries and both signers.

**pace.** A quorum from distinct governance domains endorses a pace epoch carrying a continuous decay rate. Raising the rate shortens the half-life of every outstanding grant at once, without revoking any and without delivering anything to the grant holders. Thresholds by consequence class mean the highest-consequence operations stop first. Epochs are monotonic. A verifier that has not seen a current epoch applies the more conservative of the last known rate and a declared default.

**fuse.** The required interval grows with the measured increment over a committed reference point, evidenced by a sequential delay function. Evaluation is serial, so parallel compute does not shorten it. The seed combines the shared log root with the step's registration digest, so it cannot be precomputed. The shipped function is `CheckpointedHashChain`. `SequentialFunction` is the protocol to implement for a different delay function.

**redline.** Each threshold is committed under its own blinding value into a counted tree, and the root is appended to a log before measurement. Order is decided by log index, not by a clock. An amendment is a superseding commitment that names the prior one, so a threshold relaxed after a result shows as a dated amendment. `open_threshold` reveals one threshold while the rest stay closed and the count stays published.

**oversight.** Oversight work is recorded as signed receipts naming the digests of the artifacts examined, weighted by work class and by the performer's independence. A step is authorized only when accumulated oversight stands in at least a committed ratio to the step's compute. Receipts are consumed by nonce, so the same work cannot support two steps, and per-class floors stop the cheapest class from satisfying the ratio alone.

**load_auth.** An identifier is derived from the canonical tensor digest, so the parameters name themselves. A quorum authorizes that identifier within an envelope, from an anchor time, at a decay rate. A runtime derives the identifier from what it is about to load and calls `check_load` again while the parameters stay resident. A modified checkpoint gets a different identifier and the authorization does not transfer.

**dissent.** A concern is canonicalized, sealed to an escrow with X25519 and AES-GCM, and registered as a blinded commitment. The log entry reveals no content, subject, or author. Release happens on a declared condition, including a lapse in the author's own liveness chain. A separately blinded subject tag lets independent registrations on the same subject be counted, and that count can be a release condition.

**disclosure.** A signed round descriptor fixes participants, schema, predicate, and a closing log index. Commitments land before that index, the round closes when the log passes it, and only then do reveals begin. Closure is observed identically by everyone, so no coordinator or clock is needed. A named participant with no in-round commitment is listed in a signed closure record.

## How they compose

A step registers its configuration and evaluation plan (`prereg`). The recursion bound limits how far its inputs stand from a human decision (`recursion`). The oversight ratio ties its compute to attested review of those same artifacts (`oversight`). The red line policy that judges its results was committed before the results existed (`redline`). The fuse sets how long the world has before the result may be acted on (`fuse`). The census and the provider ledger account for what it consumed (`census`, `custody`). The pace epoch in force decides how much standing any of it has when it runs (`pace`, `load_auth`). `tests/test_pacing.py` exercises the whole path in one scenario.

## Minimal example: commit red lines before the results

This runs against the real API. The operator commits two thresholds and publishes the commitment at log index 100. An evaluator records a result at log index 140. Anyone can then check that one threshold opens correctly and that the policy came before the result.

```python
from vouch import Signer, generate_identity
from vouch.pacing import (
    Threshold, commit_policy, publish_policy, open_threshold, verify_open,
    measurement_record, check_ordering,
)

def principal(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)

operator_kp, operator = principal("operator.example.com")
evaluator_kp, evaluator = principal("evaluator.example.org")

policy = commit_policy([
    Threshold("cyber", "cyber-uplift", ">=", 0.40, "halt"),
    Threshold("autonomy", "autonomy-days", ">=", 30.0, "narrow"),
])
published = publish_policy(operator, policy, log_index=100)

result = measurement_record(
    evaluator, measurement="cyber-uplift", value=0.52,
    subject_of_measurement="model-x", log_index=140,
)

reveal = open_threshold(policy, "cyber")
print(verify_open(reveal, published, operator_kp.public_key_jwk))  # [] means it verifies
print(check_ordering(published, result, operator_kp.public_key_jwk, evaluator_kp.public_key_jwk))  # []
```

The verify functions return a list of failure reasons. An empty list means the check passed.

## Notes for answering

- It is Python only (`vouch.pacing`). There is no TypeScript, Go, or WASM surface for it.
- These are verification primitives: the checks run wherever a verifier chooses to run them.
- The `SequentialFunction` slot and the `register_proof_backend` registry are the extension points for a different delay function and for range proofs.
- Where to read more: `docs/pacing-profile.md` and PAD-125 to PAD-135 in `docs/disclosures/`.
