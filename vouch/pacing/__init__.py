"""
The Pacing Profile: verification primitives for a coordinated pace of
autonomous system development (PAD-125 to PAD-135).

Everything here is an ordinary Vouch Protocol credential secured with an
``eddsa-jcs-2022`` Data Integrity proof, so a pacing artifact verifies through
the same path as any other credential and needs no new proof type.

The modules answer a set of questions that a coordinated pace requires and that
no party can answer on its own word:

``census`` and ``restraint``
    Did anyone exceed a ceiling? Proved over an attested device population whose
    completeness is itself checkable, without disclosing workload magnitudes.

``recursion``
    How many autonomous steps sit between an artifact and the nearest human
    decision? Computed as a graph metric over signed authorship credentials, with
    the bound as the pacing control.

``prereg``
    What was this step meant to do, and how was it going to be judged? Both fixed
    in one commitment before the step runs, and enforced by the scheduler.

``custody``
    Does the operator's account of its compute agree with the account kept by the
    party that granted it? Reconciled into typed, attributable divergences.

``pace``
    How does a multilateral body slow things down without stopping them? A
    threshold-signed decay rate that contracts every outstanding grant in order
    of consequence, without revoking any of them.

``fuse``
    How long must the world have to look at a capability step? An interval that
    scales with the size of the step and cannot be shortened by buying more
    parallel compute.

``redline``
    Were the safety thresholds fixed before the results were known? Established
    by log index rather than by assertion, with selective reveal.

``oversight``
    Did oversight scale with capability? A committed ratio between compute and
    artifact-bound, non-reusable attested oversight work.

``load_auth``
    May these exact parameters still be run? An authorization issued to an
    identifier derived from the tensors, which decays and is re-checked while
    they stay resident.

``dissent``
    Can someone establish that they raised a concern, without paying the cost of
    raising it today? A sealed, dated registration with declared release
    conditions and blind corroboration.

``disclosure``
    How do rivals compare measurements when neither will go first? A round whose
    close is a log index, so no party can condition its disclosure on another's.
"""

from ._common import PACING_CONTEXT_V1, PacingError
from .census import (
    Census,
    build_census,
    chain_census,
    decommission_device,
    enroll_device,
)
from .custody import (
    AdmissionController,
    Divergence,
    allocation_receipt,
    compute_mandate,
    declared_ledger,
    provider_aggregate,
    reconcile,
)
from .disclosure import (
    RoundState,
    closure_record,
    collect_round,
    commit_measurement,
    evaluate_predicate,
    open_round,
    reveal_measurement,
)
from .dissent import (
    LivenessChain,
    Registration,
    concern_object,
    escrow_keypair,
    evaluate_release,
    register_concern,
    seal_concern,
    subject_tag,
    unseal_concern,
    verify_release,
)
from .fuse import (
    CheckpointedHashChain,
    SequentialFunction,
    advancement_credential,
    check_advancement,
    derive_seed,
    required_steps,
    stage_unlock,
)
from .load_auth import (
    LoadDecision,
    attenuate_envelope,
    canonical_tensor_digest,
    check_load,
    derive_weight_identifier,
    endorse_authorization,
    identifier_for,
    is_attenuation,
    load_authorization,
    runtime_attestation,
)
from .oversight import (
    Accumulation,
    NonceLedger,
    accumulate,
    authorize_step,
    check_ratio,
    oversight_receipt,
    verify_authorization,
)
from .pace import (
    QuorumPolicy,
    effective_lambda,
    effective_standing,
    endorse_epoch,
    half_life_seconds,
    pace_epoch,
    permits,
    permitted_classes,
    select_epoch,
    verify_epoch,
)
from .prereg import (
    check_admission,
    check_results,
    issue_execution,
    object_to_step,
    publish_results,
    register_step,
    registration_digest,
)
from .recursion import (
    AuthorshipGraph,
    authorship_credential,
    check_step,
    human_review,
    max_human_distance,
    step_credential,
)
from .redline import (
    PolicyCommitment,
    Threshold,
    check_ordering,
    commit_policy,
    measurement_record,
    open_threshold,
    publish_policy,
    verify_amendment_chain,
    verify_open,
)
from .restraint import (
    PeriodAccounting,
    attest_restraint,
    build_openings,
    register_proof_backend,
    sample_workloads,
    verify_restraint,
    work_record,
    workload_commitment,
)

__all__ = [
    "PACING_CONTEXT_V1",
    "PacingError",
    # census and restraint
    "Census",
    "build_census",
    "chain_census",
    "decommission_device",
    "enroll_device",
    "PeriodAccounting",
    "attest_restraint",
    "build_openings",
    "register_proof_backend",
    "sample_workloads",
    "verify_restraint",
    "work_record",
    "workload_commitment",
    # recursion
    "AuthorshipGraph",
    "authorship_credential",
    "check_step",
    "human_review",
    "max_human_distance",
    "step_credential",
    # pre-registration
    "check_admission",
    "check_results",
    "issue_execution",
    "object_to_step",
    "publish_results",
    "register_step",
    "registration_digest",
    # compute custody
    "AdmissionController",
    "Divergence",
    "allocation_receipt",
    "compute_mandate",
    "declared_ledger",
    "provider_aggregate",
    "reconcile",
    # pace control
    "QuorumPolicy",
    "effective_lambda",
    "effective_standing",
    "endorse_epoch",
    "half_life_seconds",
    "pace_epoch",
    "permits",
    "permitted_classes",
    "select_epoch",
    "verify_epoch",
    # sequential delay
    "CheckpointedHashChain",
    "SequentialFunction",
    "advancement_credential",
    "check_advancement",
    "derive_seed",
    "required_steps",
    "stage_unlock",
    # red lines
    "PolicyCommitment",
    "Threshold",
    "check_ordering",
    "commit_policy",
    "measurement_record",
    "open_threshold",
    "publish_policy",
    "verify_amendment_chain",
    "verify_open",
    # oversight
    "Accumulation",
    "NonceLedger",
    "accumulate",
    "authorize_step",
    "check_ratio",
    "oversight_receipt",
    "verify_authorization",
    # load authorization
    "LoadDecision",
    "attenuate_envelope",
    "canonical_tensor_digest",
    "check_load",
    "derive_weight_identifier",
    "endorse_authorization",
    "identifier_for",
    "is_attenuation",
    "load_authorization",
    "runtime_attestation",
    # sealed dissent
    "LivenessChain",
    "Registration",
    "concern_object",
    "escrow_keypair",
    "evaluate_release",
    "register_concern",
    "seal_concern",
    "subject_tag",
    "unseal_concern",
    "verify_release",
    # comparative disclosure
    "RoundState",
    "closure_record",
    "collect_round",
    "commit_measurement",
    "evaluate_predicate",
    "open_round",
    "reveal_measurement",
]
