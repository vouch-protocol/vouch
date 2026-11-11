"""
Pre-Registered Development Step (PAD-127).

Before a high-consequence step runs, the operator commits to one digest set that
fixes both the step's configuration and the evaluation plan by which the step
will be judged. The registration is published to an append-only log, a mandatory
challenge window elapses, externally named objection authorities may register a
binding objection, and only then does an execution credential become issuable.

The scheduler is the enforcement point. It recomputes the configuration digest
from the workload actually submitted and admits it only against a valid
post-window execution credential naming that digest, so the commitment is
coupled to the grant of the resource rather than to a policy document.

Fixing the evaluation plan before results exist is the same discipline that
pre-registration brought to experimental trials, enforced here by a digest.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence

from ._common import (
    PacingError,
    base_credential,
    digest_of,
    iso,
    now_utc,
    parse_iso,
    subject_of,
    verify_credential,
)

REGISTRATION_TYPE = "VouchStepRegistrationCredential"
OBJECTION_TYPE = "VouchStepObjectionCredential"
EXECUTION_TYPE = "VouchStepExecutionCredential"
RESULTS_TYPE = "VouchStepResultsCredential"

DIGEST_ALGORITHM = "sha-256-jcs"

REASON_INVALID_PROOF = "invalid_proof"
REASON_NOT_EXECUTION = "not_an_execution_credential"
REASON_REGISTRATION_MISMATCH = "registration_mismatch"
REASON_CONFIG_MISMATCH = "configuration_digest_mismatch"
REASON_WINDOW_NOT_ELAPSED = "challenge_window_not_elapsed"
REASON_OBJECTED = "objection_in_force"
REASON_UNAUTHORIZED_OBJECTOR = "unauthorized_objector"
REASON_UNAUTHORIZED_EXECUTOR = "unauthorized_executor"
REASON_LOG_ORDER = "registration_not_ordered_before_window"
REASON_EVAL_ADDED = "evaluation_not_in_plan"
REASON_EVAL_OMITTED = "planned_evaluation_omitted"
REASON_SUPERSEDED = "registration_superseded"


def configuration_digest(configuration: Dict[str, Any]) -> str:
    """Canonical digest fixing the step's configuration."""
    if not isinstance(configuration, dict) or not configuration:
        raise PacingError("configuration must be a non-empty JSON object")
    return digest_of(configuration)


def evaluation_plan_digest(evaluation_plan: Dict[str, Any]) -> str:
    """Canonical digest fixing the step's evaluation plan."""
    if not isinstance(evaluation_plan, dict) or not evaluation_plan.get("evaluations"):
        raise PacingError("evaluation_plan must name at least one evaluation")
    return digest_of(evaluation_plan)


def register_step(
    signer: Any,
    *,
    step_id: str,
    configuration: Dict[str, Any],
    evaluation_plan: Dict[str, Any],
    min_seconds: int,
    objection_authorities: Sequence[str],
    opens_at: Optional[datetime] = None,
    supersedes: Optional[str] = None,
    log_reference: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Register a step before it begins.

    Args:
        signer: The operator's ``Signer``.
        step_id: A stable identifier for the step.
        configuration: The canonical configuration object being fixed.
        evaluation_plan: The canonical evaluation plan being fixed, which must
            name at least one evaluation.
        min_seconds: The mandatory challenge window, which must be positive.
        objection_authorities: Identifiers permitted to object, normally external
            to the operator.
        opens_at: When the window opens. Defaults to now.
        supersedes: The digest of a registration this one replaces.
        log_reference: Where the registration is published, carried opaquely.
    """
    if min_seconds <= 0:
        raise PacingError("a pre-registered step requires a positive challenge window")
    if not objection_authorities:
        raise PacingError("at least one objection authority must be named")
    opened = (opens_at or now_utc()).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": step_id,
        "operator": signer.get_did(),
        "configuration": dict(configuration),
        "evaluationPlan": dict(evaluation_plan),
        "configurationDigest": {
            "algorithm": DIGEST_ALGORITHM,
            "digest": configuration_digest(configuration),
        },
        "evaluationPlanDigest": {
            "algorithm": DIGEST_ALGORITHM,
            "digest": evaluation_plan_digest(evaluation_plan),
        },
        "challengeWindow": {
            "minSeconds": int(min_seconds),
            "opensAt": iso(opened),
            "objectionAuthorities": list(objection_authorities),
        },
    }
    if supersedes:
        subject["supersedes"] = supersedes
    if log_reference:
        subject["logReference"] = dict(log_reference)
    return base_credential(signer, REGISTRATION_TYPE, subject, valid_from=opened)


def registration_digest(registration: Dict[str, Any]) -> str:
    """Canonical digest of a registration credential, used to bind to it."""
    return digest_of(registration)


def object_to_step(
    objector_signer: Any,
    *,
    registration: Dict[str, Any],
    reason_code: str,
    statement: str = "",
) -> Dict[str, Any]:
    """Issue a binding objection against a registered step during its window."""
    if not reason_code or not isinstance(reason_code, str):
        raise PacingError("reason_code is required")
    subject: Dict[str, Any] = {
        "id": registration_digest(registration),
        "objector": objector_signer.get_did(),
        "step": subject_of(registration).get("id"),
        "reasonCode": reason_code,
    }
    if statement:
        subject["statement"] = statement
    return base_credential(objector_signer, OBJECTION_TYPE, subject)


def issue_execution(
    signer: Any,
    *,
    registration: Dict[str, Any],
    log_index: Optional[int] = None,
    log_tree_size: Optional[int] = None,
    inclusion_proof: Optional[Sequence[str]] = None,
    issued_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Issue the execution credential once the window has closed without objection.

    The credential repeats the configuration digest so the scheduler can compare
    it against the workload it is asked to admit, and carries the registration's
    position in the log so the ordering is checkable.
    """
    reg_subject = subject_of(registration)
    subject: Dict[str, Any] = {
        "id": reg_subject.get("id"),
        "operator": signer.get_did(),
        "registration": registration_digest(registration),
        "configurationDigest": dict(reg_subject.get("configurationDigest") or {}),
        "evaluationPlanDigest": dict(reg_subject.get("evaluationPlanDigest") or {}),
    }
    if log_index is not None:
        subject["registrationLogIndex"] = int(log_index)
    if log_tree_size is not None:
        subject["registrationLogTreeSize"] = int(log_tree_size)
    if inclusion_proof is not None:
        subject["registrationInclusionProof"] = list(inclusion_proof)
    return base_credential(signer, EXECUTION_TYPE, subject, valid_from=issued_at)


def window_closes_at(registration: Dict[str, Any]) -> datetime:
    """When the registration's challenge window closes."""
    window = subject_of(registration).get("challengeWindow") or {}
    opened = parse_iso(str(window.get("opensAt")))
    return opened + timedelta(seconds=int(window.get("minSeconds", 0)))


def check_admission(
    execution: Dict[str, Any],
    registration: Dict[str, Any],
    submitted_configuration: Dict[str, Any],
    operator_public_key: Any,
    *,
    objections: Optional[Sequence[Dict[str, Any]]] = None,
    objection_public_keys: Optional[Dict[str, Any]] = None,
    now: Optional[datetime] = None,
    superseded_by: Optional[str] = None,
) -> Optional[str]:
    """
    The scheduler's decision. Returns None to admit, or the reason to refuse.

    The configuration digest is recomputed from the workload actually submitted,
    so a workload that differs from the registered one is refused even when the
    execution credential itself is valid.
    """
    if not verify_credential(registration, operator_public_key, REGISTRATION_TYPE):
        return REASON_INVALID_PROOF
    if not verify_credential(execution, operator_public_key, EXECUTION_TYPE):
        return REASON_INVALID_PROOF

    reg_subject = subject_of(registration)
    exec_subject = subject_of(execution)

    if exec_subject.get("registration") != registration_digest(registration):
        return REASON_REGISTRATION_MISMATCH
    if exec_subject.get("operator") != reg_subject.get("operator"):
        return REASON_UNAUTHORIZED_EXECUTOR
    if execution.get("issuer") != reg_subject.get("operator"):
        return REASON_UNAUTHORIZED_EXECUTOR
    if superseded_by:
        return REASON_SUPERSEDED

    registered = (reg_subject.get("configurationDigest") or {}).get("digest")
    declared = (exec_subject.get("configurationDigest") or {}).get("digest")
    try:
        recomputed = configuration_digest(submitted_configuration)
    except PacingError:
        return REASON_CONFIG_MISMATCH
    if registered != declared or recomputed != registered:
        return REASON_CONFIG_MISMATCH

    moment = (now or now_utc()).astimezone(timezone.utc)
    closes = window_closes_at(registration)
    if moment < closes:
        return REASON_WINDOW_NOT_ELAPSED

    window = reg_subject.get("challengeWindow") or {}
    authorities = set(window.get("objectionAuthorities") or [])
    keys = objection_public_keys or {}
    for objection in objections or []:
        objector = (objection.get("credentialSubject") or {}).get("objector")
        if objector not in authorities:
            continue
        if not verify_credential(objection, keys.get(objector), OBJECTION_TYPE):
            continue
        subject = subject_of(objection)
        if subject.get("id") != registration_digest(registration):
            continue
        if objection.get("issuer") != objector:
            continue
        return REASON_OBJECTED

    index = exec_subject.get("registrationLogIndex")
    if index is not None and not isinstance(index, int):
        return REASON_LOG_ORDER
    return None


def publish_results(
    signer: Any,
    *,
    registration: Dict[str, Any],
    results: Dict[str, Any],
) -> Dict[str, Any]:
    """Publish a step's results bound to the committed evaluation plan digest."""
    reg_subject = subject_of(registration)
    subject: Dict[str, Any] = {
        "id": reg_subject.get("id"),
        "operator": signer.get_did(),
        "registration": registration_digest(registration),
        "evaluationPlanDigest": dict(reg_subject.get("evaluationPlanDigest") or {}),
        "results": dict(results),
    }
    return base_credential(signer, RESULTS_TYPE, subject)


def check_results(
    results_credential: Dict[str, Any],
    registration: Dict[str, Any],
    operator_public_key: Any,
) -> List[str]:
    """
    Compare published results against the committed evaluation plan.

    Returns the divergences: evaluations reported that the plan did not name,
    and evaluations the plan named that were not reported.
    """
    if not verify_credential(results_credential, operator_public_key, RESULTS_TYPE):
        return [REASON_INVALID_PROOF]
    if not verify_credential(registration, operator_public_key, REGISTRATION_TYPE):
        return [REASON_INVALID_PROOF]

    reg_subject = subject_of(registration)
    res_subject = subject_of(results_credential)
    if res_subject.get("registration") != registration_digest(registration):
        return [REASON_REGISTRATION_MISMATCH]

    committed = (reg_subject.get("evaluationPlanDigest") or {}).get("digest")
    declared = (res_subject.get("evaluationPlanDigest") or {}).get("digest")
    if committed != declared:
        return [REASON_REGISTRATION_MISMATCH]

    planned = set(
        str(name) for name in (reg_subject.get("evaluationPlan") or {}).get("evaluations", [])
    )
    reported = set(str(name) for name in (res_subject.get("results") or {}).keys())

    divergences: List[str] = []
    divergences.extend(REASON_EVAL_ADDED for _ in sorted(reported - planned))
    divergences.extend(REASON_EVAL_OMITTED for _ in sorted(planned - reported))
    return divergences
